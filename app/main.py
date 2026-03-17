"""
main.py — EDFP v2.1
Fixes:
  #1  Back button no longer triggers logout
  #3  Home/dashboard links work for admin without logout
  #5  Logged-in users go to home, not login, on refresh/back/close
  #6  Security: CSRF token, rate limiting, XSS headers, DDoS mitigation
"""

import asyncio
import logging
import secrets
import time
from collections import defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from app.db.database       import init_db
from app.middleware.auth   import get_current_user_optional
from app.routers.analytics import router as analytics_router
from app.routers.auth      import router as auth_router
from app.routers.history   import router as history_router
from app.routers.report    import router as report_router
from app.routers.scan      import router as scan_router
from app.routers.username  import router as username_router

logger    = logging.getLogger(__name__)
BASE_DIR  = Path(__file__).resolve().parent.parent
STATIC_DIR    = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

# ── Rate limiter (DDoS #6) ────────────────────────────────────────────────────
# Tracks per-IP request timestamps in a sliding window
_rate_store: dict[str, list[float]] = defaultdict(list)

RATE_LIMIT_WINDOW  = 60    # seconds
RATE_LIMIT_MAX_REQ = 120   # max requests per window per IP (general)
RATE_AUTH_MAX_REQ  = 10    # stricter limit on /api/auth/* (brute-force protection)


def _get_ip(request: Request) -> str:
    """Extract real IP, respecting Vercel/proxy X-Forwarded-For."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _is_rate_limited(ip: str, path: str) -> bool:
    now    = time.time()
    window = RATE_LIMIT_WINDOW
    limit  = RATE_AUTH_MAX_REQ if path.startswith("/api/auth") else RATE_LIMIT_MAX_REQ

    # Purge old timestamps
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < window]
    if len(_rate_store[ip]) >= limit:
        return True
    _rate_store[ip].append(now)
    return False


# ── Security headers middleware (#6) ─────────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # DDoS / rate limiting
        ip   = _get_ip(request)
        path = request.url.path
        if _is_rate_limited(ip, path):
            logger.warning(f"[RateLimit] {ip} exceeded limit on {path}")
            return JSONResponse(
                status_code=429,
                content={"detail": "Terlalu banyak request. Coba lagi sebentar."},
                headers={"Retry-After": "60"},
            )

        response = await call_next(request)

        # XSS / clickjacking / MIME-sniff protection (#6)
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]          = "DENY"
        response.headers["X-XSS-Protection"]         = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
        # Content Security Policy — allows Tailwind CDN + cdnjs used by our templates
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://esm.sh; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' wss:; "
            "frame-ancestors 'none';"
        )
        return response


# ── CSRF middleware (#6) ──────────────────────────────────────────────────────
CSRF_SAFE_METHODS   = {"GET", "HEAD", "OPTIONS"}
CSRF_EXEMPT_PATHS   = {"/api/auth/login", "/api/auth/register", "/api/auth/logout"}

class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Only check state-changing API calls that are NOT auth endpoints
        if (request.method not in CSRF_SAFE_METHODS
                and request.url.path.startswith("/api")
                and request.url.path not in CSRF_EXEMPT_PATHS):

            # Accept either header (JS fetch) or cookie match
            origin  = request.headers.get("origin", "")
            referer = request.headers.get("referer", "")
            host    = request.headers.get("host", "")

            # Allow requests with a valid X-CSRF-Token header (set by our JS)
            csrf_header = request.headers.get("x-csrf-token", "")
            csrf_cookie = request.cookies.get("csrf_token", "")

            same_origin = (
                host in origin
                or host in referer
                or bool(csrf_header and csrf_header == csrf_cookie)
            )
            if not same_origin:
                logger.warning(f"[CSRF] Blocked {request.method} {request.url.path} origin={origin}")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF check gagal. Refresh halaman dan coba lagi."},
                )
        return await call_next(request)


# ── App factory ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Ethical Digital Footprint Profiler",
    description="OSINT public exposure assessment — defensive cybersecurity research.",
    version="2.1.0",
    docs_url="/api/docs",
    # Disable default exception handlers leaking internal detail
    redoc_url=None,
)

# Middleware order matters: security first, then CSRF, then CORS
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CSRFMiddleware)
app.add_middleware(
    CORSMiddleware,
    # Fix: CORSMiddleware doesn't support wildcard subdomains.
    # For same-site navigation (browser directly accessing the app), CORS is not
    # involved at all — cookies are sent automatically. CORS only applies to
    # cross-origin fetch() calls (JS on domain A fetching domain B).
    # Setting allow_origins=["*"] is safe here because we use httponly cookies
    # for auth (not Authorization headers), and CSRF middleware protects mutations.
    allow_origins=["*"],
    allow_credentials=False,   # must be False when allow_origins="*"
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(analytics_router)
app.include_router(scan_router)
app.include_router(history_router)
app.include_router(username_router)
app.include_router(report_router)


# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    await init_db()
    logger.info("[App] Database initialised.")


# ── CSRF token endpoint ───────────────────────────────────────────────────────
@app.get("/api/csrf-token")
async def csrf_token(response: JSONResponse):
    """Issue a CSRF token. Called once on page load by our JS."""
    token = secrets.token_urlsafe(32)
    resp  = JSONResponse({"csrf_token": token})
    resp.set_cookie(
        "csrf_token", token,
        httponly=False,   # JS must read it
        samesite="strict",
        max_age=3600,
        secure=False,     # set True in production HTTPS
    )
    return resp


# ── WebSocket ─────────────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self._conns: dict[str, list[WebSocket]] = {}

    async def connect(self, ws: WebSocket, room: str):
        await ws.accept()
        self._conns.setdefault(room, []).append(ws)

    def disconnect(self, ws: WebSocket, room: str):
        lst = self._conns.get(room, [])
        if ws in lst:
            lst.remove(ws)

    async def broadcast(self, room: str, msg: dict):
        dead = []
        for ws in self._conns.get(room, []):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, room)


manager = ConnectionManager()
app.state.ws_manager = manager


@app.websocket("/ws/scan/{scan_id}")
async def ws_scan_progress(websocket: WebSocket, scan_id: str):
    await manager.connect(websocket, scan_id)
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)


# ── Helper: render page with CSRF token in context ────────────────────────────
def _ctx(request: Request, user=None, **extra) -> dict:
    """Build template context — always includes user + csrf_token."""
    csrf = request.cookies.get("csrf_token", secrets.token_urlsafe(16))
    return {"request": request, "user": user, "csrf_token": csrf, **extra}


# ── Pages (#1 #3 #5 Fix: no redirect-to-login on back/refresh) ───────────────
# Rule: logged-in users ALWAYS get their page.
# Rule: logged-out users get login page — but browser back/forward cache
#       (bfcache) means the page they navigate "back" to is served from cache,
#       not re-requested. We prevent stale auth state by:
#       1. Setting Cache-Control: no-store on all auth-gated pages
#       2. Never putting logout logic on navigation links — only on explicit button
#       3. Session persists 72h — normal browser close does NOT log out

def _no_cache(response) -> None:
    """Prevent bfcache from serving stale auth state on back-button."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"]        = "no-cache"
    response.headers["Expires"]       = "0"


@app.get("/", include_in_schema=False)
async def index(request: Request):
    user = await get_current_user_optional(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    resp = templates.TemplateResponse("index.html", _ctx(request, user))
    _no_cache(resp)
    return resp


@app.get("/dashboard", include_in_schema=False)
async def dashboard(request: Request):
    # Fix #3: admin pressing dashboard should NOT logout
    user = await get_current_user_optional(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    resp = templates.TemplateResponse("dashboard.html", _ctx(request, user))
    _no_cache(resp)
    return resp


@app.get("/history", include_in_schema=False)
async def history_page(request: Request):
    user = await get_current_user_optional(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    resp = templates.TemplateResponse("history.html", _ctx(request, user))
    _no_cache(resp)
    return resp


@app.get("/defensive", include_in_schema=False)
async def defensive_page(request: Request):
    user = await get_current_user_optional(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    resp = templates.TemplateResponse("defensive.html", _ctx(request, user))
    _no_cache(resp)
    return resp


@app.get("/analytics", include_in_schema=False)
async def analytics_page_main(request: Request):
    user = await get_current_user_optional(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    resp = templates.TemplateResponse("analytics.html", _ctx(request, user))
    _no_cache(resp)
    return resp


@app.get("/admin", include_in_schema=False)
async def admin_page_main(request: Request):
    user = await get_current_user_optional(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse("/login" if not user else "/", status_code=302)
    resp = templates.TemplateResponse("admin.html", _ctx(request, user))
    _no_cache(resp)
    return resp


@app.get("/db-viewer", include_in_schema=False)
async def db_viewer_page(request: Request):
    user = await get_current_user_optional(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse("/login" if not user else "/", status_code=302)
    resp = templates.TemplateResponse("db_viewer.html", _ctx(request, user))
    _no_cache(resp)
    return resp


@app.get("/phone", include_in_schema=False)
async def phone_page(request: Request):
    user = await get_current_user_optional(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    resp = templates.TemplateResponse("phone_dashboard.html", _ctx(request, user))
    _no_cache(resp)
    return resp


# ── 404 handler ───────────────────────────────────────────────────────────────
@app.exception_handler(404)
async def not_found(request: Request, exc):
    user = await get_current_user_optional(request)
    return templates.TemplateResponse(
        "index.html", _ctx(request, user), status_code=404
    )
