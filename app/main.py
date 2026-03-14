"""
main.py — Ethical Digital Footprint Profiler v2
New in v2: Auth/multi-user, analytics dashboard, 6 new APIs,
API performance logging, Brave Search, HIBP, FullContact, Twitter/X.
"""

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
import asyncio
import logging
from pathlib import Path

from app.routers.scan      import router as scan_router
from app.routers.history   import router as history_router
from app.routers.username  import router as username_router
from app.routers.report    import router as report_router
from app.routers.auth      import router as auth_router
from app.routers.analytics import router as analytics_router
from app.db.database       import init_db
from app.middleware.auth   import get_current_user_optional

logger = logging.getLogger(__name__)

BASE_DIR      = Path(__file__).resolve().parent.parent
STATIC_DIR    = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

app = FastAPI(
    title="Ethical Digital Footprint Profiler",
    description="OSINT public exposure assessment — defensive cybersecurity research.",
    version="2.0.0",
    docs_url="/api/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
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


# ── Pages ─────────────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def index(request: Request):
    user = await get_current_user_optional(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("index.html", {"request": request, "user": user})


@app.get("/dashboard", include_in_schema=False)
async def dashboard(request: Request):
    user = await get_current_user_optional(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})


@app.get("/history", include_in_schema=False)
async def history_page(request: Request):
    user = await get_current_user_optional(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("history.html", {"request": request, "user": user})


@app.get("/defensive", include_in_schema=False)
async def defensive_page(request: Request):
    user = await get_current_user_optional(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("defensive.html", {"request": request, "user": user})


@app.get("/phone", include_in_schema=False)
async def phone_page(request: Request):
    user = await get_current_user_optional(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("phone_dashboard.html", {"request": request, "user": user})
