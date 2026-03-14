"""
routers/analytics.py — Analytics & admin endpoints.
"""
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.db.database import (
    get_stats, get_scan_trend, get_risk_distribution,
    get_top_targets, get_breach_stats, get_api_performance,
    get_all_users, toggle_user_status, change_user_role,
)
from app.middleware.auth import get_current_user, require_admin

BASE_DIR = Path(__file__).resolve().parent.parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

router = APIRouter(tags=["analytics"])


# ── Pages ─────────────────────────────────────────────────────────────────────

@router.get("/analytics", response_class=HTMLResponse, include_in_schema=False)
async def analytics_page(request: Request):
    user = await get_current_user(request)
    return templates.TemplateResponse("analytics.html", {"request": request, "user": user})


@router.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def admin_page(request: Request):
    user = await require_admin(request)
    return templates.TemplateResponse("admin.html", {"request": request, "user": user})


# ── API: Analytics ────────────────────────────────────────────────────────────

@router.get("/api/analytics/overview")
async def analytics_overview(request: Request):
    user = await get_current_user(request)
    uid = user["id"] if user["role"] != "admin" else None
    stats       = await get_stats(uid)
    risk_dist   = await get_risk_distribution(uid)
    breach_stats = await get_breach_stats(uid)
    return {
        "stats":        stats,
        "risk_dist":    risk_dist,
        "breach_stats": breach_stats,
    }


@router.get("/api/analytics/trend")
async def analytics_trend(request: Request, days: int = 30):
    user = await get_current_user(request)
    uid = user["id"] if user["role"] != "admin" else None
    return await get_scan_trend(days=min(days, 365), user_id=uid)


@router.get("/api/analytics/top-targets")
async def analytics_top_targets(request: Request, limit: int = 10):
    user = await get_current_user(request)
    uid = user["id"] if user["role"] != "admin" else None
    return await get_top_targets(limit=min(limit, 50), user_id=uid)


@router.get("/api/analytics/api-performance")
async def analytics_api_perf(request: Request):
    await get_current_user(request)
    return await get_api_performance()


# ── API: Admin user management ────────────────────────────────────────────────

@router.get("/api/admin/users")
async def admin_list_users(request: Request):
    await require_admin(request)
    return await get_all_users()


@router.patch("/api/admin/users/{user_id}/status")
async def admin_toggle_user(user_id: int, request: Request):
    await require_admin(request)
    body = await request.json()
    ok = await toggle_user_status(user_id, body.get("is_active", True))
    if not ok:
        raise HTTPException(status_code=500, detail="Gagal update status user")
    return {"ok": True}


@router.patch("/api/admin/users/{user_id}/role")
async def admin_change_role(user_id: int, request: Request):
    await require_admin(request)
    body = await request.json()
    role = body.get("role", "user")
    if role not in ("user", "admin"):
        raise HTTPException(status_code=400, detail="Role tidak valid")
    ok = await change_user_role(user_id, role)
    if not ok:
        raise HTTPException(status_code=500, detail="Gagal update role")
    return {"ok": True}


# ── API: Diagnostics (admin only) ─────────────────────────────────────────────

@router.get("/api/diagnostics")
async def diagnostics(request: Request):
    """Check which API keys are loaded. Admin only."""
    await require_admin(request)
    import os
    from pathlib import Path

    env_path = Path(__file__).resolve().parent.parent.parent / ".env"

    keys = {
        "GITHUB_TOKEN":        bool(os.getenv("GITHUB_TOKEN")),
        "SERPAPI":             bool(os.getenv("SERPAPI")),
        "LEAKCHECK_API_KEY":   bool(os.getenv("LEAKCHECK_API_KEY")),
        "BRAVE_API_KEY":       bool(os.getenv("BRAVE_API_KEY")),
        "HIBP_API_KEY":        bool(os.getenv("HIBP_API_KEY")),
        "FULLCONTACT_API_KEY": bool(os.getenv("FULLCONTACT_API_KEY")),
        "TWITTER_BEARER_TOKEN":bool(os.getenv("TWITTER_BEARER_TOKEN")),
        "SHODAN_KEY":          bool(os.getenv("SHODAN_KEY")),
        "INTELLIGENCE_KEY":    bool(os.getenv("INTELLIGENCE_KEY")),
        "HUNTER_API_KEY":      bool(os.getenv("HUNTER_API_KEY")),
        "WHOISXML_API_KEY":    bool(os.getenv("WHOISXML_API_KEY")),
        "URLSCAN_API_KEY":     bool(os.getenv("URLSCAN_API_KEY")),
        "CENSYS_API_KEY":      bool(os.getenv("CENSYS_API_KEY")),
        "EMAILREP_API_KEY":    bool(os.getenv("EMAILREP_API_KEY")),
        "ABSTRACT_API_KEY":    bool(os.getenv("ABSTRACT_API_KEY")),
    }
    loaded = sum(keys.values())
    total  = len(keys)
    return {
        "env_file_found": env_path.exists(),
        "env_file_path":  str(env_path),
        "keys_loaded":    loaded,
        "keys_total":     total,
        "keys":           keys,
    }
