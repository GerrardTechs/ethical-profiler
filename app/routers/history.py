"""
history.py — Scan history CRUD endpoints (auth-aware).
"""
from fastapi import APIRouter, Query, Request, HTTPException
from typing import Optional
from app.db.database import get_scan_history, get_scan_detail, delete_scan, get_stats
from app.middleware.auth import get_current_user

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("/")
async def list_history(
    request: Request,
    limit:  int           = Query(50, ge=1, le=200),
    offset: int           = Query(0, ge=0),
    search: Optional[str] = Query(None),
    risk:   Optional[str] = Query(None),
):
    user = await get_current_user(request)
    # Admin sees all scans; regular users see only their own
    uid = None if user["role"] == "admin" else user["id"]
    rows = await get_scan_history(limit=limit, offset=offset,
                                   search=search, risk_filter=risk, user_id=uid)
    return {"scans": rows, "count": len(rows)}


@router.get("/stats")
async def history_stats(request: Request):
    user = await get_current_user(request)
    uid = None if user["role"] == "admin" else user["id"]
    return await get_stats(uid)


@router.get("/{scan_id}")
async def get_history_detail(scan_id: str, request: Request):
    await get_current_user(request)
    detail = await get_scan_detail(scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Scan not found")
    return detail


@router.delete("/{scan_id}")
async def remove_scan(scan_id: str, request: Request):
    user = await get_current_user(request)
    # Only admin can delete any scan; users can only delete their own
    # (simplified: we trust scan_id scoping for now)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Hanya admin yang bisa menghapus scan")
    ok = await delete_scan(scan_id)
    return {"deleted": ok, "scan_id": scan_id}
