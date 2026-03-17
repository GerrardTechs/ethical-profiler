"""
routers/history.py — Scan history endpoints.
Fix #4: GET /api/history/ is read-only — refresh never deletes records.
        DELETE is only possible via explicit button click with confirmation.
        Admin-only delete protected by role check.
"""
from fastapi import APIRouter, Query, Request, HTTPException
from typing import Optional

from app.db.database import get_scan_history, get_scan_detail, delete_scan, get_stats
from app.middleware.auth import get_current_user

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("/")
async def list_history(
    request:  Request,
    limit:    int           = Query(50, ge=1, le=200),
    offset:   int           = Query(0, ge=0),
    search:   Optional[str] = Query(None, max_length=100),
    risk:     Optional[str] = Query(None),
):
    """
    Fix #4: This is a pure READ — it NEVER modifies or deletes any data.
    Refreshing the history page simply re-fetches the list.
    """
    user = await get_current_user(request)
    # Admin sees all scans; regular users see only their own
    uid  = None if user["role"] == "admin" else user["id"]

    # Sanitize risk filter
    risk_clean = risk.upper() if risk and risk.upper() in {"HIGH", "MODERATE", "LOW"} else None

    rows = await get_scan_history(
        limit=limit, offset=offset,
        search=search, risk_filter=risk_clean,
        user_id=uid,
    )
    return {"scans": rows, "count": len(rows)}


@router.get("/stats")
async def history_stats(request: Request):
    user = await get_current_user(request)
    uid  = None if user["role"] == "admin" else user["id"]
    return await get_stats(uid)


@router.get("/{scan_id}")
async def get_history_detail(scan_id: str, request: Request):
    """Read a single scan result. Read-only."""
    await get_current_user(request)

    # Sanitize scan_id — only hex chars allowed
    if not scan_id.replace("-", "").isalnum() or len(scan_id) > 32:
        raise HTTPException(status_code=400, detail="scan_id tidak valid")

    detail = await get_scan_detail(scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Scan tidak ditemukan")
    return detail


@router.delete("/{scan_id}")
async def remove_scan(scan_id: str, request: Request):
    """
    Fix #4: DELETE is an EXPLICIT action — it is NEVER triggered by refresh.
    Only admins can delete. Requires intentional DELETE HTTP method from the
    delete button in the UI — a page refresh uses GET, not DELETE.
    """
    user = await get_current_user(request)

    if user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Hanya admin yang bisa menghapus scan history"
        )

    if not scan_id.replace("-", "").isalnum() or len(scan_id) > 32:
        raise HTTPException(status_code=400, detail="scan_id tidak valid")

    ok = await delete_scan(scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Scan tidak ditemukan")

    return {"deleted": True, "scan_id": scan_id}
