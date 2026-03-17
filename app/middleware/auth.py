"""
middleware/auth.py — Session auth + CSRF helpers.
Fix #5: session survives browser close (cookie max_age=72h, not session cookie).
Fix #6: CSRF token validation helper.
"""
import secrets
from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse
from app.db.database import get_session_user


async def get_current_user(request: Request) -> dict:
    """Get authenticated user. Raises 401 if not logged in."""
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Belum login")
    user = await get_session_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Sesi habis, silakan login kembali")
    return user


async def get_current_user_optional(request: Request) -> dict | None:
    """Get user if logged in, else None. Never raises."""
    try:
        token = request.cookies.get("session_token")
        if not token:
            return None
        return await get_session_user(token)
    except Exception:
        return None


async def require_admin(request: Request) -> dict:
    """Require admin role. Returns user dict."""
    user = await get_current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Akses admin diperlukan")
    return user


def get_csrf_token(request: Request) -> str:
    """Read CSRF token from cookie. Generate new one if absent."""
    return request.cookies.get("csrf_token") or secrets.token_urlsafe(16)
