"""
middleware/auth.py — Session-based auth helpers.
"""
from fastapi import Request, HTTPException
from app.db.database import get_session_user


async def get_current_user(request: Request) -> dict:
    """Get authenticated user from session cookie. Raises 401 if not logged in."""
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await get_session_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    return user


async def get_current_user_optional(request: Request) -> dict | None:
    """Get user if logged in, else None. Does not raise."""
    try:
        token = request.cookies.get("session_token")
        if not token:
            return None
        return await get_session_user(token)
    except Exception:
        return None


async def require_admin(request: Request) -> dict:
    """Get current user and verify they have admin role."""
    user = await get_current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
