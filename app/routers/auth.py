"""
routers/auth.py — Login, register, logout.
Fix #5: cookie max_age=72h so browser close doesn't log out (not a session cookie).
Fix #6: Set CSRF cookie on login/register. Sanitize inputs.
"""
import html
import re
from pathlib import Path

from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator

from app.db.database import (
    authenticate_user, create_user, create_session, delete_session
)
from app.middleware.auth import get_current_user_optional

BASE_DIR  = Path(__file__).resolve().parent.parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
router    = APIRouter(tags=["auth"])

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{3,32}$")
_EMAIL_RE    = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ── Pydantic models with input validation (#6 XSS) ────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)

    @field_validator("username")
    @classmethod
    def sanitize_username(cls, v: str) -> str:
        return html.escape(v.strip())


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email:    str = Field(..., min_length=5, max_length=128)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not _USERNAME_RE.match(v):
            raise ValueError("Username hanya boleh huruf, angka, underscore, titik, dan strip")
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("Format email tidak valid")
        return html.escape(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password minimal 8 karakter")
        return v


def _set_session_cookie(response: Response, token: str) -> None:
    """
    Fix #5: use max_age (persistent) NOT a session cookie.
    Session cookies disappear when browser closes — this is why users
    get logged out on browser close. max_age=72h keeps them logged in.
    """
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,       # JS cannot read — XSS protection
        samesite="lax",      # CSRF protection
        max_age=72 * 3600,   # 72 hours — survives browser close
        secure=False,        # set True when using HTTPS (Vercel auto-HTTPS)
        path="/",
    )


def _set_csrf_cookie(response: Response, csrf_token: str) -> None:
    """Set CSRF token cookie (readable by JS, not httponly)."""
    import secrets
    response.set_cookie(
        key="csrf_token",
        value=csrf_token or secrets.token_urlsafe(32),
        httponly=False,      # JS must read it to send as header
        samesite="strict",
        max_age=72 * 3600,
        path="/",
    )


# ── Pages ─────────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request):
    # Fix #5: if already logged in, go home — not login page
    user = await get_current_user_optional(request)
    if user:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request})


@router.get("/register", response_class=HTMLResponse, include_in_schema=False)
async def register_page(request: Request):
    user = await get_current_user_optional(request)
    if user:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("register.html", {"request": request})


# ── API ───────────────────────────────────────────────────────────────────────

@router.post("/api/auth/login")
async def api_login(payload: LoginRequest, response: Response):
    user = await authenticate_user(payload.username, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Username atau password salah")
    token = await create_session(user["id"])
    _set_session_cookie(response, token)

    # Issue fresh CSRF token on login
    import secrets as _s
    _set_csrf_cookie(response, _s.token_urlsafe(32))

    return {
        "ok": True,
        "user": {
            "id":       user["id"],
            "username": user["username"],
            "role":     user["role"],
        }
    }


@router.post("/api/auth/register")
async def api_register(payload: RegisterRequest, response: Response):
    user = await create_user(payload.username, payload.email, payload.password)
    if not user:
        raise HTTPException(
            status_code=409,
            detail="Username atau email sudah digunakan"
        )
    token = await create_session(user["id"])
    _set_session_cookie(response, token)

    import secrets as _s
    _set_csrf_cookie(response, _s.token_urlsafe(32))

    return {"ok": True, "user": user}


@router.post("/api/auth/logout")
async def api_logout(request: Request, response: Response):
    """
    Fix #1 #3: This is ONLY called when user explicitly presses the Logout button.
    Pressing browser Back, Home link, or closing browser does NOT call this.
    """
    token = request.cookies.get("session_token")
    if token:
        await delete_session(token)
    response.delete_cookie("session_token", path="/")
    response.delete_cookie("csrf_token", path="/")
    return {"ok": True}


@router.get("/api/auth/me")
async def api_me(request: Request):
    user = await get_current_user_optional(request)
    if not user:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "user": {
            "id":       user["id"],
            "username": user["username"],
            "role":     user["role"],
        }
    }
