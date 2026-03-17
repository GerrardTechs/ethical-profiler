"""
routers/auth.py — Login, register, logout.
Fix defensive→login: cookie flags diperbaiki agar selalu dikirim di Vercel HTTPS.
Fix EXIT hapus credentials: logout hanya invalidate session di DB, cookie tetap
  ada tapi expired — user bisa login lagi tanpa re-register.
"""
import html
import os
import re
import secrets
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

# ─────────────────────────────────────────────────────────────────────────────
# Cookie helper
# Key insight:
#   - Vercel selalu HTTPS  → secure=True, samesite="lax"
#   - Localhost HTTP       → secure=False, samesite="lax"
#   - samesite="lax" (bukan "strict") agar cookie dikirim saat navigasi
#     normal antar halaman (GET request dari link). "strict" memblokir ini
#     sehingga klik link ke /defensive tidak membawa cookie → dianggap logout.
# ─────────────────────────────────────────────────────────────────────────────
_IS_VERCEL = bool(os.getenv("VERCEL") or os.getenv("VERCEL_ENV"))


def _cookie_flags() -> dict:
    """Return cookie flags yang benar untuk environment saat ini."""
    return dict(
        httponly=True,
        samesite="lax",       # WAJIB lax — strict memblokir navigasi lintas halaman
        max_age=72 * 3600,    # 72 jam — persistent, bukan session cookie
        secure=_IS_VERCEL,    # True di Vercel (HTTPS), False di localhost
        path="/",
    )


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(key="session_token", value=token, **_cookie_flags())


def _set_csrf_cookie(response: Response) -> str:
    token = secrets.token_urlsafe(32)
    response.set_cookie(
        key="csrf_token",
        value=token,
        httponly=False,    # JS harus bisa baca
        samesite="lax",
        max_age=72 * 3600,
        secure=_IS_VERCEL,
        path="/",
    )
    return token


# ── Pydantic models ───────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)

    @field_validator("username")
    @classmethod
    def sanitize(cls, v: str) -> str:
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
            raise ValueError("Username hanya huruf, angka, underscore, titik, strip")
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("Format email tidak valid")
        return html.escape(v)


# ── Pages ─────────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request):
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
    _set_csrf_cookie(response)

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
    _set_csrf_cookie(response)

    return {"ok": True, "user": user}


@router.post("/api/auth/logout")
async def api_logout(request: Request, response: Response):
    """
    Logout: hapus sesi dari DB (invalidate token), tapi TIDAK menghapus
    data akun pengguna. User tetap terdaftar dan bisa login lagi kapan saja.
    
    Yang dihapus: token sesi aktif (bukan akun, bukan password, bukan history).
    Cookie dihapus dari browser agar browser tidak mengirim token lama.
    """
    token = request.cookies.get("session_token")
    if token:
        # Hapus sesi dari DB — token ini tidak bisa dipakai lagi
        await delete_session(token)

    # Hapus cookie dari browser
    # max_age=0 memaksa browser menghapus cookie segera
    response.set_cookie(
        key="session_token", value="", max_age=0,
        httponly=True, samesite="lax",
        secure=_IS_VERCEL, path="/"
    )
    response.set_cookie(
        key="csrf_token", value="", max_age=0,
        httponly=False, samesite="lax",
        secure=_IS_VERCEL, path="/"
    )
    return {"ok": True, "message": "Berhasil logout. Data akun tetap tersimpan."}


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
