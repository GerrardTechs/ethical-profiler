"""
routers/auth.py — Login, register, logout, profile endpoints.
"""
from fastapi import APIRouter, Request, Response, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr, Field
from pathlib import Path

from app.db.database import authenticate_user, create_user, create_session, delete_session, get_session_user
from app.middleware.auth import get_current_user, get_current_user_optional

BASE_DIR = Path(__file__).resolve().parent.parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email: str
    password: str = Field(..., min_length=8)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


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
    response.set_cookie(
        key="session_token", value=token,
        httponly=True, samesite="lax",
        max_age=72 * 3600,
    )
    return {"ok": True, "user": {"id": user["id"], "username": user["username"], "role": user["role"]}}


@router.post("/api/auth/register")
async def api_register(payload: RegisterRequest, response: Response):
    user = await create_user(payload.username, payload.email, payload.password)
    if not user:
        raise HTTPException(status_code=409, detail="Username atau email sudah digunakan")
    token = await create_session(user["id"])
    response.set_cookie(
        key="session_token", value=token,
        httponly=True, samesite="lax",
        max_age=72 * 3600,
    )
    return {"ok": True, "user": user}


@router.post("/api/auth/logout")
async def api_logout(request: Request, response: Response):
    token = request.cookies.get("session_token")
    if token:
        await delete_session(token)
    response.delete_cookie("session_token")
    return {"ok": True}


@router.get("/api/auth/me")
async def api_me(request: Request):
    user = await get_current_user_optional(request)
    if not user:
        return {"authenticated": False}
    return {"authenticated": True, "user": user}
