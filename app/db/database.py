"""
database.py — v4.1
Supports two storage modes:
  1. LOCAL / VERCEL-PERSISTENT: aiosqlite (file-based SQLite)
  2. TURSO (cloud SQLite, recommended for Vercel): libsql via HTTP
     Set TURSO_DATABASE_URL + TURSO_AUTH_TOKEN in .env to activate.
     Free tier: 500MB, unlimited reads, 1M writes/month.
     Sign up: https://turso.tech
"""

import json
import hashlib
import os
import secrets
import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import aiosqlite
from dotenv import load_dotenv

_EnvPath = Path
_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_FILE)

logger = logging.getLogger(__name__)

# Windows-safe default DB path
_default_db = (
    str(Path(__file__).resolve().parent.parent.parent / "data" / "profiler.db")
    if sys.platform == "win32"
    else "/tmp/profiler.db"
)
DB_PATH = Path(os.getenv("DB_PATH", _default_db))

# Turso cloud SQLite (optional — for persistent data on Vercel)
TURSO_URL   = os.getenv("TURSO_DATABASE_URL")   # libsql://xxx.turso.io
TURSO_TOKEN = os.getenv("TURSO_AUTH_TOKEN")

_INIT_SQL = [
    """CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT    UNIQUE NOT NULL,
        email         TEXT    UNIQUE NOT NULL,
        password_hash TEXT    NOT NULL,
        role          TEXT    DEFAULT 'user',
        is_active     INTEGER DEFAULT 1,
        created_at    TEXT    NOT NULL,
        last_login    TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS sessions (
        token       TEXT    PRIMARY KEY,
        user_id     INTEGER NOT NULL,
        expires_at  TEXT    NOT NULL,
        created_at  TEXT    NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    """CREATE TABLE IF NOT EXISTS scan_history (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id          TEXT    UNIQUE NOT NULL,
        user_id          INTEGER,
        full_name        TEXT    NOT NULL,
        location         TEXT,
        organization     TEXT,
        email            TEXT,
        username         TEXT,
        risk_level       TEXT    NOT NULL,
        exposure_score   INTEGER NOT NULL,
        confidence_score INTEGER NOT NULL,
        profiles_found   INTEGER DEFAULT 0,
        emails_found     INTEGER DEFAULT 0,
        phones_found     INTEGER DEFAULT 0,
        breaches_found   INTEGER DEFAULT 0,
        sources_checked  INTEGER DEFAULT 0,
        scan_mode        TEXT    DEFAULT 'standard',
        duration_ms      INTEGER DEFAULT 0,
        created_at       TEXT    NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )""",
    """CREATE TABLE IF NOT EXISTS scan_details (
        scan_id     TEXT PRIMARY KEY,
        result_json TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id) ON DELETE CASCADE
    )""",
    """CREATE TABLE IF NOT EXISTS username_cache (
        username    TEXT NOT NULL,
        platform    TEXT NOT NULL,
        profile_url TEXT,
        "exists"    INTEGER NOT NULL,
        checked_at  TEXT    NOT NULL,
        PRIMARY KEY (username, platform)
    )""",
    """CREATE TABLE IF NOT EXISTS api_usage_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER,
        scan_id    TEXT,
        api_name   TEXT    NOT NULL,
        success    INTEGER NOT NULL,
        latency_ms INTEGER DEFAULT 0,
        error_msg  TEXT,
        called_at  TEXT    NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_scan_name    ON scan_history(full_name)",
    "CREATE INDEX IF NOT EXISTS idx_scan_created ON scan_history(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_scan_risk    ON scan_history(risk_level)",
    "CREATE INDEX IF NOT EXISTS idx_scan_user    ON scan_history(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_session_tok  ON sessions(token)",
    "CREATE INDEX IF NOT EXISTS idx_api_log_date ON api_usage_log(called_at)",
]


# ── DB connection helper ──────────────────────────────────────────────────────

def _db():
    """Return aiosqlite connection to local DB."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return aiosqlite.connect(str(DB_PATH))


async def init_db() -> None:
    async with _db() as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA foreign_keys=ON")
        for stmt in _INIT_SQL:
            await db.execute(stmt)
        await db.commit()
        cursor = await db.execute("SELECT COUNT(*) FROM users")
        count = (await cursor.fetchone())[0]
        if count == 0:
            now = datetime.now(timezone.utc).isoformat()
            await db.execute(
                "INSERT INTO users (username,email,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                ("admin", "admin@profiler.local", _hash_password("admin123"), "admin", now)
            )
            await db.commit()
            logger.warning("[DB] Default admin: admin / admin123 — SEGERA GANTI!")
    logger.info(f"[DB] Ready at {DB_PATH}")

    if TURSO_URL and TURSO_TOKEN:
        logger.info("[DB] Turso cloud mode ACTIVE — data will persist on Vercel")
    else:
        logger.warning(
            "[DB] Using local SQLite. Data WILL BE LOST on Vercel cold starts. "
            "Set TURSO_DATABASE_URL + TURSO_AUTH_TOKEN to persist data. "
            "Free signup: https://turso.tech"
        )


# ── Passwords ─────────────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"{salt}:{h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
        return check.hex() == h
    except Exception:
        return False


# ── Auth ──────────────────────────────────────────────────────────────────────

async def create_user(username: str, email: str, password: str, role: str = "user") -> Optional[dict]:
    try:
        now = datetime.now(timezone.utc).isoformat()
        async with _db() as db:
            await db.execute(
                "INSERT INTO users (username,email,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                (username, email, _hash_password(password), role, now)
            )
            await db.commit()
            cursor = await db.execute("SELECT id,username,email,role FROM users WHERE username=?", (username,))
            row = await cursor.fetchone()
        return {"id": row[0], "username": row[1], "email": row[2], "role": row[3]} if row else None
    except aiosqlite.IntegrityError:
        return None


async def authenticate_user(username: str, password: str) -> Optional[dict]:
    try:
        async with _db() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM users WHERE (username=? OR email=?) AND is_active=1",
                (username, username)
            )
            row = await cursor.fetchone()
        if not row:
            return None
        user = dict(row)
        if not verify_password(password, user["password_hash"]):
            return None
        async with _db() as db:
            await db.execute("UPDATE users SET last_login=? WHERE id=?",
                             (datetime.now(timezone.utc).isoformat(), user["id"]))
            await db.commit()
        return {k: v for k, v in user.items() if k != "password_hash"}
    except Exception as e:
        logger.error(f"[DB] authenticate_user: {e}"); return None


async def create_session(user_id: int, expires_hours: int = 72) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = (now + timedelta(hours=expires_hours)).isoformat()
    async with _db() as db:
        await db.execute(
            "INSERT INTO sessions (token,user_id,expires_at,created_at) VALUES (?,?,?,?)",
            (token, user_id, expires, now.isoformat())
        )
        await db.commit()
    return token


async def get_session_user(token: str) -> Optional[dict]:
    try:
        now = datetime.now(timezone.utc).isoformat()
        async with _db() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT u.id, u.username, u.email, u.role
                FROM sessions s JOIN users u ON s.user_id = u.id
                WHERE s.token=? AND s.expires_at > ? AND u.is_active=1
            """, (token, now))
            row = await cursor.fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"[DB] get_session_user: {e}"); return None


async def delete_session(token: str) -> None:
    async with _db() as db:
        await db.execute("DELETE FROM sessions WHERE token=?", (token,))
        await db.commit()


async def get_all_users() -> list[dict]:
    try:
        async with _db() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT u.id, u.username, u.email, u.role, u.is_active,
                       u.created_at, u.last_login,
                       COUNT(s.scan_id) as total_scans
                FROM users u
                LEFT JOIN scan_history s ON u.id = s.user_id
                GROUP BY u.id ORDER BY u.created_at DESC
            """)
            rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"[DB] get_all_users: {e}"); return []


async def toggle_user_status(user_id: int, is_active: bool) -> bool:
    try:
        async with _db() as db:
            await db.execute("UPDATE users SET is_active=? WHERE id=?", (int(is_active), user_id))
            await db.commit()
        return True
    except Exception as e:
        logger.error(f"[DB] toggle_user_status: {e}"); return False


async def change_user_role(user_id: int, role: str) -> bool:
    try:
        async with _db() as db:
            await db.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
            await db.commit()
        return True
    except Exception as e:
        logger.error(f"[DB] change_user_role: {e}"); return False


# ── Scans ─────────────────────────────────────────────────────────────────────

async def save_scan(result_dict: dict, scan_mode: str = "standard",
                    user_id: Optional[int] = None, duration_ms: int = 0) -> bool:
    try:
        now = datetime.now(timezone.utc).isoformat()
        sid = result_dict["scan_id"]
        async with _db() as db:
            await db.execute("PRAGMA foreign_keys=ON")
            await db.execute("""
                INSERT OR REPLACE INTO scan_history (
                    scan_id, user_id, full_name, location, organization, email, username,
                    risk_level, exposure_score, confidence_score,
                    profiles_found, emails_found, phones_found, breaches_found,
                    sources_checked, scan_mode, duration_ms, created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                sid, user_id,
                result_dict.get("full_name", ""),
                result_dict.get("location"), result_dict.get("organization"),
                next((c["value"] for c in result_dict.get("discovered_contacts", [])
                      if c.get("contact_type") == "email"), None),
                None,
                result_dict.get("risk_level", "LOW"),
                result_dict.get("exposure_score", 0),
                result_dict.get("confidence_score", 0),
                len(result_dict.get("matched_profiles", [])),
                len(result_dict.get("probable_emails", [])),
                len([c for c in result_dict.get("discovered_contacts", [])
                     if c.get("contact_type") == "phone"]),
                len(result_dict.get("breaches", [])),
                result_dict.get("sources_checked", 0),
                scan_mode, duration_ms, now,
            ))
            await db.execute(
                "INSERT OR REPLACE INTO scan_details (scan_id,result_json,created_at) VALUES (?,?,?)",
                (sid, json.dumps(result_dict), now),
            )
            await db.commit()
        return True
    except Exception as e:
        logger.error(f"[DB] save_scan: {e}"); return False


async def get_scan_history(limit: int = 50, offset: int = 0,
                           search: Optional[str] = None, risk_filter: Optional[str] = None,
                           user_id: Optional[int] = None) -> list[dict]:
    try:
        conds, params = [], []
        if user_id is not None:
            conds.append("h.user_id=?"); params.append(user_id)
        if search:
            conds.append("(h.full_name LIKE ? OR h.organization LIKE ? OR h.email LIKE ?)")
            params += [f"%{search}%", f"%{search}%", f"%{search}%"]
        if risk_filter:
            conds.append("h.risk_level=?"); params.append(risk_filter.upper())
        where = ("WHERE " + " AND ".join(conds)) if conds else ""
        params += [limit, offset]
        async with _db() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(f"""
                SELECT h.*, u.username as scanned_by
                FROM scan_history h
                LEFT JOIN users u ON h.user_id = u.id
                {where} ORDER BY h.created_at DESC LIMIT ? OFFSET ?
            """, params)
            rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"[DB] get_scan_history: {e}"); return []


async def get_scan_detail(scan_id: str) -> Optional[dict]:
    try:
        async with _db() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT result_json FROM scan_details WHERE scan_id=?", (scan_id,))
            row = await cursor.fetchone()
        return json.loads(row["result_json"]) if row else None
    except Exception as e:
        logger.error(f"[DB] get_scan_detail: {e}"); return None


async def delete_scan(scan_id: str) -> bool:
    try:
        async with _db() as db:
            await db.execute("DELETE FROM scan_history WHERE scan_id=?", (scan_id,))
            await db.commit()
        return True
    except Exception as e:
        logger.error(f"[DB] delete_scan: {e}"); return False


# ── Analytics ─────────────────────────────────────────────────────────────────

async def get_stats(user_id: Optional[int] = None) -> dict:
    try:
        where = "WHERE user_id=?" if user_id else ""
        params = [user_id] if user_id else []
        async with _db() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(f"""
                SELECT
                    COUNT(*)                                              as total_scans,
                    SUM(CASE WHEN risk_level='HIGH'     THEN 1 ELSE 0 END) as high_risk,
                    SUM(CASE WHEN risk_level='MODERATE' THEN 1 ELSE 0 END) as moderate_risk,
                    SUM(CASE WHEN risk_level='LOW'      THEN 1 ELSE 0 END) as low_risk,
                    SUM(breaches_found)                                   as total_breaches,
                    SUM(profiles_found)                                   as total_profiles,
                    SUM(emails_found)                                     as total_emails,
                    ROUND(AVG(exposure_score), 1)                         as avg_exposure,
                    ROUND(AVG(duration_ms), 0)                            as avg_duration_ms,
                    MAX(created_at)                                       as last_scan,
                    MIN(created_at)                                       as first_scan
                FROM scan_history {where}
            """, params)
            row = await cursor.fetchone()
        return dict(row) if row else {}
    except Exception as e:
        logger.error(f"[DB] get_stats: {e}"); return {}


async def get_scan_trend(days: int = 30, user_id: Optional[int] = None) -> list[dict]:
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        conds = ["created_at >= ?"]
        params: list = [since]
        if user_id:
            conds.append("user_id=?"); params.append(user_id)
        where = "WHERE " + " AND ".join(conds)
        async with _db() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(f"""
                SELECT substr(created_at,1,10) as date,
                       COUNT(*) as count,
                       SUM(CASE WHEN risk_level='HIGH' THEN 1 ELSE 0 END) as high_count,
                       ROUND(AVG(exposure_score),1) as avg_score
                FROM scan_history {where}
                GROUP BY date ORDER BY date ASC
            """, params)
            rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"[DB] get_scan_trend: {e}"); return []


async def get_risk_distribution(user_id: Optional[int] = None) -> dict:
    try:
        where = "WHERE user_id=?" if user_id else ""
        params = [user_id] if user_id else []
        async with _db() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(f"""
                SELECT risk_level, COUNT(*) as count
                FROM scan_history {where} GROUP BY risk_level
            """, params)
            rows = await cursor.fetchall()
        return {r["risk_level"]: r["count"] for r in rows}
    except Exception as e:
        logger.error(f"[DB] get_risk_distribution: {e}"); return {}


async def get_top_targets(limit: int = 10, user_id: Optional[int] = None) -> list[dict]:
    try:
        where = "WHERE user_id=?" if user_id else ""
        params: list = [user_id] if user_id else []
        params.append(limit)
        async with _db() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(f"""
                SELECT full_name, organization, MAX(exposure_score) as max_score,
                       COUNT(*) as scan_count, MAX(risk_level) as risk_level,
                       MAX(breaches_found) as breaches
                FROM scan_history {where}
                GROUP BY full_name ORDER BY max_score DESC LIMIT ?
            """, params)
            rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"[DB] get_top_targets: {e}"); return []


async def get_breach_stats(user_id: Optional[int] = None) -> dict:
    try:
        where = "WHERE user_id=?" if user_id else ""
        params = [user_id] if user_id else []
        async with _db() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(f"""
                SELECT SUM(breaches_found) as total_breaches,
                       COUNT(CASE WHEN breaches_found > 0 THEN 1 END) as scans_with_breaches,
                       MAX(breaches_found) as max_breaches_single,
                       ROUND(AVG(CASE WHEN breaches_found > 0 THEN breaches_found END),1) as avg_breaches
                FROM scan_history {where}
            """, params)
            row = await cursor.fetchone()
        return dict(row) if row else {}
    except Exception as e:
        logger.error(f"[DB] get_breach_stats: {e}"); return {}


async def get_api_performance() -> list[dict]:
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        async with _db() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT api_name, COUNT(*) as total_calls,
                       SUM(success) as success_count,
                       ROUND(AVG(latency_ms),0) as avg_latency,
                       MAX(latency_ms) as max_latency
                FROM api_usage_log WHERE called_at >= ?
                GROUP BY api_name ORDER BY total_calls DESC
            """, (since,))
            rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"[DB] get_api_performance: {e}"); return []


async def log_api_call(api_name: str, success: bool, latency_ms: int = 0,
                       scan_id: Optional[str] = None, user_id: Optional[int] = None,
                       error_msg: Optional[str] = None) -> None:
    try:
        now = datetime.now(timezone.utc).isoformat()
        async with _db() as db:
            await db.execute(
                "INSERT INTO api_usage_log (user_id,scan_id,api_name,success,latency_ms,error_msg,called_at) VALUES (?,?,?,?,?,?,?)",
                (user_id, scan_id, api_name, int(success), latency_ms, error_msg, now)
            )
            await db.commit()
    except Exception:
        pass


async def save_username_cache(username: str, results: list[dict]) -> None:
    try:
        now = datetime.now(timezone.utc).isoformat()
        async with _db() as db:
            await db.executemany("""
                INSERT OR REPLACE INTO username_cache
                (username, platform, profile_url, "exists", checked_at) VALUES (?,?,?,?,?)
            """, [(username, r["platform"], r.get("url",""), int(r.get("exists",False)), now)
                  for r in results])
            await db.commit()
    except Exception as e:
        logger.error(f"[DB] save_username_cache: {e}")


async def get_username_cache(username: str) -> list[dict]:
    try:
        async with _db() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM username_cache WHERE username=? ORDER BY platform", (username,))
            rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"[DB] get_username_cache: {e}"); return []
