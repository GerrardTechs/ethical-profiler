"""
username.py — Username enumeration endpoint.
"""

import logging
from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import Optional, List
from app.services.username_enum import enumerate_username, PLATFORMS
from app.db.database import save_username_cache, get_username_cache

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/username", tags=["username"])


class UsernameRequest(BaseModel):
    username:   str         = Field(..., min_length=1, max_length=50)
    categories: Optional[List[str]] = None
    use_cache:  bool        = True


@router.post("/check")
async def check_username(payload: UsernameRequest):
    username = payload.username.strip().lstrip("@")

    # Try cache first
    if payload.use_cache:
        cached = await get_username_cache(username)
        if cached:
            logger.info(f"[Username] Cache hit for '{username}' — {len(cached)} results")
            found    = [r for r in cached if r.get("exists")]
            return {
                "username":    username,
                "total":       len(cached),
                "found_count": len(found),
                "found":       found,
                "all":         cached,
                "from_cache":  True,
            }

    results = await enumerate_username(
        username,
        categories=payload.categories,
    )

    # Save to cache
    await save_username_cache(username, results)

    found = [r for r in results if r.get("exists")]
    return {
        "username":    username,
        "total":       len(results),
        "found_count": len(found),
        "found":       found,
        "all":         results,
        "from_cache":  False,
    }


@router.get("/categories")
async def list_categories():
    cats = sorted(set(p[1] for p in PLATFORMS))
    return {"categories": cats, "total_platforms": len(PLATFORMS)}
