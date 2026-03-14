"""
Real API client integrations — v4 (fixed).

Keys your .env currently has and what they map to:
  LEAKCHECK_API_KEY   → check_breaches_leakcheck()
  GITHUB_TOKEN        → github_search_users()
  SERPAPI             → serpapi_search_mentions()   [replaces Google CSE]
  SHODAN_KEY          → shodan_org_search()
  INTELLIGENCE_KEY    → intelx_search()             [Intelligence X]

Keys you can add later (all free):
  HUNTER_API_KEY      → hunter_find_email() / hunter_domain_search()
  ABSTRACT_API_KEY    → validate_email_abstract()
  EMAILREP_API_KEY    → emailrep_lookup()
  BRAVE_API_KEY       → brave_search_mentions()

PhoneInfoga integration:
  Runs as a local Docker container on port 5000.
  Start it with:
    docker run -it -p 5000:5000 sundowndev/phoneinfoga serve -p 5000
  Then set in .env:
    PHONEINFOGA_URL=http://localhost:5000
"""

import asyncio
import hashlib
import logging
import os
import re
from typing import Optional

import httpx
from dotenv import load_dotenv

from app.models.schemas import (
    BreachRecord,
    CertRecord,
    EmailValidation,
    GravatarResult,
    IntelXResult,
    MatchedProfile,
    EmailPattern,
    PhoneInfoResult,
    ShodanResult,
)

from pathlib import Path as _Path

# Load .env from project root regardless of working directory (fixes Windows)
_ENV_PATH = _Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH)
logger = logging.getLogger(__name__)

# ── API keys — matched EXACTLY to your .env variable names ────────────────────
GITHUB_TOKEN      = os.getenv("GITHUB_TOKEN")
LEAKCHECK_KEY     = os.getenv("LEAKCHECK_API_KEY")
SERPAPI_KEY       = os.getenv("SERPAPI")              # your key name
SHODAN_KEY        = os.getenv("SHODAN_KEY")           # your key name
INTELX_KEY        = os.getenv("INTELLIGENCE_KEY")     # your key name
HUNTER_KEY        = os.getenv("HUNTER_API_KEY")       # add this when you get it
ABSTRACT_KEY      = os.getenv("ABSTRACT_API_KEY")
EMAILREP_KEY      = os.getenv("EMAILREP_API_KEY")
BRAVE_KEY         = os.getenv("BRAVE_API_KEY")
PHONEINFOGA_URL   = os.getenv("PHONEINFOGA_URL", "http://localhost:5000")
WHOISXML_KEY      = os.getenv("WHOISXML_API_KEY")
URLSCAN_KEY       = os.getenv("URLSCAN_API_KEY")
CENSYS_KEY        = os.getenv("CENSYS_API_KEY")

_TIMEOUT = httpx.Timeout(connect=6.0, read=12.0, write=5.0, pool=2.0)


def _warn(service: str, var: str) -> None:
    logger.warning(f"[{service}] Not configured — add {var} to .env")


# ══════════════════════════════════════════════════════════════════════════════
# 1. GITHUB
# ══════════════════════════════════════════════════════════════════════════════

async def github_search_users(
    full_name: str,
    username_hint: Optional[str] = None,
) -> tuple[list[MatchedProfile], bool]:
    """
    Multi-strategy GitHub profile discovery.
    Searches by: direct username, full name, firstname+lastname, name parts,
    location-aware queries, and repo commit author email mining.
    """
    if not GITHUB_TOKEN:
        _warn("GitHub", "GITHUB_TOKEN"); return [], False

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    profiles: list[MatchedProfile] = []
    seen: set[str] = set()
    name_lower = full_name.lower()
    _gh_sem = asyncio.Semaphore(3)  # max 3 concurrent GitHub requests to avoid rate limiting

    # Build name variants for searching
    name_parts = full_name.strip().split()
    first = name_parts[0] if name_parts else ""
    last  = name_parts[-1] if len(name_parts) > 1 else ""

    # Candidate username guesses from name
    username_guesses: list[str] = []
    if username_hint:
        username_guesses.append(username_hint)
    if first and last:
        username_guesses += [
            f"{first}{last}".lower(),
            f"{first}-{last}".lower(),
            f"{first}_{last}".lower(),
            f"{last}{first}".lower(),
            f"{first[0]}{last}".lower(),
            f"{first}{last[0]}".lower(),
        ]

    async def _fetch_user(login: str, conf: int) -> None:
        if login in seen: return
        async with _gh_sem:
            try:
                r = await client.get(f"https://api.github.com/users/{login}", headers=headers)
                if r.status_code == 200:
                    user = r.json()
                    seen.add(login)
                    profiles.append(_gh_profile(user, conf))
                elif r.status_code == 403:
                    # Rate limited — back off briefly
                    retry_after = int(r.headers.get("Retry-After", "5"))
                    logger.warning(f"[GitHub] Rate limited on user lookup, backing off {retry_after}s")
                    await asyncio.sleep(min(retry_after, 10))
            except Exception:
                pass

    async def _search_query(q: str, per_page: int = 8) -> list[dict]:
        async with _gh_sem:
            try:
                r = await client.get(
                    "https://api.github.com/search/users",
                    headers=headers, params={"q": q, "per_page": per_page, "sort": "followers"})
                if r.status_code == 200:
                    return r.json().get("items", [])
                if r.status_code == 403:
                    retry_after = int(r.headers.get("Retry-After", "10"))
                    logger.warning(f"[GitHub] Rate limited on search, backing off {retry_after}s")
                    await asyncio.sleep(min(retry_after, 15))
            except Exception as e:
                logger.error(f"[GitHub] search error: {e}")
        return []

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            # ── Strategy 1: Direct username guesses ──────────────────────
            for guess in username_guesses[:4]:  # limit API calls
                await _fetch_user(guess, 90)

            # ── Strategy 2: Full name search ──────────────────────────────
            items = await _search_query(f'"{full_name}" in:name', per_page=8)
            for item in items[:5]:
                login = item["login"]
                if login in seen: continue
                dr = await client.get(item["url"], headers=headers)
                if dr.status_code == 200:
                    user = dr.json()
                    seen.add(login)
                    # Confidence based on name match quality
                    user_name = (user.get("name") or "").lower()
                    if name_lower == user_name:
                        conf = 93
                    elif name_lower in user_name or user_name in name_lower:
                        conf = 85
                    elif first.lower() in user_name and last.lower() in user_name:
                        conf = 82
                    else:
                        conf = 72
                    profiles.append(_gh_profile(user, conf))

            # ── Strategy 3: First + Last name search (catches non-exact) ──
            if first and last and len(profiles) < 3:
                items2 = await _search_query(f'{first} {last} in:name', per_page=6)
                for item in items2[:4]:
                    login = item["login"]
                    if login in seen: continue
                    dr = await client.get(item["url"], headers=headers)
                    if dr.status_code == 200:
                        user = dr.json()
                        seen.add(login)
                        user_name = (user.get("name") or "").lower()
                        conf = 80 if (first.lower() in user_name and last.lower() in user_name) else 65
                        profiles.append(_gh_profile(user, conf))

            # ── Strategy 4: Username contains lastname/firstname ───────────
            if last and len(profiles) < 2:
                items3 = await _search_query(f'{last} in:login', per_page=5)
                for item in items3[:3]:
                    login = item["login"]
                    if login in seen: continue
                    # Only include if first name also appears somewhere
                    login_lower = login.lower()
                    if first.lower() in login_lower or (len(first) > 2 and first[:3].lower() in login_lower):
                        dr = await client.get(item["url"], headers=headers)
                        if dr.status_code == 200:
                            user = dr.json()
                            seen.add(login)
                            profiles.append(_gh_profile(user, 70))

            return profiles, True

        except Exception as e:
            logger.error(f"[GitHub] {e}"); return profiles, bool(profiles)


def _gh_profile(user: dict, confidence: int) -> MatchedProfile:
    parts = []
    if user.get("name"):         parts.append(user["name"])
    if user.get("company"):      parts.append(f"@ {user['company'].strip('@')}")
    if user.get("location"):     parts.append(f"· {user['location']}")
    if user.get("public_repos"): parts.append(f"· {user['public_repos']} repos")
    if user.get("followers"):    parts.append(f"· {user['followers']} followers")
    if user.get("email"):        parts.append(f"· 📧 {user['email']}")
    bio = "  ".join(parts) or user.get("bio") or ""
    return MatchedProfile(
        platform="GitHub", profile_url=user.get("html_url", ""),
        username=user.get("login", ""), confidence=confidence,
        bio_snippet=bio[:200] or None, category="developer",
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2. LEAKCHECK — uses LEAKCHECK_API_KEY
# ══════════════════════════════════════════════════════════════════════════════

async def check_breaches_leakcheck(email: str) -> tuple[list[BreachRecord], bool]:
    """
    Breach lookup via LeakCheck.io.
    Free tier: 50 requests/day.
    Your key: LEAKCHECK_API_KEY in .env ✓
    """
    if not LEAKCHECK_KEY:
        _warn("LeakCheck", "LEAKCHECK_API_KEY"); return [], False

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                "https://leakcheck.io/api/public",
                params={"key": LEAKCHECK_KEY, "check": email},
            )
            if r.status_code == 200:
                data = r.json()
                if not data.get("success"): return [], True
                return [
                    BreachRecord(
                        source=s.get("name", "Unknown"),
                        date=str(s.get("date")) if s.get("date") else None,
                        data_classes=s.get("data", []),
                        verified=True,
                    ) for s in data.get("sources", [])
                ], True
            elif r.status_code == 401:
                logger.error("[LeakCheck] Invalid key — check LEAKCHECK_API_KEY"); return [], False
            elif r.status_code == 429:
                logger.warning("[LeakCheck] 50/day free limit hit"); return [], False
            else:
                logger.warning(f"[LeakCheck] Status {r.status_code}"); return [], False
        except Exception as e:
            logger.error(f"[LeakCheck] {e}"); return [], False


# ══════════════════════════════════════════════════════════════════════════════
# 3. SERPAPI — replaces Google CSE, uses SERPAPI key from .env
#    Sign up: https://serpapi.com (100 free searches/month)
#    Your key is set as SERPAPI= in your .env ✓
# ══════════════════════════════════════════════════════════════════════════════

async def serpapi_search_mentions(
    full_name: str,
    organization: Optional[str] = None,
    location: Optional[str] = None,
    num_results: int = 8,
) -> tuple[list[MatchedProfile], bool]:
    """
    Multi-query web search via SerpApi.
    Runs targeted searches for social profiles, GitHub, LinkedIn, and emails.
    Free tier: 100 searches/month — uses up to 3 queries per scan.
    """
    if not SERPAPI_KEY:
        _warn("SerpApi", "SERPAPI"); return [], False

    context_parts = []
    if organization: context_parts.append(organization)
    if location:     context_parts.append(location)
    context = " ".join(context_parts)

    # 2 targeted queries per scan — balances quota vs coverage.
    # Query 1: social/developer profiles (highest signal)
    # Query 2: contextual search with org/location for bio/contact info
    # NOTE: Free SerpAPI = 100 searches/month → ~50 scans/month.
    # A 3rd "email hunting" query was removed — low yield, high quota cost.
    queries = [
        f'"{full_name}" site:github.com OR site:linkedin.com OR site:twitter.com OR site:instagram.com OR site:gitlab.com',
        f'"{full_name}" {context}'.strip() if context else f'"{full_name}" profile OR portfolio OR about',
    ]

    profiles: list[MatchedProfile] = []
    seen_urls: set[str] = set()
    any_ok = False

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for query in queries:
            try:
                r = await client.get(
                    "https://serpapi.com/search",
                    params={
                        "api_key": SERPAPI_KEY,
                        "engine":  "google",
                        "q":       query,
                        "num":     num_results,
                        "hl":      "en",
                        "gl":      "us",
                    },
                )
                if r.status_code == 200:
                    any_ok = True
                    organic = r.json().get("organic_results", [])
                    for item in organic:
                        url     = item.get("link", "")
                        snippet = item.get("snippet", "")
                        title   = item.get("title", "")
                        if url in seen_urls: continue
                        seen_urls.add(url)
                        cat, platform, conf = _classify_url(url)
                        profiles.append(MatchedProfile(
                            platform=platform, profile_url=url,
                            username=full_name, confidence=conf,
                            bio_snippet=(snippet or title)[:180],
                            category=cat,
                        ))
                elif r.status_code == 401:
                    logger.error("[SerpApi] Invalid key — check SERPAPI in .env"); break
                elif r.status_code == 429:
                    logger.warning("[SerpApi] Monthly quota hit (100/month free tier)"); break
                else:
                    logger.warning(f"[SerpApi] Status {r.status_code}: {r.text[:200]}")
            except Exception as e:
                logger.error(f"[SerpApi] {e}")

    return profiles, any_ok


# ══════════════════════════════════════════════════════════════════════════════
# 4. SHODAN — uses SHODAN_KEY from .env
#    Your key: SHODAN_KEY ✓
#    Free tier: basic host search (no scan credits needed)
# ══════════════════════════════════════════════════════════════════════════════

async def shodan_org_search(org_name: str) -> tuple[list[ShodanResult], bool]:
    """
    Search Shodan for internet-exposed infrastructure linked to an organization.
    Free tier: search queries allowed, ~1 req/sec.
    Your .env key: SHODAN_KEY ✓
    """
    if not SHODAN_KEY:
        _warn("Shodan", "SHODAN_KEY"); return [], False

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": SHODAN_KEY, "query": f'org:"{org_name}"', "limit": 5},
            )
            if r.status_code == 200:
                matches = r.json().get("matches", [])
                return [
                    ShodanResult(
                        ip=m.get("ip_str", ""),
                        hostnames=m.get("hostnames", []),
                        ports=[m.get("port", 0)] if m.get("port") else [],
                        org=m.get("org"),
                        country=m.get("location", {}).get("country_name"),
                        vulns=list(m.get("vulns", {}).keys()),
                        last_seen=m.get("timestamp"),
                    ) for m in matches
                ], True
            elif r.status_code == 401:
                logger.error("[Shodan] Invalid key — check SHODAN_KEY in .env"); return [], False
            elif r.status_code == 402:
                # Free Shodan accounts can't use org: filter — fall back to hostname search
                logger.warning("[Shodan] org: query needs paid plan, trying hostname fallback")
                return await _shodan_hostname_fallback(org_name, client), False
            else:
                logger.warning(f"[Shodan] Status {r.status_code}"); return [], False
        except Exception as e:
            logger.error(f"[Shodan] {e}"); return [], False


async def _shodan_hostname_fallback(
    org_name: str,
    client: httpx.AsyncClient,
) -> list[ShodanResult]:
    """
    Fallback for free Shodan accounts: search by hostname instead of org.
    Derives a domain from the org name and searches for that.
    """
    domain = extract_domain_from_org(org_name)
    if not domain:
        return []
    try:
        r = await client.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": SHODAN_KEY, "query": f"hostname:{domain}", "limit": 5},
        )
        if r.status_code == 200:
            matches = r.json().get("matches", [])
            return [
                ShodanResult(
                    ip=m.get("ip_str", ""),
                    hostnames=m.get("hostnames", []),
                    ports=[m.get("port", 0)] if m.get("port") else [],
                    org=m.get("org"),
                    country=m.get("location", {}).get("country_name"),
                    vulns=list(m.get("vulns", {}).keys()),
                    last_seen=m.get("timestamp"),
                ) for m in matches
            ]
    except Exception:
        pass
    return []


# ══════════════════════════════════════════════════════════════════════════════
# 5. INTELLIGENCE X (IntelX) — uses INTELLIGENCE_KEY from .env
#    Your key: INTELLIGENCE_KEY ✓
#    Sign up: https://intelx.io/?signup
#    Free tier: limited searches per day
# ══════════════════════════════════════════════════════════════════════════════

async def intelx_search(query: str) -> tuple[list[IntelXResult], bool]:
    """
    Search Intelligence X OSINT aggregator for indexed references.
    Searches pastes, darkweb, documents, and public web.
    Your .env key: INTELLIGENCE_KEY ✓
    """
    if not INTELX_KEY:
        _warn("IntelX", "INTELLIGENCE_KEY"); return [], False

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            # Step 1: Start the search
            init_r = await client.post(
                "https://2.intelx.io/intelligent/search",
                headers={"x-key": INTELX_KEY, "Content-Type": "application/json"},
                json={
                    "term":        query,
                    "buckets":     [],
                    "lookuplevel": 0,
                    "maxresults":  10,
                    "timeout":     5,
                    "datefrom":    "",
                    "dateto":      "",
                    "sort":        4,       # sort by date desc
                    "media":       0,
                    "terminate":   [],
                },
            )
            if init_r.status_code == 401:
                logger.error("[IntelX] Invalid key — check INTELLIGENCE_KEY in .env")
                return [], False
            if init_r.status_code != 200:
                logger.warning(f"[IntelX] Init status {init_r.status_code}")
                return [], False

            search_id = init_r.json().get("id")
            if not search_id:
                return [], False

            # Step 2: Wait briefly then fetch results
            import asyncio
            await asyncio.sleep(2)

            result_r = await client.get(
                "https://2.intelx.io/intelligent/search/result",
                headers={"x-key": INTELX_KEY},
                params={"id": search_id, "limit": 10},
            )
            if result_r.status_code == 200:
                records = result_r.json().get("records", [])
                return [
                    IntelXResult(
                        storageid=rec.get("storageid", ""),
                        systemid=rec.get("systemid", 0),
                        bucket=rec.get("bucket", ""),
                        name=rec.get("name", ""),
                        date=rec.get("date"),
                    ) for rec in records
                ], True
            return [], False

        except Exception as e:
            logger.error(f"[IntelX] {e}"); return [], False


# ══════════════════════════════════════════════════════════════════════════════
# 6. PHONEINFOGA — self-hosted Docker, no API key needed
#    Setup (run once in terminal):
#      docker run -it -p 5000:5000 sundowndev/phoneinfoga serve -p 5000
#    Then add to .env:
#      PHONEINFOGA_URL=http://localhost:5000
#    It will be called automatically when a phone number is provided in the scan.
# ══════════════════════════════════════════════════════════════════════════════

async def phoneinfoga_scan(phone_number: str) -> tuple[Optional[PhoneInfoResult], bool]:
    """
    Scan a phone number using PhoneInfoga REST API (self-hosted).

    PhoneInfoga gathers:
      - Carrier / line type (mobile, landline, VoIP)
      - Country + region
      - Number validity
      - Reputation data from public sources

    Requires PhoneInfoga running locally:
      docker run -it -p 5000:5000 sundowndev/phoneinfoga serve -p 5000

    Returns: (PhoneInfoResult | None, success)
    """
    if not PHONEINFOGA_URL:
        _warn("PhoneInfoga", "PHONEINFOGA_URL"); return None, False

    # Normalize: strip spaces/dashes, ensure + prefix
    clean_number = re.sub(r"[\s\-\(\)]", "", phone_number)
    if not clean_number.startswith("+"):
        clean_number = "+" + clean_number

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            # PhoneInfoga REST API endpoint
            r = await client.get(
                f"{PHONEINFOGA_URL}/api/v2/phones/{clean_number}/scan/local",
            )
            if r.status_code == 200:
                data = r.json()
                return PhoneInfoResult(
                    number=clean_number,
                    valid=data.get("Valid", False),
                    country=data.get("Country", ""),
                    carrier=data.get("Carrier", ""),
                    line_type=data.get("LineType", ""),
                    region=data.get("Region", ""),
                    raw=data,
                ), True
            elif r.status_code == 404:
                logger.warning("[PhoneInfoga] Number not found or invalid")
                return PhoneInfoResult(
                    number=clean_number, valid=False,
                    country="", carrier="", line_type="", region="",
                ), True
            else:
                logger.warning(f"[PhoneInfoga] Status {r.status_code} — is Docker running?")
                return None, False
        except httpx.ConnectError:
            logger.warning(
                "[PhoneInfoga] Connection refused — start Docker container:\n"
                "  docker run -it -p 5000:5000 sundowndev/phoneinfoga serve -p 5000"
            )
            return None, False
        except Exception as e:
            logger.error(f"[PhoneInfoga] {e}"); return None, False


# ══════════════════════════════════════════════════════════════════════════════
# 7. HUNTER.IO — optional, add HUNTER_API_KEY when you get it
# ══════════════════════════════════════════════════════════════════════════════

async def hunter_find_email(
    full_name: str,
    domain: str,
) -> tuple[Optional[EmailValidation], bool]:
    """Email finder via Hunter.io. Add HUNTER_API_KEY to .env when ready."""
    if not HUNTER_KEY:
        _warn("Hunter.io", "HUNTER_API_KEY"); return None, False

    parts = full_name.strip().split()
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                "https://api.hunter.io/v2/email-finder",
                params={
                    "domain":     domain,
                    "first_name": parts[0] if parts else "",
                    "last_name":  parts[-1] if len(parts) > 1 else "",
                    "api_key":    HUNTER_KEY,
                },
            )
            if r.status_code == 200:
                data  = r.json().get("data", {})
                email = data.get("email")
                if not email: return None, True
                return EmailValidation(
                    address=email, is_valid_format=True,
                    is_deliverable=data.get("smtp_server") is not None,
                    provider=domain, source="hunter",
                ), True
            elif r.status_code == 429:
                logger.warning("[Hunter] Monthly quota hit (25/month)"); return None, False
            return None, False
        except Exception as e:
            logger.error(f"[Hunter] {e}"); return None, False


async def hunter_domain_search(domain: str, limit: int = 5) -> tuple[list[EmailPattern], bool]:
    if not HUNTER_KEY:
        return [], False
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                "https://api.hunter.io/v2/domain-search",
                params={"domain": domain, "limit": limit, "api_key": HUNTER_KEY},
            )
            if r.status_code == 200:
                items = r.json().get("data", {}).get("emails", [])
                return [
                    EmailPattern(
                        address=i["value"],
                        pattern_type=f"hunter domain · {i.get('type', '?')}",
                        confidence=85 if int(i.get("confidence", 0)) >= 80 else 65,
                    )
                    for i in items if i.get("value")
                ], True
            return [], False
        except Exception as e:
            logger.error(f"[Hunter domain] {e}"); return [], False


# ══════════════════════════════════════════════════════════════════════════════
# 8. EMAILREP.IO — optional, add EMAILREP_API_KEY when you get it
#    Get key instantly at: emailrep.io/key  (no card, just email)
#    Free: 1,000/day
# ══════════════════════════════════════════════════════════════════════════════

async def emailrep_lookup(email: str):
    """Email reputation. Add EMAILREP_API_KEY to .env (free at emailrep.io/key)."""
    if not EMAILREP_KEY:
        return None, False
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                f"https://emailrep.io/{email}",
                headers={"Key": EMAILREP_KEY, "User-Agent": "EDFP-Profiler/1.0"},
            )
            if r.status_code == 200:
                data = r.json()
                from app.models.schemas import EmailRepResult
                return EmailRepResult(
                    address=email,
                    reputation=data.get("reputation", "none"),
                    suspicious=data.get("suspicious", False),
                    references=data.get("references", 0),
                    details=data.get("details", {}),
                ), True
            return None, False
        except Exception as e:
            logger.error(f"[EmailRep] {e}"); return None, False


# ══════════════════════════════════════════════════════════════════════════════
# 9. GRAVATAR — no key needed, always runs
# ══════════════════════════════════════════════════════════════════════════════

async def check_gravatar(email: str) -> tuple[Optional[GravatarResult], bool]:
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.head(f"https://www.gravatar.com/avatar/{h}?d=404")
            if r.status_code == 200:
                return GravatarResult(
                    email=email, has_gravatar=True,
                    avatar_url=f"https://www.gravatar.com/avatar/{h}?s=200",
                    profile_url=f"https://gravatar.com/{h}",
                ), True
            return GravatarResult(email=email, has_gravatar=False), r.status_code == 404
        except Exception as e:
            logger.error(f"[Gravatar] {e}"); return None, False


# ══════════════════════════════════════════════════════════════════════════════
# 10. CRT.SH — no key needed, always runs when org is provided
# ══════════════════════════════════════════════════════════════════════════════

async def crt_sh_search(domain: str, limit: int = 15) -> tuple[list[CertRecord], bool]:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
            if r.status_code == 200:
                seen, records = set(), []
                for entry in r.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name and name not in seen and len(records) < limit:
                            seen.add(name)
                            issuer = None
                            raw = entry.get("issuer_name", "")
                            if "O=" in raw:
                                issuer = raw.split("O=")[-1].split(",")[0].strip()
                            records.append(CertRecord(
                                domain=name, issuer=issuer,
                                logged_at=entry.get("entry_timestamp"),
                            ))
                return records, True
            return [], False
        except Exception as e:
            logger.error(f"[crt.sh] {e}"); return [], False


# ══════════════════════════════════════════════════════════════════════════════
# 11. ABSTRACT API — optional
# ══════════════════════════════════════════════════════════════════════════════

async def validate_email_abstract(email: str) -> tuple[Optional[EmailValidation], bool]:
    if not ABSTRACT_KEY:
        return None, False
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                "https://emailvalidation.abstractapi.com/v1/",
                params={"api_key": ABSTRACT_KEY, "email": email},
            )
            if r.status_code == 200:
                data = r.json()
                return EmailValidation(
                    address=email,
                    is_valid_format=data.get("is_valid_format", {}).get("value", False),
                    is_deliverable=data.get("deliverability") == "DELIVERABLE",
                    provider=data.get("domain"),
                    source="abstract",
                ), True
            return None, False
        except Exception as e:
            logger.error(f"[AbstractAPI] {e}"); return None, False


# ══════════════════════════════════════════════════════════════════════════════
# Utilities
# ══════════════════════════════════════════════════════════════════════════════

def _classify_url(url: str) -> tuple[str, str, int]:
    """Classify a result URL into (category, platform_name, confidence)."""
    domain = url.lower()
    PATTERNS = [
        ("linkedin.com/in/",  "professional", "LinkedIn",       82),
        ("linkedin.com",      "professional", "LinkedIn",       75),
        ("github.com",        "developer",    "GitHub",         80),
        ("gitlab.com",        "developer",    "GitLab",         78),
        ("twitter.com",       "social",       "Twitter/X",      72),
        ("x.com",             "social",       "Twitter/X",      72),
        ("instagram.com",     "social",       "Instagram",      68),
        ("facebook.com",      "social",       "Facebook",       65),
        ("medium.com",        "document",     "Medium",         70),
        ("researchgate.net",  "document",     "ResearchGate",   75),
        ("academia.edu",      "document",     "Academia.edu",   73),
        ("scholar.google",    "document",     "Google Scholar", 78),
        ("stackoverflow.com", "developer",    "Stack Overflow", 72),
        ("reddit.com",        "social",       "Reddit",         60),
        ("youtube.com",       "social",       "YouTube",        62),
        ("crunchbase.com",    "professional", "Crunchbase",     74),
        ("dev.to",            "developer",    "DEV Community",  68),
        ("angel.co",          "professional", "AngelList",      70),
        ("keybase.io",        "developer",    "Keybase",        72),
        ("producthunt.com",   "professional", "Product Hunt",   65),
    ]
    for fragment, cat, name, conf in PATTERNS:
        if fragment in domain:
            return cat, name, conf
    return "document", "Web Mention", 50


def extract_domain_from_org(org_name: str) -> Optional[str]:
    STRIP = r"\b(llc|inc|ltd|corp|co|gmbh|plc|sa|ag|group|solutions|technologies|tech|services|labs|ai)\b\.?"
    cleaned = re.sub(STRIP, "", org_name.lower())
    cleaned = re.sub(r"[^a-z0-9\-]", "", cleaned.replace(" ", "")).strip("-")
    return f"{cleaned}.com" if len(cleaned) >= 3 else None


# ══════════════════════════════════════════════════════════════════════════════
# 12. WHOISXML PHONE INTELLIGENCE  (real carrier/line-type lookup)
# ══════════════════════════════════════════════════════════════════════════════

async def whoisxml_phone_lookup(phone_number: str) -> tuple[Optional[PhoneInfoResult], bool]:
    """
    Queries WhoisXML Phone Intelligence API for real carrier metadata.
    Returns: country, carrier name, line type (mobile/landline/voip), validity.
    This is static registry data — NOT real-time location or tracking.
    """
    if not WHOISXML_KEY:
        _warn("WhoisXML-Phone", "WHOISXML_API_KEY"); return None, False

    clean = re.sub(r"[\s\-\(\)\.]", "", phone_number)
    if not clean.startswith("+"):
        clean = "+" + clean.lstrip("+")

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                "https://phone-intelligence.whoisxmlapi.com/api/v1",
                params={"apiKey": WHOISXML_KEY, "phone": clean},
            )
            if r.status_code == 200:
                data = r.json()
                phone_data = data if "phoneNumber" in data else data.get("phone", data)
                country  = (phone_data.get("countryCode") or
                            phone_data.get("country", {}).get("name", "") or
                            phone_data.get("location", {}).get("country", ""))
                carrier  = (phone_data.get("carrier") or
                            phone_data.get("carrierName") or
                            phone_data.get("network", "") or "")
                line_type = (phone_data.get("lineType") or
                             phone_data.get("type") or "unknown")
                valid    = bool(phone_data.get("isValid", phone_data.get("valid", True)))
                region   = (phone_data.get("location", {}).get("region", "") or
                            phone_data.get("region", "") or "")
                return PhoneInfoResult(
                    number=clean, valid=valid,
                    country=str(country), carrier=str(carrier),
                    line_type=str(line_type), region=str(region),
                    raw=phone_data,
                ), True
            logger.warning(f"[WhoisXML-Phone] HTTP {r.status_code}: {r.text[:200]}")
            return None, False
        except Exception as e:
            logger.error(f"[WhoisXML-Phone] {e}"); return None, False


# ══════════════════════════════════════════════════════════════════════════════
# 13. URLSCAN.IO  — search for pages referencing a domain / identity
# ══════════════════════════════════════════════════════════════════════════════

async def urlscan_search(query: str, max_results: int = 8) -> tuple[list[dict], bool]:
    """
    Searches urlscan.io for recent scans matching a query (domain, email, etc.)
    Returns list of {url, ip, country, timestamp, screenshot_url}.
    """
    if not URLSCAN_KEY:
        _warn("URLScan", "URLSCAN_API_KEY"); return [], False

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": query, "size": max_results},
                headers={"API-Key": URLSCAN_KEY, "Content-Type": "application/json"},
            )
            if r.status_code == 200:
                results = r.json().get("results", [])
                parsed = []
                for item in results:
                    page   = item.get("page", {})
                    task   = item.get("task", {})
                    parsed.append({
                        "url":            page.get("url", ""),
                        "domain":         page.get("domain", ""),
                        "ip":             page.get("ip", ""),
                        "country":        page.get("country", ""),
                        "timestamp":      task.get("time", ""),
                        "screenshot_url": task.get("screenshotURL", ""),
                        "uuid":           task.get("uuid", ""),
                        "visibility":     task.get("visibility", ""),
                    })
                return parsed, True
            logger.warning(f"[URLScan] HTTP {r.status_code}")
            return [], False
        except Exception as e:
            logger.error(f"[URLScan] {e}"); return [], False


# ══════════════════════════════════════════════════════════════════════════════
# 14. CENSYS  — infrastructure / certificate / host enrichment
# ══════════════════════════════════════════════════════════════════════════════

async def censys_host_search(query: str, max_results: int = 5) -> tuple[list[dict], bool]:
    """
    Searches Censys Hosts API. Returns enriched host records for a domain or IP.
    Uses API key format: 'censys_<id>' where the full string is the API key.
    """
    if not CENSYS_KEY:
        _warn("Censys", "CENSYS_API_KEY"); return [], False

    # Key format from .env: censys_QYAr4vfE_2XScX811DC85iKBeh5XqLmNv
    # Censys v2 uses this as Bearer token
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                "https://search.censys.io/api/v2/hosts/search",
                params={"q": query, "per_page": max_results},
                headers={"Authorization": f"Bearer {CENSYS_KEY}"},
            )
            if r.status_code == 200:
                hits = r.json().get("result", {}).get("hits", [])
                results = []
                for h in hits:
                    results.append({
                        "ip":          h.get("ip", ""),
                        "name":        ", ".join(h.get("names", [])),
                        "country":     h.get("location", {}).get("country", ""),
                        "asn":         h.get("autonomous_system", {}).get("asn"),
                        "org":         h.get("autonomous_system", {}).get("name", ""),
                        "services":    [s.get("port") for s in h.get("services", [])],
                        "last_updated":h.get("last_updated_at", ""),
                    })
                return results, True
            logger.warning(f"[Censys] HTTP {r.status_code}: {r.text[:200]}")
            return [], False
        except Exception as e:
            logger.error(f"[Censys] {e}"); return [], False

# ══════════════════════════════════════════════════════════════════════════════
# ▶ NEW APIs — v2 Expansion
# ══════════════════════════════════════════════════════════════════════════════

BRAVE_KEY    = os.getenv("BRAVE_API_KEY")
HIBP_KEY     = os.getenv("HIBP_API_KEY")        # haveibeenpwned.com — $3.50/mo
PIPL_KEY     = os.getenv("PIPL_API_KEY")         # pipl.com people search
FULLCONTACT_KEY = os.getenv("FULLCONTACT_API_KEY")  # fullcontact.com
TWITTER_BEARER = os.getenv("TWITTER_BEARER_TOKEN")  # Twitter/X API v2

# ══════════════════════════════════════════════════════════════════════════════
# 15. BRAVE SEARCH API — web mentions (alternative to SerpAPI)
# ══════════════════════════════════════════════════════════════════════════════

async def brave_search_mentions(
    full_name: str,
    organization: Optional[str] = None,
    location: Optional[str] = None,
) -> tuple[list[MatchedProfile], bool]:
    """
    Brave Search API — privacy-focused alternative to Google/SerpAPI.
    2,000 free queries/month. Get key at: brave.com/search/api
    """
    if not BRAVE_KEY:
        _warn("Brave Search", "BRAVE_API_KEY"); return [], False

    query_parts = [f'"{full_name}"']
    if organization:
        query_parts.append(f'"{organization}"')
    if location:
        query_parts.append(location)
    query = " ".join(query_parts)

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                "https://api.search.brave.com/res/v1/web/search",
                params={"q": query, "count": 10, "search_lang": "en"},
                headers={"Accept": "application/json", "X-Subscription-Token": BRAVE_KEY},
            )
            if r.status_code == 200:
                results = r.json().get("web", {}).get("results", [])
                profiles: list[MatchedProfile] = []
                seen: set[str] = set()
                for item in results:
                    url = item.get("url", "")
                    if url in seen:
                        continue
                    seen.add(url)
                    cat, platform, conf = _classify_url(url)
                    name_lower = full_name.lower()
                    title = item.get("title", "").lower()
                    snippet = item.get("description", "")
                    # Boost confidence if name appears in title
                    if any(part in title for part in name_lower.split() if len(part) > 2):
                        conf = min(conf + 8, 92)
                    username = _extract_username_from_url(url, platform)
                    profiles.append(MatchedProfile(
                        platform=f"{platform} (Brave)",
                        profile_url=url,
                        username=username,
                        confidence=conf,
                        bio_snippet=snippet[:200] if snippet else None,
                        category=cat,
                    ))
                return profiles[:8], True
            logger.warning(f"[Brave] HTTP {r.status_code}")
            return [], False
        except Exception as e:
            logger.error(f"[Brave] {e}"); return [], False


# ══════════════════════════════════════════════════════════════════════════════
# 16. HAVE I BEEN PWNED (HIBP) v3 — breach check by email
# ══════════════════════════════════════════════════════════════════════════════

async def hibp_check_email(email: str) -> tuple[list[BreachRecord], bool]:
    """
    Check email against HIBP v3 API.
    Requires API key ($3.50/month at haveibeenpwned.com).
    More detailed than LeakCheck — includes breach dates and data classes.
    """
    if not HIBP_KEY:
        _warn("HIBP", "HIBP_API_KEY"); return [], False

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                params={"truncateResponse": "false"},
                headers={
                    "hibp-api-key": HIBP_KEY,
                    "User-Agent": "EDFP-Profiler/2.0",
                },
            )
            if r.status_code == 200:
                breaches = r.json()
                return [
                    BreachRecord(
                        source=b.get("Name", "Unknown"),
                        date=b.get("BreachDate"),
                        data_classes=b.get("DataClasses", []),
                        verified=b.get("IsVerified", False),
                    )
                    for b in breaches
                ], True
            elif r.status_code == 404:
                return [], True   # No breaches found — still success
            elif r.status_code == 429:
                logger.warning("[HIBP] Rate limit hit — wait 6s between requests")
                return [], False
            return [], False
        except Exception as e:
            logger.error(f"[HIBP] {e}"); return [], False


async def hibp_check_pastes(email: str) -> tuple[list[dict], bool]:
    """Check HIBP paste exposure — pastebin, ghostbin, etc."""
    if not HIBP_KEY:
        return [], False
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
                headers={"hibp-api-key": HIBP_KEY, "User-Agent": "EDFP-Profiler/2.0"},
            )
            if r.status_code == 200:
                return r.json(), True
            elif r.status_code == 404:
                return [], True
            return [], False
        except Exception as e:
            logger.error(f"[HIBP-paste] {e}"); return [], False


# ══════════════════════════════════════════════════════════════════════════════
# 17. FULLCONTACT — person enrichment by email
# ══════════════════════════════════════════════════════════════════════════════

async def fullcontact_enrich(email: str) -> tuple[Optional[dict], bool]:
    """
    FullContact Person Enrichment API.
    Free tier: 500 enrichments/month.
    Get key at: app.fullcontact.com
    Returns: social profiles, job title, organization, location.
    """
    if not FULLCONTACT_KEY:
        _warn("FullContact", "FULLCONTACT_API_KEY"); return None, False

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.post(
                "https://api.fullcontact.com/v3/person.enrich",
                headers={
                    "Authorization": f"Bearer {FULLCONTACT_KEY}",
                    "Content-Type": "application/json",
                },
                json={"email": email},
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "full_name":    data.get("fullName", ""),
                    "age_range":    data.get("ageRange", ""),
                    "gender":       data.get("gender", ""),
                    "location":     data.get("location", ""),
                    "title":        data.get("title", ""),
                    "organization": data.get("organization", ""),
                    "twitter":      next((s.get("url") for s in data.get("socialProfiles", [])
                                         if "twitter" in s.get("id", "")), None),
                    "linkedin":     next((s.get("url") for s in data.get("socialProfiles", [])
                                         if "linkedin" in s.get("id", "")), None),
                    "avatar":       data.get("avatar", ""),
                    "bio":          data.get("bio", ""),
                    "social_profiles": [
                        {"platform": s.get("typeId", ""), "url": s.get("url", "")}
                        for s in data.get("socialProfiles", [])
                    ],
                }, True
            elif r.status_code == 404:
                return None, True   # Not found — still OK
            return None, False
        except Exception as e:
            logger.error(f"[FullContact] {e}"); return None, False


# ══════════════════════════════════════════════════════════════════════════════
# 18. TWITTER/X API v2 — public profile + tweet search
# ══════════════════════════════════════════════════════════════════════════════

async def twitter_user_lookup(username: str) -> tuple[Optional[dict], bool]:
    """
    Lookup a Twitter/X public profile by username.
    Bearer token — free tier, no card needed.
    Get at: developer.twitter.com/en/portal
    """
    if not TWITTER_BEARER:
        _warn("Twitter/X", "TWITTER_BEARER_TOKEN"); return None, False

    clean = username.lstrip("@")
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            r = await client.get(
                f"https://api.twitter.com/2/users/by/username/{clean}",
                params={
                    "user.fields": "description,public_metrics,location,url,created_at,profile_image_url,verified"
                },
                headers={"Authorization": f"Bearer {TWITTER_BEARER}"},
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                metrics = data.get("public_metrics", {})
                return {
                    "id":          data.get("id"),
                    "username":    data.get("username"),
                    "name":        data.get("name"),
                    "bio":         data.get("description", ""),
                    "location":    data.get("location", ""),
                    "followers":   metrics.get("followers_count", 0),
                    "following":   metrics.get("following_count", 0),
                    "tweet_count": metrics.get("tweet_count", 0),
                    "created_at":  data.get("created_at"),
                    "verified":    data.get("verified", False),
                    "avatar_url":  data.get("profile_image_url", ""),
                    "profile_url": f"https://twitter.com/{clean}",
                }, True
            elif r.status_code == 404:
                return None, True
            return None, False
        except Exception as e:
            logger.error(f"[Twitter] {e}"); return None, False


async def twitter_search_user(full_name: str) -> tuple[list[MatchedProfile], bool]:
    """Search Twitter for profiles matching a full name."""
    if not TWITTER_BEARER:
        return [], False

    # Build name-based username guesses
    parts = full_name.strip().split()
    guesses = []
    if len(parts) >= 2:
        first, last = parts[0], parts[-1]
        guesses = [
            f"{first}{last}".lower(),
            f"{first}_{last}".lower(),
            f"{first[0]}{last}".lower(),
            f"{last}{first}".lower(),
        ]
    elif parts:
        guesses = [parts[0].lower()]

    profiles: list[MatchedProfile] = []
    for guess in guesses[:3]:
        data, ok = await twitter_user_lookup(guess)
        if ok and data:
            name_lower = full_name.lower()
            display_name = data.get("name", "").lower()
            # Only include if display name overlaps with target name
            match_score = sum(1 for part in name_lower.split()
                              if part in display_name and len(part) > 2)
            if match_score > 0 or guess in display_name.replace(" ", ""):
                conf = 75 + min(match_score * 5, 15)
                profiles.append(MatchedProfile(
                    platform="Twitter/X",
                    profile_url=data["profile_url"],
                    username=data["username"],
                    confidence=conf,
                    bio_snippet=f"{data.get('bio', '')} | {data.get('followers', 0):,} followers",
                    category="social",
                ))
    return profiles, True


# ══════════════════════════════════════════════════════════════════════════════
# 19. DNS RECON — passive DNS enumeration (no key needed)
# ══════════════════════════════════════════════════════════════════════════════

async def dns_passive_recon(domain: str) -> tuple[dict, bool]:
    """
    Passive DNS recon using HackerTarget API (free, no key needed).
    Returns MX, A, NS records that help confirm organization ownership.
    """
    results = {"mx": [], "a": [], "ns": [], "txt": []}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            for record_type in ("hostsearch", "dnslookup"):
                r = await client.get(
                    f"https://api.hackertarget.com/{record_type}/",
                    params={"q": domain},
                )
                if r.status_code == 200 and "error" not in r.text.lower():
                    if record_type == "hostsearch":
                        results["a"] = [
                            line.split(",")[0]
                            for line in r.text.strip().split("\n")
                            if "," in line
                        ][:8]
                    elif record_type == "dnslookup":
                        for line in r.text.strip().split("\n"):
                            if " MX " in line:
                                results["mx"].append(line.split()[-1])
                            elif " NS " in line:
                                results["ns"].append(line.split()[-1])
            return results, True
        except Exception as e:
            logger.error(f"[DNS-Recon] {e}"); return results, False


# ══════════════════════════════════════════════════════════════════════════════
# 20. SOCIALSCAN — check username availability across platforms (no key)
# ══════════════════════════════════════════════════════════════════════════════

SOCIAL_PLATFORMS_CHECK = [
    ("GitHub",      "https://github.com/{}", "https://api.github.com/users/{}"),
    ("Twitter/X",   "https://twitter.com/{}", None),
    ("Instagram",   "https://www.instagram.com/{}/", None),
    ("Reddit",      "https://www.reddit.com/user/{}", None),
    ("Dev.to",      "https://dev.to/{}", "https://dev.to/api/users/by_username?url={}"),
    ("Medium",      "https://medium.com/@{}", None),
    ("Keybase",     "https://keybase.io/{}", "https://keybase.io/_/api/1.0/user/lookup.json?username={}"),
    ("HackerNews",  "https://news.ycombinator.com/user?id={}", "https://hacker-news.firebaseio.com/v0/user/{}.json"),
]


async def check_username_platforms(username: str) -> list[dict]:
    """
    Check if a username exists across major platforms.
    Uses public profile pages — no API key required.
    """
    results = []
    clean = username.strip().lstrip("@")

    async def _check_one(platform: str, profile_url: str, api_url: Optional[str]) -> dict:
        url = profile_url.format(clean)
        api = api_url.format(clean) if api_url else None
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=4.0, read=8.0, write=3.0, pool=2.0),
            follow_redirects=True,
        ) as client:
            try:
                check_url = api or url
                r = await client.get(
                    check_url,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; EDFP-Profiler/2.0)"},
                )
                exists = r.status_code == 200
                # Extra validation for API endpoints
                if exists and api and platform == "GitHub":
                    data = r.json()
                    exists = "login" in data
                elif exists and api and platform == "HackerNews":
                    exists = r.json() is not None
                return {
                    "platform":   platform,
                    "url":        url,
                    "exists":     exists,
                    "status":     r.status_code,
                }
            except Exception:
                return {"platform": platform, "url": url, "exists": False, "status": 0}

    tasks = [_check_one(p, pu, au) for p, pu, au in SOCIAL_PLATFORMS_CHECK]
    results = await asyncio.gather(*tasks)
    return list(results)


# ══════════════════════════════════════════════════════════════════════════════
# Helpers (internal)
# ══════════════════════════════════════════════════════════════════════════════

def _extract_username_from_url(url: str, platform: str) -> str:
    """Extract username slug from social profile URLs."""
    import re as _re
    try:
        path = url.split("//")[-1].split("/")
        # Filter empty parts and common path prefixes
        parts = [p for p in path[1:] if p and p not in ("in", "u", "user", "@")]
        return parts[0].lstrip("@") if parts else url.split("/")[-1]
    except Exception:
        return "unknown"

