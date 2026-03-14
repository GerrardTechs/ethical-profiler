"""
scan.py — v7
Real API scanning + WebSocket real-time progress + DB persistence.

Progress events are broadcast per stage so the frontend can show
live updates as each API completes — no more "black box" waiting.
"""

import asyncio
import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Request

from app.models.schemas import (
    APISourceStatus, DiscoveredContact, EmailPattern,
    MatchedProfile, ScanRequest, ScanResult,
    URLScanResult, CensysHostResult, PhoneAnalysisResult,
)
from app.services.api_clients import (
    check_breaches_leakcheck, check_gravatar, crt_sh_search,
    emailrep_lookup, extract_domain_from_org, github_search_users,
    hunter_domain_search, hunter_find_email, intelx_search,
    serpapi_search_mentions, shodan_org_search, validate_email_abstract,
    whoisxml_phone_lookup, urlscan_search, censys_host_search,
    # New v2 APIs
    brave_search_mentions, hibp_check_email, hibp_check_pastes,
    fullcontact_enrich, twitter_search_user, dns_passive_recon,
    check_username_platforms,
)
from app.services.phone_osint import simulate_phone_analysis
from app.services.osint_engine import extract_emails_from_text, extract_phones_from_text
from app.services.entity_resolver import resolve_exposure_points
from app.services.risk_engine import assess_risk, build_graph
from app.utils.scoring import calculate_confidence_score
from app.db.database import save_scan, log_api_call
from app.middleware.auth import get_current_user_optional

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["scan"])

_TOTAL_STAGES = 12  # expanded for new APIs


def _classify_url_safe(url: str) -> tuple[str, str, int]:
    """Safe wrapper around api_clients._classify_url."""
    try:
        from app.services.api_clients import _classify_url
        return _classify_url(url)
    except Exception:
        return "document", "Web", 50


def _scan_id(name: str) -> str:
    return hashlib.sha256(
        f"{name}{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:12].upper()


async def _noop(v):
    return v


async def _emit(request: Request, scan_id: str, stage: int, label: str,
                status: str = "running", detail: str = ""):
    try:
        mgr = request.app.state.ws_manager
        await mgr.broadcast(scan_id, {
            "type":    "progress",
            "scan_id": scan_id,
            "stage":   stage,
            "total":   _TOTAL_STAGES,
            "pct":     round(stage / _TOTAL_STAGES * 100),
            "label":   label,
            "status":  status,
            "detail":  detail,
            "ts":      datetime.now(timezone.utc).isoformat(),
        })
    except Exception:
        pass


async def _timed_call(coro, api_name: str, scan_id: Optional[str] = None,
                      user_id: Optional[int] = None):
    """Wrap an API call and log its latency + success to api_usage_log."""
    t0 = time.monotonic()
    try:
        result = await coro
        ok = result[1] if isinstance(result, tuple) else bool(result)
        await log_api_call(api_name, bool(ok), int((time.monotonic()-t0)*1000),
                           scan_id=scan_id, user_id=user_id)
        return result
    except Exception as e:
        await log_api_call(api_name, False, int((time.monotonic()-t0)*1000),
                           scan_id=scan_id, user_id=user_id, error_msg=str(e))
        raise


@router.post("/scan", response_model=ScanResult)
async def run_scan(payload: ScanRequest, request: Request) -> ScanResult:
    scan_start = time.monotonic()
    scan_id    = _scan_id(payload.full_name)

    # Get user from session (optional — scan works without login too)
    current_user = await get_current_user_optional(request)
    user_id = current_user["id"] if current_user else None

    status     = APISourceStatus()
    org_domain = extract_domain_from_org(payload.organization) if payload.organization else None

    # ── Stage 1: Core APIs concurrent ─────────────────────────────────────
    await _emit(request, scan_id, 1, "Querying GitHub, SerpAPI, Brave, Hunter, Shodan, IntelX, Twitter…")

    (
        (gh_profiles,    gh_ok),
        (serp_profiles,  serp_ok),
        (brave_profiles, brave_ok),
        (hunter_email,   h_ok),
        (domain_emails,  hd_ok),
        (shodan_results, sh_ok),
        (intelx_results, ix_ok),
        (twitter_profiles, tw_ok),
    ) = await asyncio.gather(
        _timed_call(github_search_users(payload.full_name, payload.username), "github", scan_id, user_id),
        _timed_call(serpapi_search_mentions(payload.full_name, payload.organization, payload.location), "serpapi", scan_id, user_id),
        _timed_call(brave_search_mentions(payload.full_name, payload.organization, payload.location), "brave", scan_id, user_id),
        _timed_call(hunter_find_email(payload.full_name, org_domain), "hunter_email", scan_id, user_id) if org_domain else _noop((None, False)),
        _timed_call(hunter_domain_search(org_domain), "hunter_domain", scan_id, user_id) if org_domain else _noop(([], False)),
        _timed_call(shodan_org_search(payload.organization), "shodan", scan_id, user_id) if payload.organization else _noop(([], False)),
        _timed_call(intelx_search(payload.full_name), "intelx", scan_id, user_id),
        _timed_call(twitter_search_user(payload.full_name), "twitter", scan_id, user_id),
    )

    status.github  = gh_ok   and bool(gh_profiles)
    status.serpapi = serp_ok and bool(serp_profiles)
    status.hunter  = h_ok    or hd_ok
    status.shodan  = sh_ok   and bool(shodan_results)
    status.intelx  = ix_ok   and bool(intelx_results)

    found_profiles = len(gh_profiles) + len(serp_profiles) + len(brave_profiles) + len(twitter_profiles)
    await _emit(request, scan_id, 1, "Core APIs complete",
                status="done",
                detail=f"{found_profiles} profiles · GitHub={'✓' if gh_ok else '○'} Serp={'✓' if serp_ok else '○'} Brave={'✓' if brave_ok else '○'} X={'✓' if tw_ok else '○'}")

    all_profiles: list[MatchedProfile] = gh_profiles + serp_profiles + brave_profiles + twitter_profiles

    # ── Stage 2: Email assembly ────────────────────────────────────────────
    await _emit(request, scan_id, 2, "Assembling email addresses…")

    all_emails: list[EmailPattern] = []
    seen_addrs: set[str] = set()

    def _add_email(addr: str, confidence: int, src: str):
        addr = addr.lower().strip()
        if addr and addr not in seen_addrs and "@" in addr:
            all_emails.append(EmailPattern(address=addr, confidence=confidence, pattern_type=src))
            seen_addrs.add(addr)

    if payload.email:
        _add_email(payload.email, 97, "direct input")
    if hunter_email:
        _add_email(hunter_email.address,
                   90 if hunter_email.is_deliverable else 74,
                   "hunter.io verified")
    for de in (domain_emails or []):
        _add_email(de.address, de.confidence, de.pattern_type)

    # Mine emails from ALL profile snippets (GitHub bios include public emails)
    all_snippets = " ".join((p.bio_snippet or "") for p in serp_profiles + gh_profiles)
    for em in extract_emails_from_text(all_snippets):
        _add_email(em, 78, "github/web profile · mined")
    for ix in intelx_results:
        for em in extract_emails_from_text(ix.name):
            _add_email(em, 75, f"intelx · {ix.bucket}")

    # Mine phones
    phone_texts    = all_snippets + " " + " ".join(ix.name for ix in intelx_results)
    raw_phones     = extract_phones_from_text(phone_texts)
    # Include user-provided phone if given
    if payload.phone:
        raw_phones = [payload.phone] + raw_phones
    discovered_phones: list[str] = list(dict.fromkeys(raw_phones))

    await _emit(request, scan_id, 2, "Email & phone mining complete",
                status="done",
                detail=f"{len(all_emails)} emails · {len(discovered_phones)} phone(s) mined from snippets")

    # ── Stage 3: Breach + Email enrichment (LeakCheck + HIBP + FullContact) ──
    await _emit(request, scan_id, 3, f"Checking breaches (LeakCheck + HIBP) & enriching {min(len(all_emails),3)} email(s)…")

    top_addrs = [e.address for e in all_emails[:4]]

    # Run LeakCheck + HIBP + Gravatar + AbstractAPI + EmailRep + FullContact concurrently
    per_email_results = await asyncio.gather(*[
        asyncio.gather(
            _timed_call(check_breaches_leakcheck(addr),      "leakcheck",  scan_id, user_id),
            _timed_call(hibp_check_email(addr),              "hibp",       scan_id, user_id),
            _timed_call(check_gravatar(addr),                "gravatar",   scan_id, user_id),
            _timed_call(validate_email_abstract(addr),       "abstract",   scan_id, user_id),
            _timed_call(emailrep_lookup(addr),               "emailrep",   scan_id, user_id),
            _timed_call(fullcontact_enrich(addr),            "fullcontact",scan_id, user_id),
        )
        for addr in top_addrs
    ]) if top_addrs else []

    all_breaches, all_gravatar, all_validations, all_emailrep = [], [], [], []
    fullcontact_data: list[dict] = []

    for (lc_res, hibp_res, grav_res, valid_res, rep_res, fc_res) in per_email_results:
        # Merge LeakCheck + HIBP breaches
        lc_breaches,  b_ok  = lc_res
        hibp_breaches, h_ok = hibp_res
        gravatar,   g_ok    = grav_res
        validation, v_ok    = valid_res
        emailrep,   r_ok    = rep_res
        fc_data,    fc_ok   = fc_res

        # Combine and deduplicate breaches
        seen_breach = {b.source for b in all_breaches}
        for b in (lc_breaches + hibp_breaches):
            if b.source not in seen_breach:
                all_breaches.append(b)
                seen_breach.add(b.source)

        if gravatar:    all_gravatar.append(gravatar)
        if validation:  all_validations.append(validation)
        if emailrep:    all_emailrep.append(emailrep)
        if fc_data:     fullcontact_data.append(fc_data)

        if b_ok:  status.leakcheck      = True
        if g_ok:  status.gravatar        = True
        if v_ok:  status.abstract_email  = True
        if r_ok:  status.emailrep        = True

    # Enrich profile list with FullContact social data
    for fc in fullcontact_data:
        for sp in fc.get("social_profiles", []):
            if sp.get("url") and sp.get("platform"):
                cat, plat, conf = _classify_url_safe(sp["url"])
                if not any(p.profile_url == sp["url"] for p in all_profiles):
                    all_profiles.append(MatchedProfile(
                        platform=f"{plat} (FullContact)",
                        profile_url=sp["url"],
                        username=sp.get("platform", ""),
                        confidence=conf,
                        bio_snippet=fc.get("bio", "")[:200] if fc.get("bio") else None,
                        category=cat,
                    ))

    await _emit(request, scan_id, 3, "Breach check complete",
                status="done",
                detail=f"{len(all_breaches)} breach(es) · LeakCheck={'✓' if status.leakcheck else '○'} HIBP={'✓' if any(b.verified for b in all_breaches) else '○'} FC={len(fullcontact_data)} enriched")

    # ── Stage 4: crt.sh + URLScan + Censys concurrent ─────────────────────
    await _emit(request, scan_id, 4, "Querying crt.sh, URLScan.io, Censys…")

    urlscan_query = payload.email or payload.full_name
    censys_query  = org_domain or payload.full_name

    results_5 = await asyncio.gather(
        _timed_call(crt_sh_search(org_domain), "crt_sh", scan_id, user_id) if org_domain else _noop(([], False)),
        _timed_call(urlscan_search(urlscan_query), "urlscan", scan_id, user_id),
        _timed_call(censys_host_search(censys_query), "censys", scan_id, user_id),
    )
    (cert_records, crt_ok)   = results_5[0]
    (urlscan_raw,  us_ok)    = results_5[1]
    (censys_raw,   cs_ok)    = results_5[2]

    status.crt_sh  = crt_ok
    status.urlscan = us_ok and bool(urlscan_raw)
    status.censys  = cs_ok and bool(censys_raw)

    urlscan_objs = [URLScanResult(**r) for r in urlscan_raw]
    censys_objs  = [CensysHostResult(**r) for r in censys_raw]

    await _emit(request, scan_id, 4, "Infrastructure recon complete",
                status="done",
                detail=f"{len(cert_records)} certs · {len(urlscan_objs)} URLScan · {len(censys_objs)} Censys hosts")

    # ── Stage 5: Phone enrichment ──────────────────────────────────────────
    phone_analyses: list[PhoneAnalysisResult] = []
    if discovered_phones:
        await _emit(request, scan_id, 5, f"Enriching {min(len(discovered_phones),5)} phone number(s) via WhoisXML…")
        for raw_phone in discovered_phones[:5]:
            wx_result, wx_ok = await whoisxml_phone_lookup(raw_phone)
            meta = simulate_phone_analysis(raw_phone)
            if wx_ok and wx_result:
                status.whoisxml = True
                phone_analyses.append(PhoneAnalysisResult(
                    number_raw=raw_phone, number_e164=wx_result.number,
                    valid=wx_result.valid,
                    country=wx_result.country or meta.get("country", ""),
                    carrier=wx_result.carrier or meta.get("operator_name", ""),
                    line_type=wx_result.line_type or meta.get("line_type", ""),
                    region=wx_result.region or meta.get("region", ""),
                    country_code=meta.get("country_code", ""),
                    iso_code=meta.get("iso_code", ""),
                    tz_estimate=meta.get("timezone_estimate", ""),
                    operator_est=meta.get("operator_name", ""),
                    network_type=meta.get("network_type", ""),
                    source="whoisxml", confidence=88,
                    disclaimer=(
                        "Carrier data sourced from WhoisXML Phone Intelligence registry. "
                        "Country/carrier reflect number registration metadata, not current location."
                    ),
                ))
            elif not meta.get("error"):
                phone_analyses.append(PhoneAnalysisResult(
                    number_raw=raw_phone, number_e164=meta.get("normalized", raw_phone),
                    valid=True,
                    country=meta.get("country", ""), carrier=meta.get("operator_name", ""),
                    line_type=meta.get("line_type", ""), region=meta.get("region", ""),
                    country_code=meta.get("country_code", ""), iso_code=meta.get("iso_code", ""),
                    tz_estimate=meta.get("timezone_estimate", ""),
                    operator_est=meta.get("operator_name", ""),
                    network_type=meta.get("network_type", ""),
                    source="e164_metadata", confidence=meta.get("confidence_score", 50),
                    disclaimer=(
                        "Carrier data estimated from ITU-T E.164 numbering plan metadata. "
                        "No real-time network query performed."
                    ),
                ))
        await _emit(request, scan_id, 5, "Phone enrichment complete",
                    status="done",
                    detail=f"{len(phone_analyses)} number(s) enriched · WhoisXML={'✓' if status.whoisxml else '≈ E.164'}")
    else:
        await _emit(request, scan_id, 5, "Phone enrichment skipped — no numbers found",
                    status="skipped")

    # ── Stage 6: Scoring ───────────────────────────────────────────────────
    await _emit(request, scan_id, 6, "Calculating exposure score…")

    confidence = calculate_confidence_score(
        real_profile_count=len(all_profiles),
        real_email_count=len(all_emails),
        breach_count=len(all_breaches),
        github_found=bool(gh_profiles),
        serp_found=bool(serp_profiles),
        intelx_found=bool(intelx_results),
        user_provided_email=bool(payload.email),
    )
    exposure_points = resolve_exposure_points(
        profiles=all_profiles, emails=all_emails,
        breaches=all_breaches, has_org=bool(payload.organization),
        shodan_results=shodan_results, intelx_results=intelx_results,
        emailrep_results=all_emailrep,
    )
    exposure_score, risk_level = assess_risk(exposure_points)

    await _emit(request, scan_id, 6, "Scoring complete",
                status="done",
                detail=f"Exposure: {exposure_score}/100 · Risk: {risk_level.value} · Confidence: {confidence}%")

    # ── Stage 7: Identity graph ────────────────────────────────────────────
    await _emit(request, scan_id, 7, "Building identity relationship graph…")

    graph_nodes, graph_edges = build_graph(
        target_name=payload.full_name, profiles=all_profiles,
        emails=all_emails, breaches=all_breaches,
        cert_records=cert_records, shodan_results=shodan_results,
        intelx_results=intelx_results,
    )

    await _emit(request, scan_id, 7, "Graph complete",
                status="done",
                detail=f"{len(graph_nodes)} nodes · {len(graph_edges)} edges")

    # ── Stage 8: Contacts list ─────────────────────────────────────────────
    await _emit(request, scan_id, 8, "Assembling discovered contacts…")

    contacts: list[DiscoveredContact] = []
    for em in all_emails:
        contacts.append(DiscoveredContact(
            value=em.address, contact_type="email",
            source=em.pattern_type, confidence=em.confidence,
        ))
    for phone in discovered_phones:
        contacts.append(DiscoveredContact(
            value=phone, contact_type="phone",
            source="web snippet · mined", confidence=52,
        ))

    # Count actual sources queried (not result items — those can be 0 even on success)
    sources_checked = sum([
        1,                           # GitHub
        1,                           # SerpApi
        1 if org_domain else 0,      # Hunter email
        1 if org_domain else 0,      # Hunter domain
        1 if payload.organization else 0,  # Shodan
        1,                           # IntelX
        1,                           # LeakCheck (per email batch)
        1,                           # Gravatar
        1,                           # EmailRep
        1 if org_domain else 0,      # crt.sh
        1,                           # URLScan
        1,                           # Censys
        1,                           # HIBP
        1,                           # FullContact
        1 if payload.username else 0,# Twitter
    ])

    await _emit(request, scan_id, 8, "Contact assembly complete",
                status="done",
                detail=f"{len(contacts)} total contacts ({len(all_emails)} email · {len(discovered_phones)} phone)")

    # ── Stage 9 (new): DNS passive recon ──────────────────────────────────
    dns_data: dict = {}
    if org_domain:
        await _emit(request, scan_id, 9, f"Running passive DNS recon for {org_domain}…")
        dns_data, dns_ok = await _timed_call(
            dns_passive_recon(org_domain), "dns_recon", scan_id, user_id
        )
        mx_count = len(dns_data.get("mx", []))
        a_count  = len(dns_data.get("a", []))
        await _emit(request, scan_id, 9, "DNS recon complete",
                    status="done",
                    detail=f"{a_count} hosts · {mx_count} MX records discovered")
    else:
        await _emit(request, scan_id, 9, "DNS recon skipped — no org domain", status="skipped")

    # ── Stage 10: Persist to DB ────────────────────────────────────────────
    await _emit(request, scan_id, 10, "Saving to history database…")

    result = ScanResult(
        full_name=payload.full_name, location=payload.location,
        organization=payload.organization,
        matched_profiles=all_profiles, probable_emails=all_emails,
        discovered_contacts=contacts,
        exposure_points=exposure_points, confidence_score=confidence,
        exposure_score=exposure_score, risk_level=risk_level,
        breaches=all_breaches, email_validations=all_validations,
        gravatar_results=all_gravatar, cert_records=cert_records[:12],
        shodan_results=shodan_results, intelx_results=intelx_results,
        emailrep_results=all_emailrep,
        urlscan_results=urlscan_objs, censys_results=censys_objs,
        phone_analyses=phone_analyses,
        graph_nodes=graph_nodes, graph_edges=graph_edges,
        scan_id=scan_id, timestamp=datetime.now(timezone.utc).isoformat(),
        sources_checked=sources_checked, api_sources=status,
    )
    duration_ms = int((time.monotonic() - scan_start) * 1000)
    saved = await save_scan(
        result.model_dump(mode="json"),
        user_id=user_id,
        duration_ms=duration_ms,
    )
    await _emit(request, scan_id, 10, "Database save complete",
                status="done",
                detail=f"Scan ID {scan_id} {'saved' if saved else 'save failed'} · {duration_ms}ms")

    # ── Stage 11: Done ─────────────────────────────────────────────────────
    await _emit(request, scan_id, 11, "Scan complete — loading dashboard…",
                status="done",
                detail=f"{sources_checked} sources checked · {len(all_profiles)} profiles · {len(all_emails)} emails · {len(all_breaches)} breaches · {duration_ms}ms")

    logger.info(
        f"[{scan_id}] '{payload.full_name}' score={exposure_score} "
        f"risk={risk_level.value} profiles={len(all_profiles)} "
        f"emails={len(all_emails)} phones={len(discovered_phones)} "
        f"breaches={len(all_breaches)}"
    )
    return result