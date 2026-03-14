"""entity_resolver.py — v5 FINAL. Real data only."""

from app.models.schemas import (
    BreachRecord, EmailPattern, EmailRepResult,
    ExposurePoint, IntelXResult, MatchedProfile, ShodanResult,
)
from app.utils.scoring import RISK_WEIGHTS


def resolve_exposure_points(
    profiles:         list[MatchedProfile],
    emails:           list[EmailPattern],
    breaches:         list[BreachRecord],
    has_org:          bool,
    shodan_results:   list[ShodanResult]   | None = None,
    intelx_results:   list[IntelXResult]   | None = None,
    emailrep_results: list[EmailRepResult] | None = None,
) -> list[ExposurePoint]:

    shodan_results   = shodan_results   or []
    intelx_results   = intelx_results   or []
    emailrep_results = emailrep_results or []

    # Breach exposure — most serious, real confirmed data
    breach_score = min(100, len(breaches) * 25)
    if breaches:
        names = ", ".join(b.source for b in breaches[:4])
        if len(breaches) > 4: names += f" +{len(breaches)-4} more"
        breach_desc = f"{len(breaches)} breach record(s): {names}"
    else:
        breach_desc = "No confirmed breaches found"

    # Email exposure — real emails only, boosted by emailrep
    real_emails = emails  # all emails are real in v5 (no simulation)
    top_conf = max((e.confidence for e in real_emails), default=0)
    rep_penalty = sum(20 for r in emailrep_results if r.suspicious)
    email_score = min(100, top_conf + rep_penalty)
    email_desc = (
        f"{len(real_emails)} address(es) found · max confidence {top_conf}%"
        + (f" · {sum(1 for r in emailrep_results if r.suspicious)} flagged suspicious" if emailrep_results else "")
    )

    # Developer presence — real GitHub/dev profiles
    dev_profiles = [p for p in profiles if p.category == "developer"]
    dev_score = min(100, len(dev_profiles) * 35)
    dev_desc = (
        f"{len(dev_profiles)} dev profile(s): " + ", ".join(p.platform for p in dev_profiles[:3])
        if dev_profiles else "No developer profiles confirmed"
    )

    # Web presence — real SerpApi results
    web_profiles = [p for p in profiles if p.category in ("document", "professional", "social")]
    web_score = min(100, len(web_profiles) * 18)
    web_desc = (
        f"{len(web_profiles)} web mention(s): " + ", ".join(dict.fromkeys(p.platform for p in web_profiles[:5]))
        if web_profiles else "No public web presence confirmed"
    )

    # Infrastructure
    vuln_count  = sum(len(s.vulns) for s in shodan_results)
    infra_score = min(100, len(shodan_results) * 22 + vuln_count * 15)
    if shodan_results:
        hosts = ", ".join((s.hostnames[0] if s.hostnames else s.ip) for s in shodan_results[:2])
        infra_desc = f"{len(shodan_results)} exposed host(s)" + (f" · {vuln_count} CVE(s)" if vuln_count else "") + f" · {hosts}"
    else:
        infra_desc = "No Shodan exposure found"

    # Dark web / IntelX
    dark_score = min(100, len(intelx_results) * 28)
    dark_desc = (
        f"{len(intelx_results)} IntelX record(s) in buckets: " + ", ".join(dict.fromkeys(r.bucket for r in intelx_results[:4]))
        if intelx_results else "No IntelX records found"
    )

    # Org linkage
    org_score = 60 if has_org else 0
    org_desc  = "Organization provided — enables domain/infra lookups" if has_org else "No organization specified"

    return [
        ExposurePoint(factor="breach_exposure",       weight=RISK_WEIGHTS["breach_exposure"],       score=breach_score, description=breach_desc),
        ExposurePoint(factor="email_exposure",         weight=RISK_WEIGHTS["email_exposure"],         score=email_score,  description=email_desc),
        ExposurePoint(factor="developer_presence",     weight=RISK_WEIGHTS["developer_presence"],     score=dev_score,    description=dev_desc),
        ExposurePoint(factor="web_presence",           weight=RISK_WEIGHTS["web_presence"],           score=web_score,    description=web_desc),
        ExposurePoint(factor="infrastructure_exposure",weight=RISK_WEIGHTS["infrastructure_exposure"],score=infra_score,  description=infra_desc),
        ExposurePoint(factor="dark_web_exposure",      weight=RISK_WEIGHTS["dark_web_exposure"],      score=dark_score,   description=dark_desc),
        ExposurePoint(factor="org_linkage",            weight=RISK_WEIGHTS["org_linkage"],            score=org_score,    description=org_desc),
    ]
