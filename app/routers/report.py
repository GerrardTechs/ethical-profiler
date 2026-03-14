"""
report.py — PDF export + defensive self-scan guidance endpoints.
"""

import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, HTMLResponse
import io
from pydantic import BaseModel
from typing import Optional, List

from app.db.database import get_scan_detail
from app.services.report_generator import generate_pdf_report

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/report", tags=["report"])


# ── PDF Export ────────────────────────────────────────────────────────────────

@router.get("/pdf/{scan_id}")
async def export_pdf(scan_id: str):
    """Generate and stream a PDF intelligence report for a given scan_id."""
    scan_data = await get_scan_detail(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found in history.")

    pdf_bytes = generate_pdf_report(scan_data)
    if not pdf_bytes:
        raise HTTPException(
            status_code=500,
            detail="PDF generation failed. Ensure 'reportlab' is installed: pip install reportlab"
        )

    filename = f"osint_report_{scan_id}_{scan_data.get('full_name', 'target').replace(' ', '_')}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Defensive / Privacy Guidance ─────────────────────────────────────────────

REMOVAL_GUIDES: dict[str, dict] = {
    "GitHub":        {"url": "https://github.com/settings/profile", "steps": ["Go to Settings → Profile", "Remove sensitive info from bio/README", "Make private repos: Settings → Danger Zone"]},
    "LinkedIn":      {"url": "https://linkedin.com/settings", "steps": ["Settings → Visibility → Profile visibility", "Turn off 'Share profile updates'", "Settings → Data privacy → Manage your data and activity"]},
    "Twitter/X":     {"url": "https://twitter.com/settings/account", "steps": ["Settings → Privacy → Protect your posts", "Remove phone number: Settings → Your account → Phone", "Deactivate: Settings → Your account → Deactivate"]},
    "Instagram":     {"url": "https://instagram.com/accounts/privacy_and_security", "steps": ["Settings → Account Privacy → set to Private", "Remove phone/email from bio", "Delete old location-tagged posts"]},
    "Facebook":      {"url": "https://facebook.com/settings/?tab=privacy", "steps": ["Settings → Privacy → 'Who can see your future posts' → Friends", "Settings → Personal info → Remove phone/email", "Activity Log → Delete old public posts"]},
    "Reddit":        {"url": "https://www.reddit.com/settings/privacy", "steps": ["Settings → Privacy → Make profile not visible to search engines", "Consider deleting old posts/comments with third-party tools"]},
    "Google":        {"url": "https://myaccount.google.com/data-and-privacy", "steps": ["myaccount.google.com → Data & privacy → Delete activity", "Request removal of personal info from Search: support.google.com/websearch/troubleshooter/9685456", "Check 'Results about you' feature"]},
    "HaveIBeenPwned":{"url": "https://haveibeenpwned.com/", "steps": ["Check if email appeared in breach", "Change passwords for any breached services", "Enable 2FA on all accounts", "Use unique passwords per service (password manager)"]},
    "Shodan":        {"url": "https://www.shodan.io/", "steps": ["If your IP/device appears: firewall exposed ports", "Contact your ISP to change public IP", "Submit removal request: shodan.io/remove"]},
    "Spokeo":        {"url": "https://www.spokeo.com/optout", "steps": ["Go to spokeo.com/optout", "Search for your listing", "Submit opt-out request with email verification"]},
    "WhitePages":    {"url": "https://www.whitepages.com/suppression_requests", "steps": ["Go to whitepages.com/suppression_requests", "Find your listing and submit removal"]},
    "Intelius":      {"url": "https://www.intelius.com/opt-out/", "steps": ["Visit intelius.com/opt-out", "Search for your profile and request removal"]},
    "BeenVerified":  {"url": "https://www.beenverified.com/app/optout/search", "steps": ["Visit beenverified.com/app/optout/search", "Enter your name and state", "Request opt-out via email"]},
    "PeopleFinder":  {"url": "https://www.peoplefinder.com/optout.php", "steps": ["Visit peoplefinder.com/optout.php", "Search for your record and submit removal"]},
    "Pipl":          {"url": "https://pipl.com/personal-information-removal-request", "steps": ["Submit removal at pipl.com/personal-information-removal-request"]},
    "Kaskus":        {"url": "https://www.kaskus.co.id/settings", "steps": ["Settings → Privacy → Ubah visibilitas profil", "Hapus nomor telepon dari profil", "Pertimbangkan menutup akun jika tidak aktif"]},
    "Tokopedia":     {"url": "https://www.tokopedia.com/account/setting/privacy", "steps": ["Pengaturan → Privasi → Sembunyikan info kontak", "Hapus nomor rekening yang tidak perlu"]},
}

GENERAL_PRIVACY_TIPS = [
    {"category": "Passwords", "tip": "Use a password manager (Bitwarden, 1Password) and unique passwords per site.", "priority": "critical"},
    {"category": "2FA",       "tip": "Enable two-factor authentication on all accounts, preferably with an authenticator app, not SMS.", "priority": "critical"},
    {"category": "Email",     "tip": "Use email aliases (SimpleLogin, AnonAddy) to prevent your real address from being harvested.", "priority": "high"},
    {"category": "Phone",     "tip": "Do not share your primary phone number publicly. Use a secondary SIM or VoIP number for sign-ups.", "priority": "high"},
    {"category": "Search",    "tip": "Regularly Google yourself (and use DuckDuckGo) to audit what's public about you.", "priority": "medium"},
    {"category": "Social",    "tip": "Audit your social media privacy settings quarterly — platforms change defaults silently.", "priority": "medium"},
    {"category": "Location",  "tip": "Remove EXIF metadata from photos before posting. Disable location tagging in camera apps.", "priority": "medium"},
    {"category": "Breaches",  "tip": "Monitor HaveIBeenPwned.com and set up email notifications for new breaches.", "priority": "high"},
    {"category": "Browsers",  "tip": "Use browser privacy settings or Firefox + uBlock Origin. Consider a VPN for sensitive browsing.", "priority": "medium"},
    {"category": "Data Brokers", "tip": "Submit opt-out requests to major data brokers (Spokeo, WhitePages, BeenVerified) annually.", "priority": "high"},
]


@router.get("/defensive/{scan_id}")
async def get_defensive_guide(scan_id: str):
    """
    Returns a personalized privacy removal & hardening guide
    based on what was found in the scan.
    """
    scan_data = await get_scan_detail(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found.")

    found_platforms = {p.get("platform", "") for p in scan_data.get("matched_profiles", [])}
    has_breaches    = len(scan_data.get("breaches", [])) > 0
    has_shodan      = len(scan_data.get("shodan_results", [])) > 0
    risk_level      = scan_data.get("risk_level", "LOW")

    # Build personalized action list
    priority_actions = []

    if has_breaches:
        priority_actions.append({
            "urgency": "CRITICAL",
            "action": "Change passwords for all breached services immediately.",
            "reason": f"{len(scan_data.get('breaches', []))} data breach(es) found containing your information.",
        })

    if has_shodan:
        priority_actions.append({
            "urgency": "HIGH",
            "action": "Review and close exposed network ports/services.",
            "reason": "Infrastructure associated with your organization was found in Shodan.",
        })

    for platform in found_platforms:
        if platform in REMOVAL_GUIDES:
            priority_actions.append({
                "urgency": "MEDIUM",
                "action": f"Review privacy settings on {platform}",
                "reason": f"Public profile found on {platform}.",
                "guide":  REMOVAL_GUIDES[platform],
            })

    # Platform-specific guides
    platform_guides = {
        p: REMOVAL_GUIDES[p]
        for p in found_platforms
        if p in REMOVAL_GUIDES
    }

    # Always include general tips
    tips = GENERAL_PRIVACY_TIPS.copy()
    if has_breaches:
        # Boost breach-related tips to top
        tips = sorted(tips, key=lambda t: 0 if t["category"] in ("2FA", "Passwords", "Breaches") else 1)

    return {
        "scan_id":         scan_id,
        "full_name":       scan_data.get("full_name"),
        "risk_level":      risk_level,
        "exposure_score":  scan_data.get("exposure_score", 0),
        "priority_actions":priority_actions,
        "platform_guides": platform_guides,
        "general_tips":    tips,
        "all_guides":      REMOVAL_GUIDES,
        "summary": {
            "profiles_exposed": len(found_platforms),
            "breaches_found":   len(scan_data.get("breaches", [])),
            "emails_exposed":   len(scan_data.get("probable_emails", [])),
            "phones_exposed":   len([c for c in scan_data.get("discovered_contacts", []) if c.get("contact_type") == "phone"]),
        },
    }
