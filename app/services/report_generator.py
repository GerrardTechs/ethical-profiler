"""
report_generator.py — Formal intelligence PDF report generator.

Generates a structured multi-page PDF from a ScanResult dict.
Style: classified intelligence briefing — dark headers, monospace data.

Requires: pip install reportlab
"""

import io
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def generate_pdf_report(scan_data: dict) -> Optional[bytes]:
    """
    Generate a PDF intelligence report from a ScanResult dict.
    Returns bytes of the PDF, or None on error.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            HRFlowable, PageBreak, Paragraph, SimpleDocTemplate,
            Spacer, Table, TableStyle,
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

        buf = io.BytesIO()
        W, H = A4
        margin = 18 * mm

        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=margin, rightMargin=margin,
            topMargin=margin, bottomMargin=margin,
            title=f"OSINT Report — {scan_data.get('full_name', 'Unknown')}",
            author="Ethical Digital Footprint Profiler",
        )

        # ── Colour palette ────────────────────────────────────────────────
        C_BG     = colors.HexColor("#060d1a")
        C_PANEL  = colors.HexColor("#0a1628")
        C_ACCENT = colors.HexColor("#38bdf8")
        C_GREEN  = colors.HexColor("#34d399")
        C_YELLOW = colors.HexColor("#facc15")
        C_RED    = colors.HexColor("#ef4444")
        C_TEXT   = colors.HexColor("#c8ddf0")
        C_DIM    = colors.HexColor("#4a6080")
        C_WHITE  = colors.white
        C_RISK = {
            "HIGH":     C_RED,
            "MODERATE": C_YELLOW,
            "LOW":      C_GREEN,
        }

        # ── Styles ────────────────────────────────────────────────────────
        styles = getSampleStyleSheet()

        def S(name, **kw):
            return ParagraphStyle(name, **kw)

        sTitle = S("sTitle", fontName="Helvetica-Bold", fontSize=20,
                   textColor=C_ACCENT, spaceAfter=2, leading=24)
        sSubtitle = S("sSub", fontName="Helvetica", fontSize=10,
                      textColor=C_DIM, spaceAfter=6)
        sSectionHdr = S("sSectionHdr", fontName="Helvetica-Bold", fontSize=9,
                        textColor=C_ACCENT, spaceBefore=10, spaceAfter=4,
                        letterSpacing=2, textTransform="uppercase" if hasattr(ParagraphStyle, "textTransform") else None)
        sLabel = S("sLabel", fontName="Helvetica-Bold", fontSize=7,
                   textColor=C_DIM, spaceAfter=1)
        sValue = S("sValue", fontName="Helvetica", fontSize=9,
                   textColor=C_TEXT, spaceAfter=4)
        sMono  = S("sMono",  fontName="Courier", fontSize=8,
                   textColor=C_TEXT, spaceAfter=3)
        sMonoAccent = S("sMonoAcc", fontName="Courier-Bold", fontSize=9,
                        textColor=C_ACCENT, spaceAfter=3)
        sBold  = S("sBold",  fontName="Helvetica-Bold", fontSize=9,
                   textColor=C_TEXT, spaceAfter=3)
        sSmall = S("sSmall", fontName="Helvetica", fontSize=7,
                   textColor=C_DIM, spaceAfter=2)
        sDis   = S("sDis",   fontName="Helvetica-Oblique", fontSize=7,
                   textColor=C_YELLOW, spaceAfter=3, leading=10)

        def HR(color=C_ACCENT, thickness=0.5):
            return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=6, spaceBefore=2)

        def Section(title: str):
            return [
                Spacer(1, 4*mm),
                HR(C_ACCENT, 0.8),
                Paragraph(f"▸  {title.upper()}", sSectionHdr),
                HR(C_DIM, 0.3),
            ]

        story = []

        # ── Cover / Header ────────────────────────────────────────────────
        risk     = scan_data.get("risk_level", "LOW")
        risk_col = C_RISK.get(risk, C_GREEN)

        # Title bar table
        title_data = [[
            Paragraph("OSINT INTELLIGENCE BRIEF", sTitle),
            Paragraph(
                f'<font color="#{risk_col.hexval()[2:]}"><b>{risk} RISK</b></font>',
                ParagraphStyle("rt", fontName="Helvetica-Bold", fontSize=14,
                               textColor=risk_col, alignment=TA_RIGHT)
            ),
        ]]
        title_tbl = Table(title_data, colWidths=[W - 2*margin - 40*mm, 40*mm])
        title_tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(title_tbl)
        story.append(HR(C_ACCENT, 1.5))

        # Meta bar
        ts  = scan_data.get("timestamp", datetime.now(timezone.utc).isoformat())[:19]
        sid = scan_data.get("scan_id", "UNKNOWN")
        meta_data = [[
            Paragraph(f"<b>SCAN ID:</b> {sid}", sMono),
            Paragraph(f"<b>GENERATED:</b> {ts} UTC", sMono),
            Paragraph(f"<b>SOURCES CHECKED:</b> {scan_data.get('sources_checked', 0)}", sMono),
        ]]
        meta_tbl = Table(meta_data, colWidths=[(W - 2*margin) / 3] * 3)
        meta_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_PANEL),
            ("GRID", (0, 0), (-1, -1), 0.3, C_DIM),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(meta_tbl)
        story.append(Spacer(1, 4*mm))

        # ── Target Profile ────────────────────────────────────────────────
        story += Section("Target Profile")
        profile_rows = [
            ["Full Name",    scan_data.get("full_name", "—")],
            ["Location",     scan_data.get("location") or "—"],
            ["Organization", scan_data.get("organization") or "—"],
            ["Exposure Score", str(scan_data.get("exposure_score", 0)) + " / 100"],
            ["Confidence",   str(scan_data.get("confidence_score", 0)) + "%"],
            ["Risk Level",   risk],
        ]
        pt = Table(
            [[Paragraph(r[0], sLabel), Paragraph(str(r[1]), sValue)] for r in profile_rows],
            colWidths=[40*mm, W - 2*margin - 40*mm],
        )
        pt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), C_PANEL),
            ("GRID", (0, 0), (-1, -1), 0.3, C_DIM),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TEXTCOLOR", (0, 0), (0, -1), C_DIM),
        ]))
        story.append(pt)

        # ── Discovered Emails ─────────────────────────────────────────────
        emails = scan_data.get("probable_emails", [])
        if emails:
            story += Section(f"Email Addresses ({len(emails)} found)")
            email_data = [
                [
                    Paragraph(e.get("address", ""), sMonoAccent),
                    Paragraph(e.get("pattern_type", ""), sSmall),
                    Paragraph(f"{e.get('confidence', 0)}%", sSmall),
                ]
                for e in emails[:20]
            ]
            et = Table(
                [
                    [Paragraph("ADDRESS", sLabel), Paragraph("SOURCE", sLabel), Paragraph("CONF", sLabel)],
                    *email_data,
                ],
                colWidths=[75*mm, 70*mm, 20*mm],
            )
            et.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), C_PANEL),
                ("GRID", (0, 0), (-1, -1), 0.3, C_DIM),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG, C_PANEL]),
            ]))
            story.append(et)

        # ── Phone Numbers ─────────────────────────────────────────────────
        phones = scan_data.get("phone_analyses", [])
        contacts = scan_data.get("discovered_contacts", [])
        phone_contacts = [c for c in contacts if c.get("contact_type") == "phone"]
        if phones or phone_contacts:
            story += Section(f"Phone Numbers ({len(phones or phone_contacts)} found)")
            if phones:
                for p in phones[:10]:
                    row_data = [
                        [Paragraph("NUMBER", sLabel), Paragraph(p.get("number_e164", "—"), sMonoAccent)],
                        [Paragraph("COUNTRY", sLabel), Paragraph(p.get("country", "—"), sValue)],
                        [Paragraph("CARRIER", sLabel), Paragraph(p.get("carrier", "—"), sValue)],
                        [Paragraph("LINE TYPE", sLabel), Paragraph(p.get("line_type", "—"), sValue)],
                        [Paragraph("SOURCE", sLabel), Paragraph(p.get("source", "—").upper(), sSmall)],
                    ]
                    rt = Table(row_data, colWidths=[35*mm, W - 2*margin - 35*mm])
                    rt.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (0, -1), C_PANEL),
                        ("GRID", (0, 0), (-1, -1), 0.3, C_DIM),
                        ("PADDING", (0, 0), (-1, -1), 4),
                    ]))
                    story.append(rt)
                    story.append(Spacer(1, 2*mm))

        # ── Discovered Profiles ───────────────────────────────────────────
        profiles = scan_data.get("matched_profiles", [])
        if profiles:
            story += Section(f"Online Profiles ({len(profiles)} found)")
            pd_data = [
                [
                    Paragraph(p.get("platform", ""), sBold),
                    Paragraph(p.get("username", ""), sMono),
                    Paragraph(p.get("profile_url", ""), sSmall),
                    Paragraph(str(p.get("confidence", 0)) + "%", sSmall),
                ]
                for p in profiles[:30]
            ]
            hdr = [Paragraph(h, sLabel) for h in ["PLATFORM", "USERNAME", "URL", "CONF"]]
            pdt = Table(
                [hdr, *pd_data],
                colWidths=[35*mm, 30*mm, 85*mm, 15*mm],
            )
            pdt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), C_PANEL),
                ("GRID", (0, 0), (-1, -1), 0.3, C_DIM),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG, C_PANEL]),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
            ]))
            story.append(pdt)

        # ── Data Breaches ─────────────────────────────────────────────────
        breaches = scan_data.get("breaches", [])
        if breaches:
            story += Section(f"Data Breaches ({len(breaches)} found)")
            bd_data = [
                [
                    Paragraph(b.get("source", "—"), sBold),
                    Paragraph(b.get("date") or "—", sMono),
                    Paragraph(", ".join(b.get("data_classes", [])) or "—", sSmall),
                    Paragraph("✓ VERIFIED" if b.get("verified") else "unverified", sSmall),
                ]
                for b in breaches[:20]
            ]
            bdt = Table(
                [[Paragraph(h, sLabel) for h in ["SOURCE", "DATE", "DATA TYPES", "STATUS"]], *bd_data],
                colWidths=[40*mm, 25*mm, 80*mm, 20*mm],
            )
            bdt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), C_PANEL),
                ("GRID", (0, 0), (-1, -1), 0.3, C_DIM),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG, C_PANEL]),
                ("TEXTCOLOR", (0, 1), (-1, -1), C_RED),
            ]))
            story.append(bdt)

        # ── Infrastructure ────────────────────────────────────────────────
        shodan = scan_data.get("shodan_results", [])
        censys = scan_data.get("censys_results", [])
        if shodan or censys:
            story += Section(f"Infrastructure ({len(shodan)+len(censys)} hosts)")
            all_hosts = [
                {**s, "_src": "Shodan"} for s in (shodan or [])
            ] + [
                {**c, "_src": "Censys"} for c in (censys or [])
            ]
            host_data = [
                [
                    Paragraph(h.get("ip", "—"), sMonoAccent),
                    Paragraph(h.get("org") or h.get("hostnames", [""])[0] if isinstance(h.get("hostnames"), list) else "—", sSmall),
                    Paragraph(h.get("country") or "—", sSmall),
                    Paragraph(str(h.get("ports") or h.get("services") or "—")[:30], sSmall),
                    Paragraph(h.get("_src", "—"), sSmall),
                ]
                for h in all_hosts[:15]
            ]
            ht = Table(
                [[Paragraph(h, sLabel) for h in ["IP", "ORG/HOST", "COUNTRY", "PORTS", "SRC"]], *host_data],
                colWidths=[30*mm, 50*mm, 25*mm, 45*mm, 15*mm],
            )
            ht.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), C_PANEL),
                ("GRID", (0, 0), (-1, -1), 0.3, C_DIM),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG, C_PANEL]),
            ]))
            story.append(ht)

        # ── URLScan ───────────────────────────────────────────────────────
        urlscans = scan_data.get("urlscan_results", [])
        if urlscans:
            story += Section(f"Web Scan History ({len(urlscans)} records)")
            ud_data = [
                [
                    Paragraph(u.get("domain") or u.get("url", "—")[:40], sMono),
                    Paragraph(u.get("ip") or "—", sSmall),
                    Paragraph(u.get("country") or "—", sSmall),
                    Paragraph((u.get("timestamp") or "—")[:10], sSmall),
                ]
                for u in urlscans[:10]
            ]
            ut = Table(
                [[Paragraph(h, sLabel) for h in ["DOMAIN/URL", "IP", "COUNTRY", "DATE"]], *ud_data],
                colWidths=[75*mm, 30*mm, 25*mm, 35*mm],
            )
            ut.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), C_PANEL),
                ("GRID", (0, 0), (-1, -1), 0.3, C_DIM),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG, C_PANEL]),
            ]))
            story.append(ut)

        # ── Exposure Surface ──────────────────────────────────────────────
        exposure = scan_data.get("exposure_points", [])
        if exposure:
            story += Section("Exposure Surface Analysis")
            exp_data = [
                [
                    Paragraph(e.get("factor", "—"), sBold),
                    Paragraph(str(e.get("score", 0)), sValue),
                    Paragraph(e.get("description", "—"), sSmall),
                ]
                for e in sorted(exposure, key=lambda x: x.get("score", 0), reverse=True)
            ]
            expt = Table(
                [[Paragraph(h, sLabel) for h in ["FACTOR", "SCORE", "DESCRIPTION"]], *exp_data],
                colWidths=[50*mm, 20*mm, 95*mm],
            )
            expt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), C_PANEL),
                ("GRID", (0, 0), (-1, -1), 0.3, C_DIM),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG, C_PANEL]),
            ]))
            story.append(expt)

        # ── Disclaimer Page ───────────────────────────────────────────────
        story.append(PageBreak())
        story += Section("Legal Disclaimer & Methodology")
        disclaimer_text = (
            "This report was generated by the Ethical Digital Footprint Profiler (EDFP), "
            "an OSINT-based public exposure assessment tool for defensive cybersecurity research. "
            "All data presented in this report was collected exclusively from publicly available "
            "sources including but not limited to: search engine indices, public social media profiles, "
            "certificate transparency logs, public breach databases, and WHOIS records. "
            "<br/><br/>"
            "This report is intended solely for: (1) self-assessment of personal digital footprint, "
            "(2) authorized security research, (3) due diligence with appropriate legal authorization. "
            "Use of this report for stalking, harassment, unauthorized surveillance, or any illegal "
            "purpose is strictly prohibited and may violate applicable laws including but not limited to "
            "UU ITE (Indonesia), GDPR (EU), CFAA (USA), and equivalent legislation. "
            "<br/><br/>"
            "Phone carrier data is sourced from ITU-T E.164 numbering plan registries and WhoisXML "
            "Phone Intelligence. This data reflects number registration metadata and does NOT indicate "
            "real-time location, current carrier status, or subscriber activity. "
            "<br/><br/>"
            f"Report generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC | "
            f"Scan ID: {scan_data.get('scan_id', 'N/A')}"
        )
        story.append(Paragraph(disclaimer_text, sDis))

        # ── Build ─────────────────────────────────────────────────────────
        def _page_bg(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(C_BG)
            canvas.rect(0, 0, W, H, fill=1, stroke=0)
            # Header bar
            canvas.setFillColor(C_PANEL)
            canvas.rect(0, H - 10*mm, W, 10*mm, fill=1, stroke=0)
            canvas.setFont("Helvetica-Bold", 7)
            canvas.setFillColor(C_DIM)
            canvas.drawString(margin, H - 6.5*mm, "ETHICAL DIGITAL FOOTPRINT PROFILER  //  CONFIDENTIAL")
            canvas.drawRightString(
                W - margin, H - 6.5*mm,
                f"PAGE {doc.page}  //  SCAN {scan_data.get('scan_id', '')}"
            )
            # Footer bar
            canvas.setFillColor(C_PANEL)
            canvas.rect(0, 0, W, 8*mm, fill=1, stroke=0)
            canvas.setFont("Helvetica", 6)
            canvas.setFillColor(C_DIM)
            canvas.drawString(margin, 3*mm, "FOR AUTHORIZED USE ONLY — OSINT PUBLIC DATA — NOT FOR UNLAWFUL SURVEILLANCE")
            canvas.restoreState()

        doc.build(story, onFirstPage=_page_bg, onLaterPages=_page_bg)
        return buf.getvalue()

    except ImportError:
        logger.error("[PDF] reportlab not installed — run: pip install reportlab")
        return None
    except Exception as e:
        logger.error(f"[PDF] Generation error: {e}")
        return None
