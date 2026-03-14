"""
osint_engine.py — v5 FINAL

Simulation: COMPLETELY REMOVED.
This file only contains text-mining utilities used to extract
real contact information from API response snippets.
"""

import re

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

_PHONE_RE = re.compile(
    r"""
    (?:
        \+\d{1,3}[\s\-\.]?\(?\d{1,4}\)?[\s\-\.]?\d{2,4}[\s\-\.]?\d{2,4}[\s\-\.]?\d{0,4}
        |
        \(?\d{3}\)?[\s\.\-]\d{3}[\s\.\-]\d{4}
        |
        \d{3}[\s\.\-]\d{3}[\s\.\-]\d{4}
    )
    """,
    re.VERBOSE,
)


def extract_emails_from_text(text: str) -> list[str]:
    if not text:
        return []
    seen, out = set(), []
    for e in _EMAIL_RE.findall(text):
        e = e.lower().strip(".,;:\"'")
        if e not in seen and len(e) < 80:
            seen.add(e); out.append(e)
    return out


def extract_phones_from_text(text: str) -> list[str]:
    if not text:
        return []
    seen, out = set(), []
    for p in _PHONE_RE.findall(text):
        p = p.strip()
        digits = re.sub(r"\D", "", p)
        if len(digits) < 7 or len(digits) > 15:
            continue
        if len(set(digits)) < 3:
            continue
        if p not in seen:
            seen.add(p); out.append(p)
    return out
