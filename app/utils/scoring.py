"""scoring.py — v5 FINAL. All scores derived from real API signals only."""

from app.models.schemas import RiskLevel

RISK_WEIGHTS = {
    "breach_exposure":       0.28,
    "email_exposure":        0.22,
    "developer_presence":    0.15,
    "web_presence":          0.13,
    "infrastructure_exposure": 0.10,
    "dark_web_exposure":     0.07,
    "org_linkage":           0.05,
}


def calculate_exposure_score(factor_scores: dict) -> int:
    return int(min(100, max(0, sum(
        factor_scores.get(f, 0.0) * w for f, w in RISK_WEIGHTS.items()
    ))))


def determine_risk_level(score: int) -> RiskLevel:
    if score >= 65: return RiskLevel.HIGH
    if score >= 30: return RiskLevel.MODERATE
    return RiskLevel.LOW


def calculate_confidence_score(
    real_profile_count: int,
    real_email_count: int,
    breach_count: int,
    github_found: bool,
    serp_found: bool,
    intelx_found: bool,
    user_provided_email: bool,
) -> int:
    """Confidence = how certain we are the data belongs to the target. Real signals only."""
    score = 0
    if user_provided_email: score += 20
    score += min(20, real_email_count * 6)
    score += min(20, breach_count * 8)
    score += min(18, real_profile_count * 4)
    if github_found:  score += 10
    if serp_found:    score += 7
    if intelx_found:  score += 5
    return min(98, score)
