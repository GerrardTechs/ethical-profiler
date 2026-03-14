"""
phone.py — Educational OSINT Phone Number Analysis Router

This endpoint provides a simulated intelligence dashboard view of phone number
metadata using publicly available ITU-T E.164 numbering plan data.

⚠️ ETHICAL NOTICE: No real-time tracking, location data, or live network
queries are performed. Results are algorithmic estimations for privacy
education purposes only.
"""

import logging
from fastapi import APIRouter
from app.models.schemas import PhoneOSINTRequest, PhoneOSINTResult
from app.services.phone_osint import simulate_phone_analysis

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/phone", tags=["phone-osint"])


@router.post("/analyze", response_model=PhoneOSINTResult)
async def analyze_phone(payload: PhoneOSINTRequest) -> PhoneOSINTResult:
    """
    Accepts an international phone number and returns simulated OSINT metadata:
    - Country / region allocation from ITU-T E.164 prefix database
    - Estimated mobile operator based on numbering plan
    - Line type classification (Mobile / VoIP / Landline)
    - Simulated last-seen activity window (NON-REAL-TIME estimation)
    - Risk flag assessment from public spam/fraud numbering datasets
    - Confidence score based on number format plausibility

    All temporal data is SIMULATED and clearly labeled as non-real-time.
    This endpoint is for educational and privacy-awareness demonstrations only.
    """
    logger.info(
        f"[PHONE-OSINT] Analyzing: {payload.phone_number[:6]}***  "
        f"risk_flags={payload.include_risk_flags}  SIMULATION=ON"
    )

    result = simulate_phone_analysis(payload.phone_number)

    if "error" in result:
        return PhoneOSINTResult(
            input_raw=payload.phone_number,
            normalized="",
            country_code="",
            subscriber_number="",
            country="",
            iso_code="",
            region="",
            timezone_estimate="",
            operator_name="",
            network_type="",
            operator_tier="",
            line_type="",
            prefix_block="",
            prefix_type="",
            registration_estimate="",
            last_seen_simulated="",
            last_seen_label="",
            activity_pattern="",
            risk_flags=[],
            risk_flag_count=0,
            confidence_score=0,
            number_length=0,
            analysis_id="",
            analysis_timestamp="",
            disclaimer=(
                "⚠️ EDUCATIONAL SIMULATION ONLY — "
                "This tool does not perform real-time tracking or network queries."
            ),
            error=result["error"],
        )

    if not payload.include_risk_flags:
        result["risk_flags"] = []
        result["risk_flag_count"] = 0

    return PhoneOSINTResult(**result)
