"""schemas.py — v5 FINAL"""

from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


class RiskLevel(str, Enum):
    LOW      = "LOW"
    MODERATE = "MODERATE"
    HIGH     = "HIGH"


class ScanRequest(BaseModel):
    full_name:    str            = Field(..., min_length=2)
    location:     Optional[str] = None
    organization: Optional[str] = None
    username:     Optional[str] = None
    email:        Optional[str] = None
    phone:        Optional[str] = None
    _ws_room:     Optional[str] = None


class MatchedProfile(BaseModel):
    platform:    str
    profile_url: str
    username:    str
    confidence:  int
    bio_snippet: Optional[str] = None
    category:    str


class EmailPattern(BaseModel):
    address:      str
    pattern_type: str
    confidence:   int


class DiscoveredContact(BaseModel):
    """Unified phone or email found from real API data."""
    value:        str
    contact_type: str   # "email" | "phone"
    source:       str
    confidence:   int


class ExposurePoint(BaseModel):
    factor:      str
    weight:      float
    score:       float
    description: str


class GraphNode(BaseModel):
    id:        str
    label:     str
    node_type: str
    metadata:  dict = {}


class GraphEdge(BaseModel):
    source:   str
    target:   str
    relation: str


class BreachRecord(BaseModel):
    source:       str
    date:         Optional[str] = None
    data_classes: List[str]     = []
    verified:     bool          = False


class EmailValidation(BaseModel):
    address:         str
    is_valid_format: bool
    is_deliverable:  Optional[bool] = None
    provider:        Optional[str]  = None
    source:          str            = "pattern"


class GravatarResult(BaseModel):
    email:        str
    has_gravatar: bool
    avatar_url:   Optional[str] = None
    profile_url:  Optional[str] = None


class CertRecord(BaseModel):
    domain:    str
    issuer:    Optional[str] = None
    logged_at: Optional[str] = None


class ShodanResult(BaseModel):
    ip:        str
    hostnames: List[str] = []
    ports:     List[int] = []
    org:       Optional[str] = None
    country:   Optional[str] = None
    vulns:     List[str] = []
    last_seen: Optional[str] = None


class IntelXResult(BaseModel):
    storageid: str
    systemid:  int
    bucket:    str
    name:      str
    date:      Optional[str] = None


class EmailRepResult(BaseModel):
    address:    str
    reputation: str
    suspicious: bool
    references: int
    details:    dict = {}


class PhoneInfoResult(BaseModel):
    number:    str
    valid:     bool
    country:   str = ""
    carrier:   str = ""
    line_type: str = ""
    region:    str = ""
    raw:       Optional[dict] = None


class PhoneOSINTRequest(BaseModel):
    phone_number: str = Field(..., min_length=5, description="International phone number (E.164 preferred)")
    include_risk_flags: bool = True


class PhoneOSINTResult(BaseModel):
    # Input
    input_raw:           str
    normalized:          str
    country_code:        str
    subscriber_number:   str

    # Geographic
    country:             str
    iso_code:            str
    region:              str
    timezone_estimate:   str

    # Telecom
    operator_name:       str
    network_type:        str
    operator_tier:       str
    line_type:           str
    prefix_block:        str
    prefix_type:         str

    # Temporal estimations (SIMULATED)
    registration_estimate: str
    last_seen_simulated:   str
    last_seen_label:       str
    activity_pattern:      str

    # Risk
    risk_flags:          List[str] = []
    risk_flag_count:     int

    # Meta
    confidence_score:    int
    number_length:       int
    analysis_id:         str
    analysis_timestamp:  str
    disclaimer:          str

    # Error (optional)
    error: Optional[str] = None


class URLScanResult(BaseModel):
    url:            str
    domain:         str
    ip:             str = ""
    country:        str = ""
    timestamp:      str = ""
    screenshot_url: str = ""
    uuid:           str = ""
    visibility:     str = ""


class CensysHostResult(BaseModel):
    ip:           str
    name:         str  = ""
    country:      str  = ""
    asn:          Optional[int] = None
    org:          str  = ""
    services:     List[int] = []
    last_updated: str  = ""


class PhoneAnalysisResult(BaseModel):
    """Enriched phone result combining WhoisXML real data + E.164 metadata."""
    number_raw:    str
    number_e164:   str
    valid:         bool
    country:       str
    carrier:       str
    line_type:     str
    region:        str
    # E.164 metadata (always available)
    country_code:  str
    iso_code:      str
    tz_estimate:   str
    operator_est:  str  # fallback when carrier API unavailable
    network_type:  str
    # Source provenance
    source:        str  # "whoisxml" | "e164_metadata"
    confidence:    int
    disclaimer:    str


class APISourceStatus(BaseModel):
    github:        bool = False
    leakcheck:     bool = False
    serpapi:       bool = False
    shodan:        bool = False
    intelx:        bool = False
    hunter:        bool = False
    emailrep:      bool = False
    gravatar:      bool = False
    crt_sh:        bool = False
    abstract_email:bool = False
    whoisxml:      bool = False
    urlscan:       bool = False
    censys:        bool = False


class ScanResult(BaseModel):
    full_name:    str
    location:     Optional[str]
    organization: Optional[str]

    matched_profiles:    List[MatchedProfile]
    probable_emails:     List[EmailPattern]
    discovered_contacts: List[DiscoveredContact] = []
    exposure_points:     List[ExposurePoint]
    confidence_score:    int
    exposure_score:      int
    risk_level:          RiskLevel

    breaches:          List[BreachRecord]    = []
    email_validations: List[EmailValidation] = []
    gravatar_results:  List[GravatarResult]  = []
    cert_records:      List[CertRecord]      = []
    shodan_results:    List[ShodanResult]    = []
    intelx_results:    List[IntelXResult]    = []
    emailrep_results:  List[EmailRepResult]  = []
    urlscan_results:   List[URLScanResult]   = []
    censys_results:    List[CensysHostResult]= []
    phone_analyses:    List[PhoneAnalysisResult] = []

    graph_nodes: List[GraphNode]
    graph_edges: List[GraphEdge]

    scan_id:         str
    timestamp:       str
    sources_checked: int
    api_sources:     APISourceStatus = APISourceStatus()