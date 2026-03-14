"""Risk assessment + identity graph builder — v4."""

from app.models.schemas import (
    BreachRecord, CertRecord, EmailPattern, ExposurePoint,
    GraphEdge, GraphNode, IntelXResult, MatchedProfile,
    RiskLevel, ShodanResult,
)
from app.utils.scoring import calculate_exposure_score, determine_risk_level

_CAT_TYPE = {
    "social": "social", "professional": "social",
    "developer": "developer", "document": "document",
}


def assess_risk(exposure_points: list[ExposurePoint]) -> tuple[int, RiskLevel]:
    score = calculate_exposure_score({ep.factor: ep.score for ep in exposure_points})
    return score, determine_risk_level(score)


def build_graph(
    target_name:    str,
    profiles:       list[MatchedProfile],
    emails:         list[EmailPattern],
    breaches:       list[BreachRecord]  | None = None,
    cert_records:   list[CertRecord]    | None = None,
    shodan_results: list[ShodanResult]  | None = None,
    intelx_results: list[IntelXResult]  | None = None,
) -> tuple[list[GraphNode], list[GraphEdge]]:

    breaches       = breaches       or []
    cert_records   = cert_records   or []
    shodan_results = shodan_results or []
    intelx_results = intelx_results or []

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    seen:  set[str]        = set()

    def add(node: GraphNode):
        if node.id not in seen:
            nodes.append(node); seen.add(node.id)

    # Target node
    add(GraphNode(id="target_0", label=target_name, node_type="target",
                  metadata={"display": target_name}))

    # Email nodes
    for i, email in enumerate(emails[:4]):
        eid = f"email_{i}"
        add(GraphNode(id=eid, label=email.address, node_type="email",
                      metadata={"confidence": email.confidence, "pattern": email.pattern_type}))
        edges.append(GraphEdge(source="target_0", target=eid,
                               relation="owns" if email.confidence >= 70 else "linked_to"))

    # Profile nodes
    for i, p in enumerate(profiles):
        nid   = f"profile_{i}"
        ntype = _CAT_TYPE.get(p.category, "social")
        add(GraphNode(id=nid, label=p.platform, node_type=ntype,
                      metadata={"username": p.username, "url": p.profile_url,
                                "confidence": p.confidence, "bio": p.bio_snippet or ""}))
        edges.append(GraphEdge(source="target_0", target=nid,
                               relation="owns" if p.confidence >= 70 else "linked_to"))
        if p.confidence >= 75 and "email_0" in seen:
            edges.append(GraphEdge(source=nid, target="email_0", relation="associated_with"))

    # Breach nodes
    for i, b in enumerate(breaches[:6]):
        bid = f"breach_{i}"
        add(GraphNode(id=bid, label=b.source, node_type="breach",
                      metadata={"date": b.date or "?", "data": ", ".join(b.data_classes)}))
        src = "email_0" if "email_0" in seen else "target_0"
        edges.append(GraphEdge(source=src, target=bid, relation="found_in"))

    # Cert nodes
    for i, cert in enumerate(cert_records[:5]):
        cid = f"cert_{i}"
        add(GraphNode(id=cid, label=cert.domain, node_type="cert",
                      metadata={"issuer": cert.issuer or "?", "logged": cert.logged_at or "?"}))
        edges.append(GraphEdge(source="target_0", target=cid, relation="registered"))

    # Shodan nodes
    for i, sh in enumerate(shodan_results[:4]):
        sid   = f"shodan_{i}"
        label = sh.hostnames[0] if sh.hostnames else sh.ip
        add(GraphNode(id=sid, label=label, node_type="infrastructure",
                      metadata={"ip": sh.ip, "ports": str(sh.ports),
                                "vulns": len(sh.vulns), "org": sh.org or "?"}))
        edges.append(GraphEdge(source="target_0", target=sid, relation="operates"))

    # IntelX nodes
    for i, ix in enumerate(intelx_results[:4]):
        iid = f"intelx_{i}"
        add(GraphNode(id=iid, label=ix.bucket, node_type="intelligence",
                      metadata={"name": ix.name, "date": ix.date or "?", "bucket": ix.bucket}))
        edges.append(GraphEdge(source="target_0", target=iid, relation="indexed_in"))

    return nodes, edges
