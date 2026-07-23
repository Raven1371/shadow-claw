"""Core data models for the Nmap flow analyzer.

All records produced by the pipeline are plain dataclasses so they can be
serialized deterministically to CSV, JSON, Excel, and HTML.
"""

from __future__ import annotations

import dataclasses
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class EvidenceClass(str, Enum):
    """How a flow or rule is supported by evidence."""

    OBSERVED = "Observed"
    INFERRED = "Inferred"
    USER_DEFINED = "User-Defined"
    UNKNOWN = "Unknown"
    MANUAL_REVIEW = "Manual Review Required"


#: Priority used when de-duplicating flows (higher wins).
EVIDENCE_PRIORITY: Dict[str, int] = {
    EvidenceClass.OBSERVED.value: 4,
    EvidenceClass.USER_DEFINED.value: 3,
    EvidenceClass.INFERRED.value: 2,
    EvidenceClass.MANUAL_REVIEW.value: 1,
    EvidenceClass.UNKNOWN.value: 0,
}


class RiskLevel(str, Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


RISK_ORDER: Dict[str, int] = {
    RiskLevel.INFORMATIONAL.value: 0,
    RiskLevel.LOW.value: 1,
    RiskLevel.MEDIUM.value: 2,
    RiskLevel.HIGH.value: 3,
    RiskLevel.CRITICAL.value: 4,
}


class VulnCategory(str, Enum):
    CONFIRMED = "Confirmed by script"
    LIKELY = "Likely"
    POTENTIAL = "Potential"
    INFORMATIONAL = "Informational"
    UNDETERMINED = "Unable to determine"


@dataclass
class ScriptResult:
    """A single NSE script result (host- or port-scoped)."""

    script_id: str = ""
    output: str = ""
    scope: str = "port"  # "port" | "host"


@dataclass
class PortRecord:
    """One port entry from the Nmap XML."""

    protocol: str = "tcp"
    port: int = 0
    state: str = "unknown"
    reason: str = ""
    service_name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    detection_method: str = ""
    detection_confidence: str = ""
    cpes: List[str] = field(default_factory=list)
    scripts: List[ScriptResult] = field(default_factory=list)


@dataclass
class OSMatch:
    name: str = ""
    accuracy: int = 0
    device_types: List[str] = field(default_factory=list)


@dataclass
class TracerouteHop:
    ttl: int = 0
    ip: str = ""
    rtt: str = ""
    host: str = ""


@dataclass
class Host:
    """A scanned host plus configuration/inference enrichment."""

    ipv4: str = ""
    ipv6: str = ""
    mac: str = ""
    mac_vendor: str = ""
    hostnames: List[str] = field(default_factory=list)
    state: str = "unknown"
    state_reason: str = ""
    ports: List[PortRecord] = field(default_factory=list)
    os_matches: List[OSMatch] = field(default_factory=list)
    device_types: List[str] = field(default_factory=list)
    traceroute: List[TracerouteHop] = field(default_factory=list)
    host_scripts: List[ScriptResult] = field(default_factory=list)
    # Enrichment (from configuration and role inference)
    zone: str = "Unknown"
    role: str = "Unknown"
    role_confidence: int = 0
    role_evidence: List[str] = field(default_factory=list)
    role_contradictions: List[str] = field(default_factory=list)
    role_source: str = "none"  # "user configuration" | "xml evidence" | "none"
    owner: str = ""
    purpose: str = ""
    device_class: str = "unknown"

    @property
    def primary_ip(self) -> str:
        return self.ipv4 or self.ipv6

    @property
    def ip_version(self) -> int:
        if self.ipv4:
            return 4
        if self.ipv6:
            return 6
        return 0

    @property
    def display_name(self) -> str:
        if self.hostnames:
            return self.hostnames[0]
        return self.primary_ip or "unknown-host"

    @property
    def best_os(self) -> str:
        return self.os_matches[0].name if self.os_matches else ""

    def open_ports(self) -> List[PortRecord]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class ScanMetadata:
    command_line: str = ""
    nmap_version: str = ""
    xml_version: str = ""
    scanner: str = ""
    args: str = ""
    start_time: str = ""
    end_time: str = ""
    elapsed: str = ""
    summary: str = ""
    scan_types: List[str] = field(default_factory=list)
    scan_protocols: List[str] = field(default_factory=list)
    source_file: str = ""


@dataclass
class ServiceRecord:
    """Flattened per-port service inventory row with risk assessment."""

    hostname: str = ""
    ip: str = ""
    zone: str = "Unknown"
    role: str = "Unknown"
    protocol: str = "tcp"
    port: int = 0
    state: str = "unknown"
    reason: str = ""
    detected_service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    normalized_service: str = ""
    expected_service: str = ""
    mismatch: bool = False
    mismatch_note: str = ""
    cpes: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    risk_level: str = RiskLevel.INFORMATIONAL.value
    risk_reasons: List[str] = field(default_factory=list)
    encryption: str = "Unknown"
    authentication: str = "Unknown"
    evidence_class: str = EvidenceClass.UNKNOWN.value
    approved: str = "not specified"  # "yes" | "no" | "not specified"
    # v1.2.0 Zeek correlation (append-only)
    zeek_observation: str = ""
    correlation_status: str = ""
    # v1.2.1: scanner traffic is not production traffic, so the two are
    # tracked separately and never reported as the same thing.
    any_zeek_traffic_observed: bool = False
    non_scanner_zeek_traffic_observed: bool = False
    scanner_only_zeek_traffic_observed: bool = False


@dataclass
class Flow:
    """Normalized data-flow object."""

    flow_id: str = ""
    source_name: str = ""
    source: str = ""  # IP or CIDR
    source_zone: str = "Unknown"
    destination_name: str = ""
    destination: str = ""  # IP or CIDR
    destination_zone: str = "Unknown"
    ip_version: int = 4
    protocol: str = "tcp"
    source_port: str = "any"
    destination_port: int = 0
    normalized_service: str = ""
    detected_service: str = ""
    direction: str = "inbound"  # relative to the scanned target
    purpose: str = ""
    evidence_class: str = EvidenceClass.UNKNOWN.value
    evidence: str = ""
    confidence: int = 0
    port_state: str = ""
    state_reason: str = ""
    risk_level: str = RiskLevel.INFORMATIONAL.value
    risk_reasons: List[str] = field(default_factory=list)
    encryption: str = "Unknown"
    authentication: str = "Unknown"
    recommended_action: str = ""
    manual_review_reason: str = ""
    source_xml_host: str = ""
    related_scripts: List[str] = field(default_factory=list)
    # Per-component evidence (see compose_flow_evidence); evidence_class is
    # preserved unchanged for backward compatibility.
    service_evidence: str = ""
    source_scope_evidence: str = ""
    destination_scope_evidence: str = ""
    purpose_evidence: str = ""
    role_evidence: str = ""
    flow_evidence: str = ""
    perspective: str = ""  # source-outbound | destination-inbound | network
    # v1.2.0 Zeek correlation fields (append-only)
    evidence_sources: List[str] = field(default_factory=list)
    nmap_observation: str = ""
    zeek_observation: str = ""
    correlation_status: str = ""
    first_seen: str = ""
    last_seen: str = ""
    connection_count: int = 0
    successful_connections: int = 0
    failed_connections: int = 0
    one_way_connections: int = 0
    partial_connections: int = 0
    originator_bytes: int = 0
    responder_bytes: int = 0
    originator_packets: int = 0
    responder_packets: int = 0
    zeek_conn_states: List[str] = field(default_factory=list)
    zeek_services: List[str] = field(default_factory=list)
    sample_zeek_uids: List[str] = field(default_factory=list)
    dns_names: List[str] = field(default_factory=list)
    tls_server_names: List[str] = field(default_factory=list)
    http_hosts: List[str] = field(default_factory=list)
    sensor_quality: str = ""
    confidence_notes: str = ""  # why Zeek confidence was reduced (v1.2.1)


@dataclass
class FirewallRule:
    """A candidate firewall exception (never an implemented rule)."""

    rule_id: str = ""
    direction: str = "inbound"
    target_hostname: str = ""
    target_ip: str = ""
    target_zone: str = "Unknown"
    source: str = ""
    source_hostname: str = ""
    source_zone: str = "Unknown"
    destination: str = ""
    destination_hostname: str = ""
    destination_zone: str = "Unknown"
    protocol: str = "tcp"
    port: str = ""  # string so ranges like "1024-65535" are representable
    service: str = ""
    purpose: str = ""
    evidence_class: str = EvidenceClass.UNKNOWN.value
    evidence: str = ""
    confidence: int = 0
    encryption: str = "Unknown"
    authentication: str = "Unknown"
    risk_level: str = RiskLevel.INFORMATIONAL.value
    recommended_action: str = ""
    description: str = ""
    scope_warning: str = ""
    manual_review_notes: str = ""
    flow_id: str = ""
    service_evidence: str = ""
    source_scope_evidence: str = ""
    destination_scope_evidence: str = ""
    purpose_evidence: str = ""
    role_evidence: str = ""
    flow_evidence: str = ""
    perspective: str = ""  # source-outbound | destination-inbound | network
    enforcement_model: str = ""
    source_scope_status: str = ""
    destination_scope_status: str = ""
    matched_source_policy: str = ""
    matched_destination_policy: str = ""
    policy_violation: bool = False
    policy_notes: str = ""
    # v1.2.0 Zeek correlation fields (append-only)
    evidence_sources: List[str] = field(default_factory=list)
    nmap_observation: str = ""
    zeek_observation: str = ""
    correlation_status: str = ""
    first_seen: str = ""
    last_seen: str = ""
    connection_count: int = 0
    successful_connections: int = 0
    failed_connections: int = 0
    one_way_connections: int = 0
    partial_connections: int = 0
    originator_bytes: int = 0
    responder_bytes: int = 0
    originator_packets: int = 0
    responder_packets: int = 0
    zeek_conn_states: List[str] = field(default_factory=list)
    zeek_services: List[str] = field(default_factory=list)
    sample_zeek_uids: List[str] = field(default_factory=list)
    dns_names: List[str] = field(default_factory=list)
    tls_server_names: List[str] = field(default_factory=list)
    http_hosts: List[str] = field(default_factory=list)
    sensor_quality: str = ""
    confidence_notes: str = ""  # why Zeek confidence was reduced (v1.2.1)


@dataclass
class ManualReviewItem:
    item_id: str = ""
    category: str = ""
    host: str = ""
    ip: str = ""
    protocol: str = ""
    port: str = ""
    finding: str = ""
    reason: str = ""
    recommendation: str = ""
    evidence_class: str = EvidenceClass.MANUAL_REVIEW.value
    related_flow: str = ""


@dataclass
class VulnFinding:
    host: str = ""
    ip: str = ""
    protocol: str = ""
    port: str = ""
    script_id: str = ""
    category: str = VulnCategory.UNDETERMINED.value
    excerpt: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ip_sort_key(ip: str) -> Tuple[int, int]:
    """Deterministic sort key: IPv4 first, then IPv6, then non-parsable."""
    try:
        obj = ipaddress.ip_address(ip)
        return (obj.version, int(obj))
    except ValueError:
        return (9, 0)


def as_flat_dict(obj: Any) -> Dict[str, Any]:
    """Convert a dataclass to a flat dict suitable for CSV/Excel rows.

    Lists become "; "-joined strings and booleans become "yes"/"no".
    """
    raw = dataclasses.asdict(obj)
    flat: Dict[str, Any] = {}
    for key, value in raw.items():
        if isinstance(value, list):
            flat[key] = "; ".join(
                v if isinstance(v, str) else str(v) for v in value
            )
        elif isinstance(value, bool):
            flat[key] = "yes" if value else "no"
        else:
            flat[key] = value
    return flat


def field_names(cls: type) -> List[str]:
    """Ordered dataclass field names (deterministic column order)."""
    return [f.name for f in dataclasses.fields(cls)]


#: Order used when combining evidence components into flow_evidence.
_EVIDENCE_COMBINE_ORDER = [
    EvidenceClass.OBSERVED.value,
    EvidenceClass.USER_DEFINED.value,
    EvidenceClass.INFERRED.value,
    EvidenceClass.UNKNOWN.value,
    EvidenceClass.MANUAL_REVIEW.value,
]


def compose_flow_evidence(
    service: str = "",
    source_scope: str = "",
    destination_scope: str = "",
) -> str:
    """Transparently combine per-component evidence into one label.

    Rules: any component requiring manual review makes the whole flow
    "Manual Review Required"; an Unknown service combined with any Inferred
    scope is likewise unsafe to act on.  Otherwise the unique component
    classes are joined, e.g. "Observed + User-Defined".
    """
    parts = [p for p in (service, source_scope, destination_scope) if p]
    if not parts:
        return EvidenceClass.UNKNOWN.value
    if EvidenceClass.MANUAL_REVIEW.value in parts:
        return EvidenceClass.MANUAL_REVIEW.value
    if service == EvidenceClass.UNKNOWN.value and EvidenceClass.INFERRED.value in parts:
        return EvidenceClass.MANUAL_REVIEW.value
    unique = [c for c in _EVIDENCE_COMBINE_ORDER if c in parts]
    return " + ".join(unique)
