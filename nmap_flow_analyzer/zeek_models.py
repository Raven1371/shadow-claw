"""Typed data models for Zeek log ingestion and correlation.

Zeek describes *actual communications seen by a passive sensor*; Nmap
describes *reachability from the scanner*; configuration describes
*declared intent*.  These models keep those meanings separate so the
correlation layer can merge evidence without conflating it.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Connection-outcome classes (see zeek_aggregation.classify_connection)
OUTCOME_SUCCESSFUL = "successful"
OUTCOME_FAILED = "failed"
OUTCOME_REJECTED = "rejected"
OUTCOME_ONE_WAY = "one-way"
OUTCOME_PARTIAL = "partial"
OUTCOME_AMBIGUOUS = "ambiguous"

# Correlation statuses (spec-defined vocabulary)
CORR_NMAP_ONLY = "nmap-reachability-only"
CORR_ZEEK_ONLY = "zeek-traffic-only"
CORR_NMAP_AND_ZEEK = "nmap-and-zeek"
CORR_USER_ONLY = "user-defined-only"
CORR_USER_AND_ZEEK = "user-defined-and-zeek"
CORR_INFERRED_ONLY = "inferred-only"
CORR_ATTEMPTED_ONLY = "attempted-only"
CORR_CONFLICTING = "conflicting-evidence"
CORR_NOT_CORRELATED = "not-correlated"

# evidence_sources vocabulary
SOURCE_NMAP = "nmap"
SOURCE_ZEEK = "zeek"
SOURCE_USER = "user_configuration"
SOURCE_INFERENCE = "inference"


def iso_utc(epoch: Optional[float]) -> str:
    """Zeek epoch timestamp -> UTC ISO-8601 string ('' when absent)."""
    if epoch is None:
        return ""
    try:
        return datetime.datetime.fromtimestamp(
            float(epoch), tz=datetime.timezone.utc
        ).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class ZeekConnectionRecord:
    """One conn.log record (only the fields the analyzer uses)."""

    uid: str = ""
    ts: Optional[float] = None
    orig_h: str = ""
    orig_p: int = 0
    resp_h: str = ""
    resp_p: int = 0
    proto: str = ""
    service: str = ""
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    conn_state: str = ""
    missed_bytes: int = 0
    orig_pkts: int = 0
    orig_ip_bytes: int = 0
    resp_pkts: int = 0
    resp_ip_bytes: int = 0
    tunnel_parents: List[str] = field(default_factory=list)
    vlan: str = ""
    community_id: str = ""


@dataclass
class ZeekInputMetadata:
    """What was read, from where, and how well it parsed."""

    input_directories: List[str] = field(default_factory=list)
    files_processed: List[Dict[str, object]] = field(default_factory=list)
    log_types_found: List[str] = field(default_factory=list)
    record_counts: Dict[str, int] = field(default_factory=dict)
    malformed_counts: Dict[str, int] = field(default_factory=dict)
    # v1.2.1: raw lines that parsed structurally vs. records that passed
    # required-field validation. raw = usable + malformed for each log type.
    raw_records_read: Dict[str, int] = field(default_factory=dict)
    usable_records: Dict[str, int] = field(default_factory=dict)
    # v1.2.2: for optional logs whose stored samples are capped, how many
    # bounded samples were kept vs. dropped. Parsing always reads the whole
    # file; only sample storage is capped, so records/malformed counts stay
    # complete while these show the truncation.
    samples_retained: Dict[str, int] = field(default_factory=dict)
    samples_truncated: Dict[str, int] = field(default_factory=dict)
    # v1.2.3: per-log-type roll-ups. The sample cap for bounded logs (files,
    # notice) is GLOBAL across all rotated files of that type, so retention is
    # reported once here at log-type scope - never copied onto each physical
    # file entry in files_processed (which stays strictly per-file).
    log_type_summaries: List[Dict[str, object]] = field(default_factory=list)
    earliest_timestamp: str = ""
    latest_timestamp: str = ""
    conn_log_available: bool = False
    capture_loss_available: bool = False
    warnings: List[str] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)


@dataclass
class ZeekFlowAggregate:
    """All conn.log records for one canonical communication.

    Keyed by (originator IP, responder IP, transport protocol, responder
    port).  Distinct originators are never merged merely because they talk
    to the same server.
    """

    originator: str = ""
    responder: str = ""
    protocol: str = ""
    responder_port: int = 0
    ip_version: int = 4
    services: List[str] = field(default_factory=list)
    originator_ports_seen: int = 0
    originator_port_min: int = 0
    originator_port_max: int = 0
    first_seen: str = ""
    last_seen: str = ""
    connection_count: int = 0
    successful_count: int = 0
    failed_count: int = 0
    rejected_count: int = 0
    one_way_count: int = 0
    partial_count: int = 0
    ambiguous_count: int = 0
    originator_bytes: int = 0
    responder_bytes: int = 0
    originator_ip_bytes: int = 0
    responder_ip_bytes: int = 0
    originator_packets: int = 0
    responder_packets: int = 0
    total_duration: float = 0.0
    max_duration: float = 0.0
    conn_states: List[str] = field(default_factory=list)
    missed_bytes: int = 0
    sample_uids: List[str] = field(default_factory=list)
    tunnel_parents: List[str] = field(default_factory=list)
    vlans: List[str] = field(default_factory=list)
    community_ids: List[str] = field(default_factory=list)
    scanner_traffic: bool = False
    ignored_by_config: bool = False
    sensor_quality: str = "unknown"
    outcome_label: str = ""
    # Enrichment (correlated via uid; bounded sample lists)
    dns_names: List[str] = field(default_factory=list)
    #: v1.2.1: application-protocol logs (ssh/rdp/kerberos/...) that
    #: matched this flow by uid. Supporting evidence only.
    protocol_confirmations: List[str] = field(default_factory=list)
    tls_server_names: List[str] = field(default_factory=list)
    http_hosts: List[str] = field(default_factory=list)
    enrichment_notes: List[str] = field(default_factory=list)

    @property
    def key(self):
        return (self.originator, self.responder, self.protocol, self.responder_port)

    @property
    def outcome(self) -> str:
        """Dominant outcome, conservatively: success only if any succeeded."""
        if self.successful_count:
            return OUTCOME_SUCCESSFUL
        if self.rejected_count:
            return OUTCOME_REJECTED
        if self.failed_count:
            return OUTCOME_FAILED
        if self.one_way_count:
            return OUTCOME_ONE_WAY
        if self.partial_count:
            return OUTCOME_PARTIAL
        return OUTCOME_AMBIGUOUS

    @property
    def success_ratio(self) -> float:
        if not self.connection_count:
            return 0.0
        return self.successful_count / self.connection_count


@dataclass
class ZeekProtocolEnrichment:
    """Bounded per-uid enrichment extracted from optional Zeek logs."""

    uid: str = ""
    log_type: str = ""
    dns_query: str = ""
    dns_qtype: str = ""
    dns_rcode: str = ""
    dns_answers: List[str] = field(default_factory=list)
    dns_rejected: bool = False
    tls_server_name: str = ""
    tls_version: str = ""
    tls_cipher: str = ""
    tls_next_protocol: str = ""
    tls_established: bool = False
    cert_subject: str = ""
    cert_issuer: str = ""
    http_host: str = ""
    http_method: str = ""
    http_status: str = ""
    http_uri_path: str = ""  # query strings and fragments stripped
    detail: str = ""


@dataclass
class ZeekCertificate:
    """Bounded X.509 metadata (never private keys or payload contents)."""

    fuid: str = ""
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_valid_before: str = ""
    not_valid_after: str = ""
    key_algorithm: str = ""
    key_length: str = ""
    signature_algorithm: str = ""
    source_log: str = ""  # x509 | known_certs
    chain_position: str = ""  # server-leaf | server-chain | client


@dataclass
class ZeekExtras:
    """Evidence from the optional supporting logs (all bounded).

    These logs corroborate; none of them substitutes for successful
    conn.log evidence when generating firewall rules.
    """

    #: responder IP -> bounded certificate records
    certificates: Dict[str, List[ZeekCertificate]] = field(default_factory=dict)
    #: IPs Zeek has seen at all (known_hosts.log) - presence only
    known_hosts: List[str] = field(default_factory=list)
    #: "ip/proto/port" -> service names from known_services.log
    known_services: Dict[str, List[str]] = field(default_factory=dict)
    #: IP -> bounded software observations (never treated as vulnerabilities)
    software: Dict[str, List[str]] = field(default_factory=dict)
    #: bounded file-transfer metadata (no contents, no full paths)
    file_transfers: List[Dict[str, object]] = field(default_factory=list)
    #: bounded notice.log entries surfaced as review findings
    notices: List[Dict[str, str]] = field(default_factory=list)
    #: weird.log anomaly name -> count, plus bounded per-endpoint samples
    weird_counts: Dict[str, int] = field(default_factory=dict)
    weird_samples: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class ZeekSensorHealth:
    """Passive-sensor quality assessment for the collection window."""

    status: str = "unknown"  # healthy | degraded | unknown | unusable
    capture_loss_available: bool = False
    max_capture_loss_percent: float = 0.0
    capture_loss_samples: int = 0
    aggregates_with_missed_bytes: int = 0
    total_missed_bytes: int = 0
    reporter_errors: List[str] = field(default_factory=list)
    reporter_warnings: List[str] = field(default_factory=list)
    malformed_records: int = 0
    missing_logs: List[str] = field(default_factory=list)
    observation_start: str = ""
    observation_end: str = ""
    notes: List[str] = field(default_factory=list)


@dataclass
class EndpointIdentity:
    """One endpoint in the unified inventory.

    The IP address is the primary identity.  Service-endpoint names (HTTP
    hosts, TLS SNI, certificate identities) are stored separately from the
    device hostname and never replace it.
    """

    ip: str = ""
    display_name: str = ""
    device_hostname: str = ""
    device_hostname_source: str = ""  # configuration | nmap | dhcp | dns | ip
    zone: str = "Unknown"
    observation_source: str = ""  # Nmap scanned | Zeek observed | Nmap and Zeek | Configuration only | External
    external: bool = False
    dns_aliases: List[str] = field(default_factory=list)
    dhcp_hostname: str = ""
    http_hosts: List[str] = field(default_factory=list)
    tls_server_names: List[str] = field(default_factory=list)
    certificate_identities: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    alias_evidence: List[str] = field(default_factory=list)
    # v1.2.1 supporting evidence from the optional logs. None of these
    # establish an open service or a dependency on their own.
    certificate_details: List[str] = field(default_factory=list)
    software: List[str] = field(default_factory=list)
    known_services: List[str] = field(default_factory=list)
    seen_in_known_hosts: bool = False


@dataclass
class CorrelationFinding:
    """A neutral discrepancy or noteworthy correlation observation."""

    finding_id: str = ""
    category: str = ""
    source: str = ""
    destination: str = ""
    protocol: str = ""
    port: str = ""
    detail: str = ""
    evidence: str = ""
    recommendation: str = ""
    correlation_status: str = ""
