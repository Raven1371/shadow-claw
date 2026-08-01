"""Correlate Zeek observations with Nmap results and configuration.

The rule here is *merge, never discard*: identical canonical communications
from different evidence sources are combined with all supporting evidence
preserved, while communications that merely share a destination (e.g. the
Nmap scanner's probe vs. a production client's traffic) are kept separate
because their sources differ.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .config import AnalyzerConfig
from .pluralize import count_noun, plural
from .models import (
    EvidenceClass,
    Flow,
    Host,
    ManualReviewItem,
    ServiceRecord,
    compose_flow_evidence,
)
from .zeek_models import (
    CORR_ATTEMPTED_ONLY,
    CORR_CONFLICTING,
    CORR_INFERRED_ONLY,
    CORR_NMAP_AND_ZEEK,
    CORR_NMAP_ONLY,
    CORR_USER_AND_ZEEK,
    CORR_USER_ONLY,
    CORR_ZEEK_ONLY,
    SOURCE_INFERENCE,
    SOURCE_NMAP,
    SOURCE_USER,
    SOURCE_ZEEK,
    CorrelationFinding,
    EndpointIdentity,
    ZeekExtras,
    ZeekFlowAggregate,
    ZeekInputMetadata,
    ZeekSensorHealth,
)

LOG = logging.getLogger(__name__)

NOT_OBSERVED_TEXT = "Not observed during the Zeek collection window"
SCANNER_OBSERVATION_TEXT = "scanner-generated traffic observed by sensor"
SCANNER_ONLY_TEXT = (
    "Observed only in scanner-generated traffic; no non-scanner production "
    "traffic observed during the Zeek collection window"
)
AUTHORIZATION_NOTE = (
    "Observed traffic does not independently establish business authorization."
)

# ---------------------------------------------------------------------------
# Confidence policy (v1.2.1, defect 3)
# ---------------------------------------------------------------------------

#: Starting confidence for a Zeek flow whose connections succeeded.
ZEEK_BASE_CONFIDENCE = 85
#: Starting confidence for a Zeek flow with no successful connections.
ZEEK_ATTEMPTED_CONFIDENCE = 30
#: Deterministic penalties. A passive sensor that is losing packets or
#: reporting content gaps saw less than it claims, so every observation it
#: produced is worth proportionally less as evidence.
CONFIDENCE_PENALTIES = {
    "global_sensor_degraded": 10,   # sensor-wide degradation (loss/errors)
    "aggregate_missed_bytes": 10,   # content gap inside this exact flow
    "capture_loss_over_threshold": 5,  # measured loss above configured limit
    "partial_observation": 15,      # midstream/partial connection evidence
    "ambiguous_observation": 20,    # documented-but-ambiguous conn states
    "sensor_unusable": 30,          # sensor data cannot be trusted at all
}
#: Displayed confidence is always clamped into this range.
MIN_CONFIDENCE = 20
MAX_CONFIDENCE = 100

#: Deterministic evidence-source ordering used everywhere (defect 5).
EVIDENCE_SOURCE_ORDER = [SOURCE_NMAP, SOURCE_ZEEK, SOURCE_USER, SOURCE_INFERENCE]


def order_evidence_sources(sources) -> List[str]:
    """Return evidence sources de-duplicated in the canonical order.

    Any unrecognized source is preserved (sorted) after the known ones so
    merging never silently drops provenance.
    """
    unique = set(sources)
    ordered = [s for s in EVIDENCE_SOURCE_ORDER if s in unique]
    ordered += sorted(unique - set(EVIDENCE_SOURCE_ORDER))
    return ordered


def add_evidence_source(flow, source: str) -> None:
    """Add one provenance entry and re-apply the canonical ordering."""
    flow.evidence_sources = order_evidence_sources(
        list(flow.evidence_sources) + [source]
    )


def compute_zeek_confidence(agg, health, zeek_cfg=None):
    """Confidence for a Zeek-derived flow, with the reasons it was reduced.

    Returns ``(confidence, reasons)``. This is the single place where Zeek
    observation quality becomes a number: sensor-wide degradation, content
    gaps in this particular aggregate, capture loss above the configured
    threshold, and partial/ambiguous connection evidence each subtract a
    fixed, documented amount. The result is clamped to
    [MIN_CONFIDENCE, MAX_CONFIDENCE] so a heavily degraded observation is
    devalued but never discarded.
    """
    reasons: List[str] = []
    confidence = (
        ZEEK_BASE_CONFIDENCE if agg.successful_count else ZEEK_ATTEMPTED_CONFIDENCE
    )
    status = getattr(health, "status", "unknown")
    if status == "degraded":
        confidence -= CONFIDENCE_PENALTIES["global_sensor_degraded"]
        reasons.append("Zeek sensor health is degraded")
    elif status == "unusable":
        confidence -= CONFIDENCE_PENALTIES["sensor_unusable"]
        reasons.append("Zeek sensor data is unusable")
    if agg.missed_bytes:
        confidence -= CONFIDENCE_PENALTIES["aggregate_missed_bytes"]
        reasons.append(
            f"{count_noun(agg.missed_bytes, 'missed byte')} in this flow "
            "(content gap)"
        )
    if zeek_cfg is not None and getattr(health, "capture_loss_available", False):
        if health.max_capture_loss_percent > zeek_cfg.capture_loss_warning_percent:
            confidence -= CONFIDENCE_PENALTIES["capture_loss_over_threshold"]
            reasons.append(
                f"capture loss {health.max_capture_loss_percent:.2f}% exceeds "
                f"the {zeek_cfg.capture_loss_warning_percent}% threshold"
            )
    if agg.partial_count:
        confidence -= CONFIDENCE_PENALTIES["partial_observation"]
        reasons.append(
            f"{count_noun(agg.partial_count, 'partial/midstream observation')}")
    if agg.ambiguous_count:
        confidence -= CONFIDENCE_PENALTIES["ambiguous_observation"]
        reasons.append(
            f"{count_noun(agg.ambiguous_count, 'ambiguous observation')}")
    confidence = max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, confidence))
    return confidence, reasons


#: Nmap states that contradict successful Zeek traffic to the same service.
CONFLICTING_NMAP_STATES = ("closed", "filtered", "open|filtered")


def conflict_reason(state: str, agg) -> str:
    """Explain an Nmap/Zeek contradiction for a manual-review item."""
    return (
        f"Nmap reported {agg.responder} {agg.protocol}/{agg.responder_port} as "
        f"{state}, but the Zeek sensor observed {agg.successful_count} "
        f"{plural('connection', agg.successful_count)} to it "
        f"({agg.first_seen or 'unknown'} to {agg.last_seen or 'unknown'}). "
        "The active scan and the passive collection cover different times and "
        "different network perspectives, so one observation may be stale or "
        "the path may be filtered asymmetrically. This conflict requires "
        "validation before any rule is written; all rule perspectives derived "
        "from this flow are withheld."
    )


#: Cleartext management/authentication protocols worth a neutral finding.
_CLEARTEXT_PROTOCOLS = {
    ("tcp", 23): "Telnet",
    ("tcp", 21): "FTP (control channel)",
    ("tcp", 80): "HTTP (cleartext web/management)",
    ("tcp", 389): "LDAP (cleartext bind possible)",
    ("udp", 161): "SNMP v1/v2c",
}


@dataclass
class ZeekAnalysis:
    """Bundle of everything the Zeek pipeline produced."""

    metadata: ZeekInputMetadata
    aggregates: List[ZeekFlowAggregate] = field(default_factory=list)
    health: ZeekSensorHealth = field(default_factory=ZeekSensorHealth)
    dns_aliases: Dict[str, List[str]] = field(default_factory=dict)
    dhcp_names: Dict[str, str] = field(default_factory=dict)
    cert_identities: Dict[str, List[str]] = field(default_factory=dict)
    extras: ZeekExtras = field(default_factory=ZeekExtras)


@dataclass
class CorrelationResult:
    flows: List[Flow] = field(default_factory=list)
    findings: List[CorrelationFinding] = field(default_factory=list)
    endpoints: List[EndpointIdentity] = field(default_factory=list)
    external_dependencies: List[ZeekFlowAggregate] = field(default_factory=list)
    attempted: List[ZeekFlowAggregate] = field(default_factory=list)
    reviews: List[ManualReviewItem] = field(default_factory=list)


def _is_external(ip: str, config: AnalyzerConfig) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return False
    nets: List[str] = list(config.zeek.monitored_networks)
    if not nets:
        for cidrs in config.zones.values():
            nets.extend(cidrs)
        nets.extend(config.local_networks)
    if not nets:
        return bool(addr.is_global)
    for entry in nets:
        try:
            net = ipaddress.ip_network(str(entry), strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return False
    return True


def _zone_for(ip: str, config: AnalyzerConfig) -> str:
    if _is_external(ip, config):
        return config.zeek.external_zone_name
    return config.zone_for_ip(str(ip).split("%")[0])


def _merge_zeek_into_flow(flow: Flow, agg: ZeekFlowAggregate,
                          health: ZeekSensorHealth, zeek_cfg=None) -> None:
    """Attach Zeek observation data to an existing flow (evidence merging).

    Confidence is recomputed through the centralized policy so a merged
    flow is devalued by sensor degradation exactly like a new one
    (defect 3): the lower of the flow's prior confidence and the Zeek
    confidence wins, because the combined claim is only as strong as its
    weakest supporting observation.
    """
    if SOURCE_ZEEK not in flow.evidence_sources:
        flow.evidence_sources.append(SOURCE_ZEEK)
    flow.zeek_observation = (
        SCANNER_OBSERVATION_TEXT
        if agg.scanner_traffic else "successful traffic observed"
        if agg.successful_count else "attempted traffic only"
    )
    flow.first_seen = flow.first_seen or agg.first_seen
    if agg.first_seen and agg.first_seen < (flow.first_seen or agg.first_seen):
        flow.first_seen = agg.first_seen
    if agg.last_seen and agg.last_seen > (flow.last_seen or ""):
        flow.last_seen = agg.last_seen
    flow.connection_count += agg.connection_count
    flow.successful_connections += agg.successful_count
    flow.failed_connections += agg.failed_count + agg.rejected_count
    flow.one_way_connections += agg.one_way_count
    flow.partial_connections += agg.partial_count + agg.ambiguous_count
    flow.originator_bytes += agg.originator_bytes
    flow.responder_bytes += agg.responder_bytes
    flow.originator_packets += agg.originator_packets
    flow.responder_packets += agg.responder_packets
    for state in agg.conn_states:
        if state not in flow.zeek_conn_states:
            flow.zeek_conn_states.append(state)
    flow.zeek_conn_states.sort()
    for svc in agg.services:
        if svc not in flow.zeek_services:
            flow.zeek_services.append(svc)
    for uid in agg.sample_uids:
        if uid not in flow.sample_zeek_uids and len(flow.sample_zeek_uids) < 10:
            flow.sample_zeek_uids.append(uid)
    for name in agg.dns_names:
        if name not in flow.dns_names and len(flow.dns_names) < 10:
            flow.dns_names.append(name)
    for name in agg.tls_server_names:
        if name not in flow.tls_server_names and len(flow.tls_server_names) < 10:
            flow.tls_server_names.append(name)
    for name in agg.http_hosts:
        if name not in flow.http_hosts and len(flow.http_hosts) < 10:
            flow.http_hosts.append(name)
    flow.sensor_quality = (
        "degraded" if agg.missed_bytes else health.status
    )
    confidence, reasons = compute_zeek_confidence(agg, health, zeek_cfg)
    if reasons:
        flow.confidence = min(flow.confidence or confidence, confidence)
        flow.confidence_notes = "; ".join(reasons)
    elif not flow.confidence:
        flow.confidence = confidence


class ZeekCorrelator:
    def __init__(
        self,
        hosts: List[Host],
        records: List[ServiceRecord],
        flows: List[Flow],
        config: AnalyzerConfig,
        options,
        zeek: ZeekAnalysis,
    ) -> None:
        self.hosts = hosts
        self.records = records
        self.flows = flows
        self.config = config
        self.options = options
        self.zeek = zeek
        self.result = CorrelationResult(flows=flows)
        self.hosts_by_ip = {h.primary_ip: h for h in hosts}
        #: (ip, proto, port) -> ServiceRecord (any state)
        self.services: Dict[Tuple[str, str, int], ServiceRecord] = {
            (r.ip, r.protocol, r.port): r for r in records
        }
        #: canonical (src, dst, proto, port) -> flows (all perspectives)
        self.flow_index: Dict[Tuple, List[Flow]] = {}
        for flow in flows:
            self.flow_index.setdefault(
                (flow.source, flow.destination, flow.protocol, flow.destination_port),
                [],
            ).append(flow)
        # Defect 4: a service touched only by the Nmap scanner's own probes
        # must never be reported as production traffic, and must never be
        # filed under a plain "not observed" heading either.
        self._services_any_traffic: set = set()
        self._services_non_scanner_traffic: set = set()
        self._touched_services: set = set()
        self._icmp_review_added = False

    # -- findings helpers ---------------------------------------------------

    def _finding(self, category: str, agg: Optional[ZeekFlowAggregate],
                 detail: str, recommendation: str,
                 correlation_status: str = "", source: str = "",
                 destination: str = "", protocol: str = "", port: str = "") -> None:
        self.result.findings.append(
            CorrelationFinding(
                category=category,
                source=source or (agg.originator if agg else ""),
                destination=destination or (agg.responder if agg else ""),
                protocol=protocol or (agg.protocol if agg else ""),
                port=port or (str(agg.responder_port) if agg else ""),
                detail=detail,
                evidence=(
                    f"Zeek: {agg.successful_count} successful / "
                    f"{agg.connection_count} total "
                    f"{plural('connection', agg.connection_count)}, states "
                    f"{','.join(agg.conn_states) or '-'}" if agg else ""
                ),
                recommendation=recommendation,
                correlation_status=correlation_status,
            )
        )

    def _review(self, category: str, agg: ZeekFlowAggregate, finding: str,
                reason: str, recommendation: str) -> None:
        self.result.reviews.append(
            ManualReviewItem(
                category=category,
                host=agg.responder,
                ip=agg.responder,
                protocol=agg.protocol,
                port=str(agg.responder_port),
                finding=finding,
                reason=reason,
                recommendation=recommendation,
            )
        )

    # -- per-aggregate handling ---------------------------------------------

    def _nmap_state(self, agg: ZeekFlowAggregate) -> Tuple[str, Optional[ServiceRecord]]:
        """('open'|'closed'|'filtered'|'open|filtered'|'not scanned'|'out of scope', record)."""
        record = self.services.get((agg.responder, agg.protocol, agg.responder_port))
        if record is not None:
            return record.state, record
        if agg.responder in self.hosts_by_ip:
            return "not scanned", None  # host scanned, port not reported
        if _is_external(agg.responder, self.config):
            return "out of scope", None
        return "not scanned", None

    def _new_zeek_flow(self, agg: ZeekFlowAggregate, direction: str,
                       perspective: str, status: str, nmap_obs: str) -> Flow:
        src_host = self.hosts_by_ip.get(agg.originator)
        dst_host = self.hosts_by_ip.get(agg.responder)
        service = (agg.services[0].upper() if agg.services
                   else ("ICMP" if agg.protocol == "icmp" else "Unknown"))
        flow = Flow(
            source_name=src_host.display_name if src_host else agg.originator,
            source=agg.originator,
            source_zone=(src_host.zone if src_host else _zone_for(agg.originator, self.config)),
            destination_name=dst_host.display_name if dst_host else agg.responder,
            destination=agg.responder,
            destination_zone=(dst_host.zone if dst_host else _zone_for(agg.responder, self.config)),
            ip_version=agg.ip_version,
            protocol=agg.protocol,
            destination_port=agg.responder_port,
            normalized_service=service,
            direction=direction,
            perspective=perspective,
            evidence_class=EvidenceClass.OBSERVED.value,
            evidence=(
                f"Zeek sensor observed {agg.successful_count} successful "
                f"{plural('connection', agg.successful_count)} "
                f"({agg.connection_count} total) from "
                f"{agg.originator} to {agg.responder} "
                f"{agg.protocol}/{agg.responder_port} between "
                f"{agg.first_seen or 'unknown'} and {agg.last_seen or 'unknown'}. "
                + AUTHORIZATION_NOTE
            ),
            confidence=compute_zeek_confidence(
                agg, self.zeek.health, self.config.zeek
            )[0],
            recommended_action=(
                "Confirm business authorization with the system owner; "
                "observed traffic alone is not approval"
            ),
            source_xml_host=agg.originator,
            service_evidence=EvidenceClass.OBSERVED.value,
            source_scope_evidence=EvidenceClass.OBSERVED.value,
            destination_scope_evidence=EvidenceClass.OBSERVED.value,
            correlation_status=status,
            nmap_observation=nmap_obs,
        )
        flow.evidence_sources = order_evidence_sources(
            [SOURCE_ZEEK, SOURCE_NMAP] if nmap_obs.startswith(
                ("service open", "port reported")
            ) else [SOURCE_ZEEK]
        )
        _merge_zeek_into_flow(flow, agg, self.zeek.health, self.config.zeek)
        confidence, reasons = compute_zeek_confidence(
            agg, self.zeek.health, self.config.zeek
        )
        flow.confidence = confidence
        flow.confidence_notes = "; ".join(reasons)
        if reasons:
            flow.evidence += (
                " Confidence reduced to "
                f"{confidence}: {'; '.join(reasons)}."
            )
        flow.flow_evidence = compose_flow_evidence(
            flow.service_evidence, flow.source_scope_evidence,
            flow.destination_scope_evidence,
        )
        return flow

    def _emit_zeek_flows(self, agg: ZeekFlowAggregate, status: str,
                         nmap_obs: str, review_reason: str = "") -> None:
        rg = self.config.rule_generation
        emitted: List[Flow] = []
        if rg.enforcement_model == "network_only":
            emitted.append(self._new_zeek_flow(agg, "inbound", "network", status, nmap_obs))
        else:
            if rg.generate_source_outbound:
                emitted.append(self._new_zeek_flow(agg, "outbound", "source-outbound", status, nmap_obs))
            if rg.generate_destination_inbound:
                emitted.append(self._new_zeek_flow(agg, "inbound", "destination-inbound", status, nmap_obs))
        for flow in emitted:
            if review_reason:
                flow.manual_review_reason = review_reason
            self.flows.append(flow)
            self.flow_index.setdefault(
                (flow.source, flow.destination, flow.protocol, flow.destination_port),
                [],
            ).append(flow)

    def _register_conflict(self, agg: ZeekFlowAggregate, state: str) -> None:
        """Record the finding and manual-review item for an Nmap/Zeek conflict."""
        self._finding(
            "Correlation discrepancy", agg,
            f"Zeek observed successful traffic to a port Nmap reported "
            f"{state}. The scan and the collection window may cover "
            "different times, or filtering may be asymmetric.",
            "Reconcile the scan time with the Zeek window; verify current "
            "port state before acting",
            correlation_status=CORR_CONFLICTING,
        )
        self._review(
            "Correlation discrepancy", agg,
            f"Zeek traffic to {agg.responder} "
            f"{agg.protocol}/{agg.responder_port} which Nmap reported {state}",
            conflict_reason(state, agg),
            "Verify which observation reflects current state before "
            "writing a rule; all derived rule perspectives are withheld",
        )

    def _note_service_traffic(self, agg: ZeekFlowAggregate) -> None:
        key = (agg.responder, agg.protocol, agg.responder_port)
        self._touched_services.add(key)
        self._services_any_traffic.add(key)
        if not agg.scanner_traffic:
            self._services_non_scanner_traffic.add(key)

    def _handle_successful(self, agg: ZeekFlowAggregate) -> None:
        key = agg.key
        existing = self.flow_index.get(key, [])
        state, record = self._nmap_state(agg)
        self._note_service_traffic(agg)

        if existing:
            # Defect 1 (v1.2.1): a flow that already exists - declared in
            # configuration, inferred, or Nmap-derived - is NOT exempt from
            # the Nmap destination-state check. The conflict evaluation below
            # runs before this branch returns, for every prior evidence class.
            conflicting = state in CONFLICTING_NMAP_STATES
            for flow in existing:
                prior = flow.evidence_class
                _merge_zeek_into_flow(flow, agg, self.zeek.health,
                                      self.config.zeek)
                if prior == EvidenceClass.USER_DEFINED.value:
                    flow.correlation_status = CORR_USER_AND_ZEEK
                    add_evidence_source(flow, SOURCE_USER)
                    flow.evidence += (
                        "; Zeek observed this declared dependency in actual traffic"
                    )
                    flow.evidence_class = EvidenceClass.OBSERVED.value
                    flow.service_evidence = EvidenceClass.OBSERVED.value
                    flow.flow_evidence = compose_flow_evidence(
                        flow.service_evidence, flow.source_scope_evidence,
                        flow.destination_scope_evidence,
                    )
                elif prior == EvidenceClass.INFERRED.value:
                    add_evidence_source(flow, SOURCE_INFERENCE)
                    flow.correlation_status = (
                        CORR_NMAP_AND_ZEEK if state == "open" else CORR_ZEEK_ONLY
                    )
                    flow.evidence += "; corroborated by Zeek-observed traffic"
                else:
                    add_evidence_source(flow, SOURCE_NMAP)
                    flow.correlation_status = CORR_NMAP_AND_ZEEK
                if state == "open":
                    # Defect 5: Nmap corroborated the destination service, so
                    # it belongs in the provenance whatever the primary
                    # correlation status is.
                    flow.nmap_observation = "service open (Nmap)"
                    add_evidence_source(flow, SOURCE_NMAP)
                elif conflicting:
                    # Contradictory active-scan evidence: keep the flow (it
                    # was really observed) but withhold every rule
                    # perspective derived from it.
                    flow.correlation_status = CORR_CONFLICTING
                    flow.nmap_observation = f"port reported {state} (Nmap)"
                    add_evidence_source(flow, SOURCE_NMAP)
                    flow.manual_review_reason = conflict_reason(state, agg)
                elif state == "not scanned":
                    flow.nmap_observation = "not scanned (Nmap)"
                elif state == "out of scope":
                    flow.nmap_observation = "outside Nmap scope"
            if self.zeek.health.status == "unusable":
                for flow in existing:
                    flow.manual_review_reason = (
                        flow.manual_review_reason
                        or "Zeek sensor data is unusable; corroboration "
                        "cannot support a candidate rule without manual review"
                    )
            if conflicting:
                self._register_conflict(agg, state)
            if record is not None and agg.scanner_traffic is False:
                record.zeek_observation = "active traffic observed"
                record.correlation_status = CORR_NMAP_AND_ZEEK
            return

        # No existing flow with this exact source: never merge into a flow
        # from a different originator; create the Zeek flow itself.
        nmap_obs = ""
        status = CORR_ZEEK_ONLY
        review_reason = ""
        if state == "open":
            status = CORR_NMAP_AND_ZEEK
            nmap_obs = "service open (Nmap)"
            if record is not None:
                record.zeek_observation = "active traffic observed"
                record.correlation_status = CORR_NMAP_AND_ZEEK
        elif state in CONFLICTING_NMAP_STATES:
            status = CORR_CONFLICTING
            nmap_obs = f"port reported {state} (Nmap)"
            self._register_conflict(agg, state)
            review_reason = conflict_reason(state, agg)
        elif state == "out of scope":
            nmap_obs = "outside Nmap scope"
            external = _is_external(agg.responder, self.config)
            if external:
                self.result.external_dependencies.append(agg)
                self._finding(
                    "External dependency", agg,
                    f"{agg.originator} communicates with external endpoint "
                    f"{agg.responder} {agg.protocol}/{agg.responder_port}"
                    + (f" ({', '.join(agg.tls_server_names[:3])})"
                       if agg.tls_server_names else ""),
                    "Confirm the external dependency is expected and approved",
                    correlation_status=CORR_ZEEK_ONLY,
                )
                if not self.config.zeek.include_external_dependencies_in_rules:
                    review_reason = (
                        "External dependency; candidate rules disabled by "
                        "zeek.include_external_dependencies_in_rules"
                    )
        else:  # not scanned
            nmap_obs = "not scanned (Nmap)"
            self._finding(
                "Unscanned dependency", agg,
                f"Zeek observed traffic to {agg.responder} "
                f"{agg.protocol}/{agg.responder_port}, which was not covered "
                "by the Nmap scan",
                "Include the destination in a future scan scope to corroborate",
                correlation_status=CORR_ZEEK_ONLY,
            )

        if self.zeek.health.status == "unusable" and not review_reason:
            # Defect 3: observations from a sensor we cannot trust are kept
            # in the report but may never become rules unreviewed.
            review_reason = (
                "Zeek sensor data is unusable; observed traffic is reported "
                "but cannot support a candidate rule without manual review"
            )
        if agg.protocol == "icmp":
            review_reason = "ICMP policy decisions require manual review"
            if not self._icmp_review_added:
                self._icmp_review_added = True
                self._review(
                    "ICMP policy", agg,
                    "ICMP traffic observed by the Zeek sensor",
                    "ICMP type/code are not transport ports; no port-based "
                    "rule is generated",
                    "Decide ICMP policy (echo, PMTUD, unreachables) manually",
                )
        if agg.missed_bytes and not review_reason:
            # Degraded observation lowers confidence but keeps the flow.
            pass
        self._emit_zeek_flows(agg, status, nmap_obs, review_reason)

        # Neutral cleartext-protocol finding.
        label = _CLEARTEXT_PROTOCOLS.get((agg.protocol, agg.responder_port))
        if label:
            self._finding(
                "Cleartext protocol", agg,
                f"{label} traffic observed from {agg.originator} to "
                f"{agg.responder}",
                "Prefer an encrypted equivalent or restrict scope",
            )

    def _handle_attempted(self, agg: ZeekFlowAggregate) -> None:
        self.result.attempted.append(agg)
        self._note_service_traffic(agg)
        if agg.rejected_count + agg.failed_count >= 10:
            self._finding(
                "Excessive failed attempts", agg,
                f"{agg.rejected_count + agg.failed_count} failed/rejected "
                f"attempt(s) from {agg.originator} to {agg.responder} "
                f"{agg.protocol}/{agg.responder_port}",
                "Investigate whether this is misconfiguration, a broken "
                "dependency, or probing",
            )
        if self.config.zeek.include_attempted_flows_in_diagram:
            flow = self._new_zeek_flow(
                agg, "inbound", "destination-inbound",
                CORR_ATTEMPTED_ONLY, "",
            )
            flow.evidence_class = EvidenceClass.MANUAL_REVIEW.value
            flow.service_evidence = EvidenceClass.MANUAL_REVIEW.value
            flow.flow_evidence = EvidenceClass.MANUAL_REVIEW.value
            flow.manual_review_reason = (
                "Attempted/unsuccessful traffic only; never a candidate rule"
            )
            flow.zeek_observation = "attempted traffic only"
            self.flows.append(flow)

    # -- passes over existing data -------------------------------------------

    def _annotate_uncorrelated(self) -> None:
        for flow in self.flows:
            if flow.correlation_status:
                continue
            if flow.evidence_class == EvidenceClass.USER_DEFINED.value:
                flow.correlation_status = CORR_USER_ONLY
                flow.zeek_observation = NOT_OBSERVED_TEXT
                if SOURCE_USER not in flow.evidence_sources:
                    flow.evidence_sources.append(SOURCE_USER)
            elif flow.evidence_class == EvidenceClass.INFERRED.value:
                flow.correlation_status = CORR_INFERRED_ONLY
                flow.zeek_observation = NOT_OBSERVED_TEXT
                if SOURCE_INFERENCE not in flow.evidence_sources:
                    flow.evidence_sources.append(SOURCE_INFERENCE)
            elif flow.evidence_class == EvidenceClass.OBSERVED.value:
                flow.correlation_status = CORR_NMAP_ONLY
                flow.zeek_observation = NOT_OBSERVED_TEXT
                if SOURCE_NMAP not in flow.evidence_sources:
                    flow.evidence_sources.append(SOURCE_NMAP)

        seen_defined = set()
        for flow in self.flows:
            if flow.correlation_status == CORR_USER_ONLY:
                key = (flow.source, flow.destination, flow.protocol,
                       flow.destination_port)
                if key in seen_defined:
                    continue
                seen_defined.add(key)
                self._finding(
                    "Declared dependency not observed", None,
                    f"Configured flow {flow.source} -> {flow.destination} "
                    f"{flow.protocol}/{flow.destination_port} was "
                    + NOT_OBSERVED_TEXT.lower(),
                    "Confirm the dependency is still current; absence of "
                    "traffic in this window is not proof it is unnecessary",
                    correlation_status=CORR_USER_ONLY,
                    source=flow.source, destination=flow.destination,
                    protocol=flow.protocol, port=str(flow.destination_port),
                )

    def _annotate_nmap_only_services(self) -> None:
        """Annotate Nmap-open services with their true observation state.

        Three distinct states are reported (defect 4): no Zeek traffic at
        all, scanner-generated traffic only, and genuine non-scanner
        traffic. Only the first belongs under a plain "not observed"
        heading; scanner probes are never production evidence.
        """
        for record in self.records:
            if record.state != "open":
                continue
            key = (record.ip, record.protocol, record.port)
            record.any_zeek_traffic_observed = key in self._services_any_traffic
            record.non_scanner_zeek_traffic_observed = (
                key in self._services_non_scanner_traffic
            )
            record.scanner_only_zeek_traffic_observed = (
                record.any_zeek_traffic_observed
                and not record.non_scanner_zeek_traffic_observed
            )
            if record.non_scanner_zeek_traffic_observed:
                continue  # already annotated as corroborated
            if record.scanner_only_zeek_traffic_observed:
                record.zeek_observation = SCANNER_ONLY_TEXT
                record.correlation_status = CORR_NMAP_ONLY
                self._finding(
                    "Exposed service with scanner-only traffic", None,
                    f"Nmap found {record.normalized_service} open on "
                    f"{record.ip} {record.protocol}/{record.port}. The only "
                    "traffic the sensor saw to it was generated by the Nmap "
                    "scanner itself, which is not production usage.",
                    "Treat this as no production evidence: do NOT call it "
                    "unused, and do NOT treat the scan traffic as a "
                    "dependency. Confirm with the system owner or a longer "
                    "collection window",
                    correlation_status=CORR_NMAP_ONLY,
                    destination=record.ip, protocol=record.protocol,
                    port=str(record.port),
                )
                continue
            record.zeek_observation = NOT_OBSERVED_TEXT
            record.correlation_status = CORR_NMAP_ONLY
            self._finding(
                "Exposed service without observed traffic", None,
                f"Nmap found {record.normalized_service} open on {record.ip} "
                f"{record.protocol}/{record.port}, but no traffic to it was "
                "observed during the Zeek collection window",
                "Do NOT treat this as unused; the window may simply not "
                "cover its clients. Verify with a longer window or owner "
                "confirmation",
                correlation_status=CORR_NMAP_ONLY,
                destination=record.ip, protocol=record.protocol,
                port=str(record.port),
            )

    def _service_conflicts(self) -> None:
        for agg in self.zeek.aggregates:
            record = self.services.get(
                (agg.responder, agg.protocol, agg.responder_port)
            )
            if record is None or not agg.services:
                continue
            zeek_names = {s.lower() for s in agg.services}
            nmap_name = (record.normalized_service or "").lower()
            base = nmap_name.split(" ")[0].split("/")[0]
            synonyms = {
                "ssl": {"https", "tls", "ssl", "imaps", "pop3s", "smtps", "ldaps"},
                "quic": {"https", "http/3", "quic"},
                "dns": {"domain", "dns"},
                "krb": {"kerberos"}, "krb_tcp": {"kerberos"},
                "dce-rpc": {"msrpc", "ms rpc", "epmap"},
                "smb": {"microsoft-ds", "smb", "netbios-ssn", "cifs"},
                "gssapi": {"kerberos", "ldap", "microsoft-ds", "smb"},
                "ntlm": {"microsoft-ds", "smb", "ntlm"},
                "postgresql": {"postgresql", "postgres"},
                "http": {"http", "www", "http-alt"},
            }
            def _matches(z: str) -> bool:
                if base in z or z in base or z in nmap_name:
                    return True
                return any(base in s or s in nmap_name for s in synonyms.get(z, ()))
            if base and zeek_names and not any(_matches(z) for z in zeek_names):
                self._finding(
                    "Service identification conflict", agg,
                    f"Zeek identified {'/'.join(sorted(agg.services))} on "
                    f"{agg.responder} {agg.protocol}/{agg.responder_port} "
                    f"while Nmap detected {record.normalized_service}",
                    "Determine which application is genuinely running "
                    "before writing a rule",
                )

    def _endpoint_inventory(self) -> None:
        info: Dict[str, EndpointIdentity] = {}

        def _get(ip: str) -> EndpointIdentity:
            if ip not in info:
                info[ip] = EndpointIdentity(ip=ip, zone=_zone_for(ip, self.config))
            return info[ip]

        for host in self.hosts:
            ep = _get(host.primary_ip)
            ep.observation_source = "Nmap scanned"
            if host.display_name and host.display_name != host.primary_ip:
                ep.device_hostname = host.display_name
                ep.device_hostname_source = "nmap"
        for ip, host_cfg in self.config.hosts.items():
            ep = _get(ip)
            if host_cfg.hostname:
                ep.device_hostname = host_cfg.hostname
                ep.device_hostname_source = "configuration"
            if not ep.observation_source:
                ep.observation_source = "Configuration only"
        zeek_ips = set()
        for agg in self.zeek.aggregates:
            for ip in (agg.originator, agg.responder):
                zeek_ips.add(ip)
                ep = _get(ip)
                if agg.first_seen and (not ep.first_seen or agg.first_seen < ep.first_seen):
                    ep.first_seen = agg.first_seen
                if agg.last_seen and agg.last_seen > ep.last_seen:
                    ep.last_seen = agg.last_seen
            resp = _get(agg.responder)
            for name in agg.tls_server_names:
                if name not in resp.tls_server_names and len(resp.tls_server_names) < 10:
                    resp.tls_server_names.append(name)
            for name in agg.http_hosts:
                if name not in resp.http_hosts and len(resp.http_hosts) < 10:
                    resp.http_hosts.append(name)
        for ip, aliases in self.zeek.dns_aliases.items():
            ep = _get(ip)
            for alias in aliases:
                if alias not in ep.dns_aliases and len(ep.dns_aliases) < 10:
                    ep.dns_aliases.append(alias)
                    ep.alias_evidence.append(f"dns:{alias}")
        for ip, name in self.zeek.dhcp_names.items():
            ep = _get(ip)
            ep.dhcp_hostname = name
            ep.alias_evidence.append(f"dhcp:{name}")
        extras = self.zeek.extras
        for ip, certs in extras.certificates.items():
            ep = _get(ip)
            for cert in certs:
                summary = "; ".join(filter(None, [
                    f"subject={cert.subject}" if cert.subject else "",
                    f"issuer={cert.issuer}" if cert.issuer else "",
                    f"serial={cert.serial}" if cert.serial else "",
                    f"valid={cert.not_valid_before}..{cert.not_valid_after}"
                    if cert.not_valid_before or cert.not_valid_after else "",
                    f"key={cert.key_algorithm} {cert.key_length}".strip()
                    if cert.key_algorithm else "",
                    f"sig={cert.signature_algorithm}"
                    if cert.signature_algorithm else "",
                    f"chain={cert.chain_position}" if cert.chain_position else "",
                    f"fuid={cert.fuid}" if cert.fuid else "",
                ]))
                if summary and summary not in ep.certificate_details \
                        and len(ep.certificate_details) < 5:
                    ep.certificate_details.append(summary)
                if cert.subject and cert.subject not in ep.certificate_identities \
                        and len(ep.certificate_identities) < 10:
                    ep.certificate_identities.append(cert.subject)
        for ip, names in extras.software.items():
            ep = _get(ip)
            for name in names[:10]:
                if name not in ep.software:
                    ep.software.append(name)
        for ip in extras.known_hosts:
            _get(ip).seen_in_known_hosts = True
        for key, services in extras.known_services.items():
            ip = key.split("/")[0]
            ep = _get(ip)
            label = f"{key.split('/', 1)[1]} ({', '.join(services)})" if services \
                else key.split("/", 1)[1]
            if label not in ep.known_services and len(ep.known_services) < 20:
                ep.known_services.append(label)
        for ip, subjects in self.zeek.cert_identities.items():
            ep = _get(ip)
            for subject in subjects:
                if subject not in ep.certificate_identities and len(ep.certificate_identities) < 10:
                    ep.certificate_identities.append(subject)

        for ip, ep in info.items():
            in_nmap = ip in self.hosts_by_ip
            in_zeek = ip in zeek_ips
            if ep.external is False and _is_external(ip, self.config):
                ep.external = True
            if in_nmap and in_zeek:
                ep.observation_source = "Nmap and Zeek"
            elif in_zeek and not in_nmap:
                ep.observation_source = "External" if ep.external else "Zeek observed"
            # Display-name precedence: config > nmap > dhcp > dns > ip.
            # (Service names — HTTP hosts / TLS SNI — never become the
            # device identity.)
            if not ep.device_hostname:
                if ep.dhcp_hostname:
                    ep.device_hostname = ep.dhcp_hostname
                    ep.device_hostname_source = "dhcp"
                elif ep.dns_aliases:
                    ep.device_hostname = ep.dns_aliases[0]
                    ep.device_hostname_source = "dns"
            ep.display_name = ep.device_hostname or ip
            if not ep.device_hostname_source:
                ep.device_hostname_source = "ip"
        self.result.endpoints = sorted(info.values(), key=lambda e: e.ip)

    def _supporting_log_findings(self) -> None:
        """Surface notice.log and weird.log as neutral review findings.

        A Zeek notice is an alert worth a human look, not a confirmed
        vulnerability; a "weird" is a protocol anomaly, not proof of
        compromise. Both are reported in those terms and capped.
        """
        extras = self.zeek.extras
        for notice in extras.notices[:25]:
            self.result.findings.append(
                CorrelationFinding(
                    category="Zeek notice",
                    source=notice.get("source", ""),
                    destination=notice.get("destination", ""),
                    protocol=notice.get("protocol", ""),
                    port=notice.get("port", ""),
                    detail=(
                        f"Zeek notice {notice.get('note', 'unknown')}: "
                        f"{notice.get('message', '')}"
                    ),
                    evidence="notice.log",
                    recommendation=(
                        "Review the notice in context; a notice is an alert "
                        "for human assessment, not a confirmed vulnerability"
                    ),
                    correlation_status=CORR_ZEEK_ONLY,
                )
            )
        if extras.weird_counts:
            top = sorted(extras.weird_counts.items(),
                         key=lambda kv: (-kv[1], kv[0]))[:5]
            summary = ", ".join(f"{name} x{count}" for name, count in top)
            self.result.findings.append(
                CorrelationFinding(
                    category="Protocol anomalies",
                    detail=(
                        f"weird.log recorded "
                        f"{count_noun(sum(extras.weird_counts.values()), 'protocol anomaly')} "
                        f"across {count_noun(len(extras.weird_counts), 'type')}. "
                        f"Most frequent: {summary}"
                    ),
                    evidence="weird.log",
                    recommendation=(
                        "Protocol anomalies often indicate asymmetric routing, "
                        "truncation, or sensor placement issues rather than "
                        "compromise; interpret alongside sensor health"
                    ),
                    correlation_status=CORR_ZEEK_ONLY,
                )
            )

    def _sensor_reviews(self) -> None:
        health = self.zeek.health
        cfg = self.config.zeek
        if (health.capture_loss_available
                and health.max_capture_loss_percent > cfg.capture_loss_warning_percent):
            self.result.reviews.append(
                ManualReviewItem(
                    category="Zeek sensor health",
                    host=cfg.sensor_name or "zeek sensor",
                    finding=(
                        f"Capture loss reached "
                        f"{health.max_capture_loss_percent:.2f}%, above the "
                        f"configured {cfg.capture_loss_warning_percent}% threshold"
                    ),
                    reason="Passive observations may be incomplete; absence "
                    "of a flow is weaker evidence than usual",
                    recommendation="Investigate sensor capacity/placement and "
                    "re-collect if practical",
                )
            )
        if health.status == "degraded":
            self._finding(
                "Sensor degradation", None,
                "Zeek sensor health is degraded ("
                + "; ".join(health.notes[:2]) + ")",
                "Treat Zeek-derived confidence as reduced; observed flows "
                "are preserved",
            )

    # -- main ---------------------------------------------------------------

    def run(self) -> CorrelationResult:
        for agg in self.zeek.aggregates:
            if agg.ignored_by_config:
                continue  # counted in input statistics only
            if agg.scanner_traffic and self.config.zeek.exclude_nmap_scanner_traffic_from_rules:
                # Preserve for correlation/audit: merge into the matching
                # scanner-sourced Nmap flow when present, never into
                # production evidence, and never into new rules.
                self._note_service_traffic(agg)  # scanner-only unless a
                # non-scanner aggregate also touches this service
                for flow in self.flow_index.get(agg.key, []):
                    _merge_zeek_into_flow(flow, agg, self.zeek.health,
                                          self.config.zeek)
                    flow.correlation_status = CORR_NMAP_AND_ZEEK
                    flow.zeek_observation = SCANNER_OBSERVATION_TEXT
                    if SOURCE_NMAP not in flow.evidence_sources:
                        flow.evidence_sources.insert(0, SOURCE_NMAP)
                continue
            if agg.protocol not in ("tcp", "udp", "icmp"):
                continue
            eligible = (
                agg.successful_count >= max(1, self.config.zeek.minimum_successful_connections_for_rule)
                and agg.success_ratio >= self.config.zeek.minimum_success_ratio_for_rule
            )
            if agg.protocol == "icmp":
                eligible = agg.connection_count > 0  # observed flow, never a rule
            if eligible:
                self._handle_successful(agg)
            else:
                self._handle_attempted(agg)

        self._annotate_uncorrelated()
        self._annotate_nmap_only_services()
        self._service_conflicts()
        self._endpoint_inventory()
        self._supporting_log_findings()
        self._sensor_reviews()
        for index, finding in enumerate(
            sorted(
                self.result.findings,
                key=lambda f: (f.category, f.destination, f.protocol, f.port, f.source),
            ),
            start=1,
        ):
            finding.finding_id = f"CF-{index:04d}"
        self.result.findings.sort(key=lambda f: f.finding_id)
        return self.result


def communication_key(item) -> tuple:
    """Canonical identity of one observed communication (defect 6).

    Identity is (originator, responder, transport, responder port). Firewall
    perspectives (destination-inbound / source-outbound / network) of the
    same communication collapse to a single key, so perspective counts can
    never inflate the number of communications reported.
    """
    if hasattr(item, "originator"):  # ZeekFlowAggregate
        return (item.originator, item.responder, item.protocol,
                item.responder_port)
    return (item.source, item.destination, item.protocol,
            item.destination_port)


def supported_by_nmap_and_zeek(flow) -> bool:
    """True when a flow's evidence_sources include BOTH nmap and zeek.

    This is an evidence-overlap question, distinct from the primary
    correlation_status (issue 3, v1.2.2). A declared dependency that Nmap
    confirmed open and Zeek observed keeps its primary status
    user-defined-and-zeek while still being supported by both tools, and
    must be counted as such. Scanner-only observations are excluded: the
    scanner's own probes are scan-audit evidence, not production
    corroboration.
    """
    sources = set(getattr(flow, "evidence_sources", ()) or ())
    if "nmap" not in sources or "zeek" not in sources:
        return False
    return not is_scanner_observation(flow)


def evidence_overlap_breakdown(flows) -> dict:
    """Unique-communication counts across overlapping evidence dimensions.

    Returns counts keyed by dimension. The dimensions overlap by design - a
    single communication can be both "declared and observed" and "supported
    by both Nmap and Zeek" - so callers must present them as overlapping
    evidence facets, not mutually exclusive buckets. Every count is by unique
    communication identity, so inbound/outbound firewall perspectives of one
    communication are never counted twice.
    """
    both = [f for f in flows if supported_by_nmap_and_zeek(f)]
    return {
        "supported_by_nmap_and_zeek": count_communications(both),
        "nmap_and_zeek_only": count_communications(
            [f for f in both if f.correlation_status == "nmap-and-zeek"]
        ),
        "declared_with_nmap_corroboration": count_communications(
            [f for f in both
             if f.correlation_status == "user-defined-and-zeek"]
        ),
        "inferred_with_nmap_corroboration": count_communications(
            [f for f in both
             if f.correlation_status in ("inferred-and-zeek",
                                         "inferred-and-observed")]
        ),
        "declared_and_observed": count_communications(
            [f for f in flows
             if f.correlation_status == "user-defined-and-zeek"]
        ),
    }


def is_scanner_observation(flow) -> bool:
    """True when a flow's only Zeek evidence is the scanner's own probes.

    Such a flow is real, but it is audit evidence that the scan happened -
    never proof of a production dependency - so summaries count it apart
    from genuinely corroborated communications (defect 4).
    """
    return getattr(flow, "zeek_observation", "") == SCANNER_OBSERVATION_TEXT


def count_communications(items) -> int:
    """Number of unique communications represented by flows/aggregates."""
    return len({communication_key(item) for item in items})


@dataclass
class ZeekReportData:
    """Everything the report writers need, in one optional bundle."""

    metadata: ZeekInputMetadata
    health: ZeekSensorHealth
    aggregates: List[ZeekFlowAggregate] = field(default_factory=list)
    endpoints: List[EndpointIdentity] = field(default_factory=list)
    findings: List[CorrelationFinding] = field(default_factory=list)
    external_dependencies: List[ZeekFlowAggregate] = field(default_factory=list)
    attempted: List[ZeekFlowAggregate] = field(default_factory=list)


def correlate_zeek(hosts, records, flows, config, options, zeek: ZeekAnalysis) -> CorrelationResult:
    return ZeekCorrelator(hosts, records, flows, config, options, zeek).run()
