"""Data-flow construction.

Core accuracy rules implemented here:

* Nmap-observed open ports produce flows **from the scanner to the target
  only** ("Observed").  No arbitrary host-to-host flows are invented merely
  because two systems appear in the same XML file.
* ``open|filtered`` ports are uncertain: they never become Observed flows
  and always generate a manual-review item.
* Additional flows come only from the YAML configuration ("User-Defined"),
  from opt-in infrastructure-role inference ("Inferred", with the assumption
  spelled out), or — very conservatively — from NSE cross-references, which
  by default become manual-review items rather than flows.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .pluralize import count_noun

from .config import AnalyzerConfig, INFERENCE_CATEGORIES
from .models import (
    compose_flow_evidence,
    EVIDENCE_PRIORITY,
    EvidenceClass,
    Flow,
    Host,
    ManualReviewItem,
    RiskLevel,
    ServiceRecord,
    ip_sort_key,
)
from .normalization import normalize_port
from .risk_analysis import MANAGEMENT_SERVICES, always_manual_review
from .role_inference import infer_role

LOG = logging.getLogger("nmap_flow_analyzer.flow_analysis")

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class AnalysisOptions:
    include_open_filtered: bool = False
    include_inferred_outbound: bool = False
    firewall_mode: str = "stateful"
    strict: bool = False
    diagram_detail: str = "summary"


@dataclass
class FlowBuildResult:
    flows: List[Flow] = field(default_factory=list)
    reviews: List[ManualReviewItem] = field(default_factory=list)


#: (infrastructure key, protocol, port, service, purpose, applies_to, confidence)
#: applies_to: "all" | "windows" | "server"
INFRA_OUTBOUND_TEMPLATES: List[Tuple[str, str, int, str, str, str, int]] = [
    ("dns_servers", "udp", 53, "DNS", "Name resolution against approved DNS servers", "all", 55),
    ("dns_servers", "tcp", 53, "DNS", "Name resolution (large responses / zone data)", "all", 45),
    ("ntp_servers", "udp", 123, "NTP", "Time synchronization against approved NTP servers", "all", 55),
    ("domain_controllers", "tcp", 88, "Kerberos", "Domain authentication (Kerberos)", "windows", 50),
    ("domain_controllers", "udp", 88, "Kerberos", "Domain authentication (Kerberos)", "windows", 45),
    ("domain_controllers", "tcp", 389, "LDAP", "Domain directory lookups (LDAP)", "windows", 50),
    ("domain_controllers", "tcp", 445, "SMB", "Domain services (SYSVOL/NETLOGON over SMB)", "windows", 50),
    ("domain_controllers", "tcp", 135, "MS RPC", "Domain services (RPC endpoint mapper)", "windows", 45),
    ("domain_controllers", "tcp", 53, "DNS", "AD-integrated DNS", "windows", 40),
    ("domain_controllers", "udp", 53, "DNS", "AD-integrated DNS", "windows", 40),
    ("logging_servers", "udp", 514, "Syslog", "Log forwarding to SIEM/logging servers", "all", 40),
    ("logging_servers", "tcp", 6514, "Syslog over TLS", "Encrypted log forwarding", "all", 35),
    ("patch_servers", "tcp", 443, "HTTPS", "Patch/repository access", "all", 40),
    ("backup_servers", "tcp", 443, "HTTPS", "Backup agent control channel (port assumed; verify vendor ports)", "all", 30),
    ("mail_relay_servers", "tcp", 25, "SMTP", "Application mail via approved relay", "server", 35),
    ("proxy_servers", "tcp", 3128, "HTTP Proxy", "Internet egress via approved proxy (port assumed)", "all", 30),
    ("authentication_servers", "tcp", 636, "LDAPS", "Directory authentication (assumed LDAPS)", "all", 30),
]

_INFRA_LABELS = {
    "dns_servers": "DNS server",
    "ntp_servers": "NTP server",
    "domain_controllers": "Domain controller",
    "authentication_servers": "Authentication server",
    "logging_servers": "Logging/SIEM server",
    "patch_servers": "Patch-management server",
    "backup_servers": "Backup server",
    "mail_relay_servers": "Mail relay",
    "proxy_servers": "Internet proxy",
}


def enrich_hosts(hosts: List[Host], config: AnalyzerConfig) -> None:
    """Apply zones, configuration metadata, and role inference to hosts."""
    for host in hosts:
        host.zone = config.zone_for_ip(host.primary_ip)
        cfg = config.host_cfg(host.primary_ip)
        configured_role = ""
        if cfg:
            configured_role = cfg.role
            if cfg.hostname and cfg.hostname not in host.hostnames:
                host.hostnames.insert(0, cfg.hostname)
            host.owner = cfg.owner
            host.purpose = cfg.purpose
            if cfg.device_class:
                host.device_class = cfg.device_class
        inference = infer_role(host, configured_role)
        host.role = inference.role
        host.role_confidence = inference.confidence
        host.role_evidence = inference.evidence
        host.role_contradictions = inference.contradictions
        host.role_source = inference.source


def _is_windows(host: Host) -> bool:
    text = " ".join(m.name for m in host.os_matches).lower()
    if "windows" in text:
        return True
    if host.role in {"Domain controller", "Windows server"}:
        return True
    return any(
        rec.state == "open" and rec.port in {135, 445} and rec.protocol == "tcp"
        for rec in host.ports
    )


def _applies(predicate: str, host: Host) -> bool:
    if predicate == "all":
        return True
    if predicate == "windows":
        return _is_windows(host)
    if predicate == "server":
        return host.device_class not in {"workstation", "printer"} and host.role != "Workstation"
    return False


def _ip_version(value: str) -> int:
    try:
        return ipaddress.ip_network(value, strict=False).version
    except ValueError:
        return 4


def _review(
    category: str,
    host: Optional[Host],
    finding: str,
    reason: str,
    recommendation: str,
    protocol: str = "",
    port: str = "",
    related_flow: str = "",
) -> ManualReviewItem:
    return ManualReviewItem(
        category=category,
        host=host.display_name if host else "",
        ip=host.primary_ip if host else "",
        protocol=protocol,
        port=port,
        finding=finding,
        reason=reason,
        recommendation=recommendation,
        related_flow=related_flow,
    )


class FlowBuilder:
    """Builds the normalized flow set plus manual-review items."""

    def __init__(
        self,
        hosts: List[Host],
        service_records: List[ServiceRecord],
        config: AnalyzerConfig,
        options: AnalysisOptions,
    ) -> None:
        self.hosts = hosts
        self.records = service_records
        self.config = config
        self.options = options
        self.hosts_by_ip: Dict[str, Host] = {h.primary_ip: h for h in hosts}
        self.flows: List[Flow] = []
        self.reviews: List[ManualReviewItem] = []
        self._scanner_missing_reported = False
        self._scanner_zone_conflict = self._detect_scanner_zone_conflict()

    def _detect_scanner_zone_conflict(self) -> bool:
        """True when --scanner-zone disagrees with CIDR-based zone mapping."""
        cfg = self.config
        if not (cfg.scanner_ip and cfg.scanner_zone):
            return False
        try:
            addr = ipaddress.ip_address(cfg.scanner_ip)
        except ValueError:
            return False
        mapped = ""
        for net, zone in cfg._zone_networks():
            if addr.version == net.version and addr in net:
                mapped = zone
                break
        if not mapped or mapped == cfg.scanner_zone:
            return False
        message = (
            f"Scanner zone '{cfg.scanner_zone}' conflicts with CIDR-based zone "
            f"mapping ('{mapped}' contains {cfg.scanner_ip})"
        )
        LOG.warning(message)
        cfg.warnings.append(message)
        self.reviews.append(
            _review(
                "Scan metadata",
                None,
                message,
                "Observed sources may be attributed to the wrong zone",
                "Correct --scanner-zone or the zone CIDRs, then re-run",
            )
        )
        return True

    # -- scanner ------------------------------------------------------------

    def _scanner(self) -> Tuple[str, str, str]:
        """(source value, source name, source zone) for observed flows."""
        cfg = self.config
        if cfg.scanner_ip:
            zone = cfg.scanner_zone or cfg.zone_for_ip(cfg.scanner_ip)
            name = cfg.scanner_hostname or "Nmap scanner"
            if cfg.policy.default_source_scope == "scanner-zone" and cfg.scanner_zone:
                cidrs = cfg.zones.get(cfg.scanner_zone, [])
                if cidrs:
                    return (",".join(cidrs), f"{cfg.scanner_zone} zone", cfg.scanner_zone)
            return (cfg.scanner_ip, name, zone)
        if not self._scanner_missing_reported:
            self._scanner_missing_reported = True
            self.reviews.append(
                _review(
                    "Scan metadata",
                    None,
                    "Scanner IP address is not configured",
                    "Nmap XML does not reliably record the scanner's own address, so "
                    "observed flows cannot be scoped to a concrete source",
                    "Provide --scanner-ip / --scanner-zone or scanner settings in the "
                    "YAML configuration, then re-run the analysis",
                )
            )
        return ("unknown", "Nmap scanner (unverified)", "Unknown")

    def _role_evidence(self, host: Optional[Host]) -> str:
        if host is None:
            return ""
        if host.role_source == "user configuration":
            return EvidenceClass.USER_DEFINED.value
        if host.role and host.role != "Unknown":
            return EvidenceClass.INFERRED.value
        return EvidenceClass.UNKNOWN.value

    def _finalize_evidence(self, flow: Flow, host: Optional[Host]) -> Flow:
        """Fill role and combined evidence once the components are set."""
        if not flow.role_evidence:
            flow.role_evidence = self._role_evidence(host)
        flow.flow_evidence = compose_flow_evidence(
            flow.service_evidence,
            flow.source_scope_evidence,
            flow.destination_scope_evidence,
        )
        return flow

    # -- observed flows -----------------------------------------------------

    def _observed_flows(self) -> None:
        src, src_name, src_zone = self._scanner()
        for sr in self.records:
            host = self.hosts_by_ip.get(sr.ip)
            if host is None:
                continue
            rec = next(
                (p for p in host.ports if p.protocol == sr.protocol and p.port == sr.port),
                None,
            )
            if sr.state == "open":
                self._add_open_flow(sr, host, rec, src, src_name, src_zone)
            elif sr.state == "open|filtered":
                self.reviews.append(
                    _review(
                        "Uncertain port state",
                        host,
                        f"{sr.protocol}/{sr.port} reported open|filtered",
                        "Nmap could not distinguish an open port from a filtered one "
                        "(common for UDP); treating it as reachable would be unsafe",
                        "Verify with a targeted scan (e.g. version probe, --reason), "
                        "packet capture, or on-host inspection before allowing traffic",
                        protocol=sr.protocol,
                        port=str(sr.port),
                    )
                )
                if self.options.include_open_filtered:
                    flow = self._base_flow(sr, host, src, src_name, src_zone)
                    flow.evidence_class = EvidenceClass.MANUAL_REVIEW.value
                    flow.confidence = 25
                    flow.evidence = (
                        f"Nmap reported {sr.protocol}/{sr.port} as open|filtered "
                        f"(reason: {sr.reason or 'unspecified'}); reachability unconfirmed"
                    )
                    flow.manual_review_reason = "Port state open|filtered is uncertain"
                    flow.recommended_action = "Do not implement until the port state is verified"
                    flow.perspective = "destination-inbound"
                    flow.service_evidence = EvidenceClass.MANUAL_REVIEW.value
                    flow.source_scope_evidence = (
                        EvidenceClass.MANUAL_REVIEW.value
                        if src == "unknown" else EvidenceClass.OBSERVED.value
                    )
                    flow.destination_scope_evidence = EvidenceClass.OBSERVED.value
                    self.flows.append(self._finalize_evidence(flow, host))
            # filtered / closed ports never generate allow flows

    def _base_flow(
        self,
        sr: ServiceRecord,
        host: Host,
        src: str,
        src_name: str,
        src_zone: str,
    ) -> Flow:
        return Flow(
            source_name=src_name,
            source=src,
            source_zone=src_zone,
            destination_name=host.display_name,
            destination=host.primary_ip,
            destination_zone=host.zone,
            ip_version=host.ip_version or 4,
            protocol=sr.protocol,
            source_port="any",
            destination_port=sr.port,
            normalized_service=sr.normalized_service,
            detected_service=sr.detected_service,
            direction="inbound",
            purpose=host.purpose,
            port_state=sr.state,
            state_reason=sr.reason,
            risk_level=sr.risk_level,
            risk_reasons=list(sr.risk_reasons),
            encryption=sr.encryption,
            authentication=sr.authentication,
            source_xml_host=host.primary_ip,
            related_scripts=list(sr.scripts),
        )

    def _add_open_flow(
        self,
        sr: ServiceRecord,
        host: Host,
        rec,
        src: str,
        src_name: str,
        src_zone: str,
    ) -> None:
        flow = self._base_flow(sr, host, src, src_name, src_zone)
        flow.evidence_class = EvidenceClass.OBSERVED.value
        flow.perspective = "destination-inbound"
        flow.service_evidence = EvidenceClass.OBSERVED.value
        flow.destination_scope_evidence = EvidenceClass.OBSERVED.value
        if src == "unknown":
            flow.source_scope_evidence = EvidenceClass.MANUAL_REVIEW.value
        elif self.config.policy.default_source_scope == "scanner-zone" and "," in src:
            flow.source_scope_evidence = EvidenceClass.USER_DEFINED.value
        else:
            flow.source_scope_evidence = EvidenceClass.OBSERVED.value
        if self._scanner_zone_conflict and self.options.strict:
            flow.manual_review_reason = (
                "Scanner zone conflicts with CIDR-based zone mapping"
            )
        flow.confidence = 90 if sr.reason in {"syn-ack", "udp-response"} else 75
        flow.evidence = (
            f"Nmap observed {sr.protocol}/{sr.port} open on {host.primary_ip} "
            f"(state reason: {sr.reason or 'unspecified'}). This confirms "
            "reachability from the scanner's location only."
        )
        host_cfg = self.config.host_cfg(host.primary_ip)
        if host_cfg:
            entry = host_cfg.approved_entry(sr.protocol, sr.port)
            if entry is not None:
                flow.purpose = str(entry.get("purpose", "") or host.purpose)
                if entry.get("approved", True) is False:
                    flow.manual_review_reason = "Service explicitly marked unapproved in configuration"
                    self.reviews.append(
                        _review(
                            "Unapproved service",
                            host,
                            f"{sr.normalized_service} on {sr.protocol}/{sr.port} is "
                            "marked approved: false in the configuration",
                            "The service is reachable but the owner has not approved it",
                            "Confirm with the system owner; disable the service or "
                            "approve it in network_config.yaml",
                            protocol=sr.protocol,
                            port=str(sr.port),
                        )
                    )
            elif host_cfg.approved_services:
                flow.manual_review_reason = "Service not listed in the host's approved_services"
                self.reviews.append(
                    _review(
                        "Unapproved service",
                        host,
                        f"{sr.normalized_service} on {sr.protocol}/{sr.port} is not in "
                        "the host's approved_services list",
                        "An approval list exists for this host and this service is absent",
                        "Confirm with the system owner before creating a firewall exception",
                        protocol=sr.protocol,
                        port=str(sr.port),
                    )
                )
        if rec is not None and always_manual_review(
            rec, _norm_stub(sr), self.config
        ):
            flow.manual_review_reason = (
                flow.manual_review_reason or "Matched policy.always_manual_review"
            )
            self.reviews.append(
                _review(
                    "Policy: always review",
                    host,
                    f"{sr.normalized_service} on {sr.protocol}/{sr.port} matches "
                    "policy.always_manual_review",
                    "Organization policy requires human review of this port/service",
                    "Review with the firewall owner before implementation",
                    protocol=sr.protocol,
                    port=str(sr.port),
                )
            )
        if sr.mismatch:
            self.reviews.append(
                _review(
                    "Service mismatch",
                    host,
                    sr.mismatch_note,
                    "Detected service disagrees with the registered service for this port",
                    "Verify which service is genuinely running before writing a rule",
                    protocol=sr.protocol,
                    port=str(sr.port),
                )
            )
        if flow.normalized_service in MANAGEMENT_SERVICES:
            mgmt = self.config.policy.management_source
            flow.recommended_action = (
                f"Restrict source to the approved management subnet "
                f"({mgmt})" if mgmt else
                "Restrict source to an approved management subnet or jump host"
            )
        elif not flow.recommended_action:
            flow.recommended_action = "Validate business need, then approve"
        if flow.purpose:
            flow.purpose_evidence = EvidenceClass.USER_DEFINED.value
        self.flows.append(self._finalize_evidence(flow, host))

    # -- user-defined flows -------------------------------------------------

    def _user_defined_flows(self) -> None:
        for entry in self.config.defined_flows:
            src = str(entry["source"])
            dst = str(entry["destination"])
            self._emit_config_flow(src, dst, entry, "defined_flows")
        for ip, host_cfg in sorted(self.config.hosts.items(), key=lambda kv: ip_sort_key(kv[0])):
            host = self.hosts_by_ip.get(ip)
            for entry in host_cfg.expected_outbound:
                dst = str(entry.get("destination", ""))
                if not dst:
                    continue
                self._emit_config_flow(ip, dst, entry, f"hosts.{ip}.expected_outbound")
            if host is None and (host_cfg.expected_inbound or host_cfg.expected_outbound):
                self.reviews.append(
                    ManualReviewItem(
                        category="Configuration drift",
                        host=host_cfg.hostname or ip,
                        ip=ip,
                        finding="Host is configured but was not present in the scan",
                        reason="Expected services cannot be checked against scan results",
                        recommendation="Confirm the host is online and included in scan scope",
                    )
                )

    def _emit_config_flow(self, src: str, dst: str, entry: Dict, origin: str) -> None:
        """Emit rule-perspective flows for one declared dependency.

        A single declared communication (src -> dst proto/port) may need a
        source-side outbound permission AND a destination-side inbound
        permission depending on where enforcement happens.  Which
        perspectives are produced is controlled by ``rule_generation``.
        """
        if not self._parseable_endpoint(src) or not self._parseable_endpoint(dst):
            self.reviews.append(
                ManualReviewItem(
                    category="Unresolvable defined flow",
                    host=src,
                    ip=src if self._parseable_endpoint(src) else "",
                    finding=f"Declared flow {src} -> {dst} has an unresolvable endpoint",
                    reason="A candidate rule cannot be scoped safely",
                    recommendation=f"Correct the entry in {origin}",
                )
            )
            return
        rg = self.config.rule_generation
        if rg.enforcement_model == "network_only":
            flow = self._config_flow(src, dst, entry, origin, "inbound", "network")
            flow.evidence = (
                flow.evidence
                + " Normalized as a single network-enforcement rule (enforcement_model: network_only)."
            )
            self.flows.append(flow)
            return
        if rg.generate_source_outbound:
            self.flows.append(
                self._config_flow(src, dst, entry, origin, "outbound", "source-outbound")
            )
        if rg.generate_destination_inbound:
            self.flows.append(
                self._config_flow(src, dst, entry, origin, "inbound", "destination-inbound")
            )
        if not rg.generate_source_outbound and not rg.generate_destination_inbound:
            self.reviews.append(
                ManualReviewItem(
                    category="Configuration",
                    host=src,
                    finding=f"Declared flow {src} -> {dst} generated no rule perspectives",
                    reason="Both rule_generation perspectives are disabled",
                    recommendation="Enable generate_source_outbound and/or "
                    "generate_destination_inbound",
                )
            )

    @staticmethod
    def _parseable_endpoint(value: str) -> bool:
        try:
            ipaddress.ip_network(str(value).split("%")[0], strict=False)
            return True
        except ValueError:
            return False

    def _config_flow(
        self,
        src: str,
        dst: str,
        entry: Dict,
        origin: str,
        direction: str,
        perspective: str,
    ) -> Flow:
        src_host = self.hosts_by_ip.get(src)
        dst_host = self.hosts_by_ip.get(dst)
        port = int(entry.get("port", entry.get("destination_port", 0)) or 0)
        protocol = str(entry.get("protocol", "tcp")).lower()
        service = str(entry.get("service", "") or normalize_port(protocol, port) or "Unknown")
        flow = Flow(
            source_name=src_host.display_name if src_host else src,
            source=src,
            source_zone=src_host.zone if src_host else self.config.zone_for_ip(src.split("/")[0]),
            destination_name=dst_host.display_name if dst_host else dst,
            destination=dst,
            destination_zone=dst_host.zone if dst_host else self.config.zone_for_ip(dst.split("/")[0]),
            ip_version=_ip_version(dst),
            protocol=protocol,
            destination_port=port,
            normalized_service=service,
            detected_service="",
            direction=direction,
            purpose=str(entry.get("purpose", "") or ""),
            evidence_class=EvidenceClass.USER_DEFINED.value,
            evidence=f"Declared in configuration ({origin}); not verified by the scan",
            confidence=80,
            recommended_action="Confirm the declared dependency is still current",
            source_xml_host=src if src_host else dst,
            perspective=perspective,
            service_evidence=EvidenceClass.USER_DEFINED.value,
            source_scope_evidence=EvidenceClass.USER_DEFINED.value,
            destination_scope_evidence=EvidenceClass.USER_DEFINED.value,
            purpose_evidence=(
                EvidenceClass.USER_DEFINED.value if entry.get("purpose") else ""
            ),
        )
        return self._finalize_evidence(flow, src_host if direction == "outbound" else dst_host)

    # -- inferred outbound --------------------------------------------------

    #: category -> list of (protocol, port, service, purpose, confidence)
    _CATEGORY_TRANSPORTS = {
        "dns": [("udp", 53, "DNS", "Name resolution against approved DNS servers", 75),
                ("tcp", 53, "DNS", "Name resolution (large responses / zone data)", 70)],
        "ntp": [("udp", 123, "NTP", "Time synchronization against approved NTP servers", 72)],
        "active_directory": [
            ("tcp", 88, "Kerberos", "Domain authentication (Kerberos)", 75),
            ("tcp", 389, "LDAP", "Domain directory lookups (LDAP)", 75),
            ("tcp", 445, "SMB", "Domain services (SYSVOL/NETLOGON over SMB)", 75),
            ("tcp", 135, "MS RPC", "Domain services (RPC endpoint mapper)", 70),
        ],
        "patch_management": [("tcp", 443, "HTTPS", "Patch/repository access", 55)],
        "backup": [("tcp", 443, "HTTPS",
                    "Backup agent control channel (port assumed; verify vendor ports)", 50)],
    }

    def _ad_applies(self, host: Host, roles: List[str]) -> bool:
        """AD dependencies only for role-compatible hosts.

        Linux systems are excluded unless their configured/inferred role is
        explicitly listed in inference_policy.active_directory.enabled_for_roles.
        """
        if host.role and host.role in roles:
            return True
        if _is_windows(host):
            category = "Windows server" if _applies("server", host) else "Windows workstation"
            if category in roles:
                return True
            # A generic "Windows" entry covers both when configured that way.
            return "Windows" in roles
        return False

    def _category_transports(self, cat_name: str, cat) -> List[Tuple[str, int, str, str, int]]:
        if cat_name == "logging":
            transports = []
            pt = cat.preferred_transport or {"protocol": "tcp", "port": 6514}
            transports.append(
                (str(pt["protocol"]), int(pt["port"]), "Syslog",
                 "Log forwarding to configured logging/SIEM servers (preferred transport)", 72)
            )
            for ft in cat.fallback_transports:
                transports.append(
                    (str(ft["protocol"]), int(ft["port"]), "Syslog",
                     "Log forwarding (explicitly configured fallback transport)", 60)
                )
            return transports
        transports = list(self._CATEGORY_TRANSPORTS.get(cat_name, []))
        if cat_name == "dns" and cat.protocols:
            transports = [tr for tr in transports if tr[0] in cat.protocols]
        return transports

    def _inferred_outbound(self) -> None:
        """Policy-driven, role-compatible outbound dependency inference.

        Strictly opt-in via --include-inferred-outbound.  Every emitted flow
        carries the policy entry and infrastructure entry that caused it, a
        confidence score, and is withheld to manual review when confidence
        falls below inference_policy.minimum_confidence_for_candidate_rule.
        """
        if not self.options.include_inferred_outbound:
            return
        policy = self.config.inference_policy
        threshold = policy.minimum_confidence_for_candidate_rule
        infra = self.config.infrastructure
        clients = [h for h in self.hosts if h.primary_ip != self.config.scanner_ip]
        emitted = set()
        for cat_name in sorted(policy.categories):
            cat = policy.categories[cat_name]
            if not cat.enabled:
                continue
            infra_key = INFERENCE_CATEGORIES[cat_name]
            servers = list(dict.fromkeys(infra.get(infra_key, [])))
            applicable = [
                h for h in clients
                if cat_name != "active_directory" or self._ad_applies(h, cat.enabled_for_roles)
            ]
            if not servers:
                if applicable and infra_key in infra:
                    self.reviews.append(
                        _review(
                            "Unresolved inferred dependency",
                            None,
                            f"inference_policy.{cat_name} is enabled but "
                            f"infrastructure.{infra_key} lists no servers",
                            "The dependency cannot be resolved to a concrete "
                            "destination; a broad rule will not be created",
                            f"Configure infrastructure.{infra_key} or disable "
                            f"inference_policy.{cat_name}",
                        )
                    )
                continue
            transports = self._category_transports(cat_name, cat)
            label = _INFRA_LABELS.get(infra_key, infra_key)
            for host in applicable:
                for server_ip in servers:
                    if server_ip == host.primary_ip:
                        continue  # never infer a self-dependency
                    for protocol, port, service, purpose, confidence in transports:
                        key = (host.primary_ip, server_ip, protocol, port)
                        if key in emitted:
                            continue
                        emitted.add(key)
                        server_host = self.hosts_by_ip.get(server_ip)
                        flow = Flow(
                            source_name=host.display_name,
                            source=host.primary_ip,
                            source_zone=host.zone,
                            destination_name=(
                                server_host.display_name if server_host
                                else f"{label} {server_ip}"
                            ),
                            destination=server_ip,
                            destination_zone=(
                                server_host.zone if server_host
                                else self.config.zone_for_ip(server_ip)
                            ),
                            ip_version=_ip_version(server_ip),
                            protocol=protocol,
                            destination_port=port,
                            normalized_service=service,
                            direction="outbound",
                            purpose=purpose,
                            evidence_class=EvidenceClass.INFERRED.value,
                            evidence=(
                                f"Inferred from inference_policy.{cat_name} and "
                                f"infrastructure.{infra_key} ({server_ip}). "
                                f"Assumption based on host role/OS "
                                f"({host.role or 'unclassified'}); not observed traffic."
                            ),
                            confidence=confidence,
                            recommended_action=(
                                "Confirm the dependency with flow logs or the "
                                "system owner before implementation"
                            ),
                            source_xml_host=host.primary_ip,
                            perspective="source-outbound",
                            service_evidence=EvidenceClass.INFERRED.value,
                            source_scope_evidence=EvidenceClass.OBSERVED.value,
                            destination_scope_evidence=EvidenceClass.USER_DEFINED.value,
                            purpose_evidence=EvidenceClass.INFERRED.value,
                        )
                        if confidence < threshold:
                            flow.manual_review_reason = (
                                f"Inference confidence {confidence} is below "
                                f"inference_policy.minimum_confidence_for_candidate_rule "
                                f"({threshold})"
                            )
                        self.flows.append(self._finalize_evidence(flow, host))

    # -- NSE cross-references ------------------------------------------------

    def _nse_cross_references(self) -> None:
        """NSE output naming another in-scope host is review material, not a flow."""
        known = set(self.hosts_by_ip)
        infra_ips = {ip for ips in self.config.infrastructure.values() for ip in ips}
        interesting = known | infra_ips
        for host in self.hosts:
            scripts = list(host.host_scripts)
            for rec in host.ports:
                scripts.extend(rec.scripts)
            seen: set = set()
            for script in scripts:
                for match in _IPV4_RE.findall(script.output):
                    if (
                        match in interesting
                        and match not in {host.primary_ip, self.config.scanner_ip}
                        and (script.script_id, match) not in seen
                    ):
                        seen.add((script.script_id, match))
                        self.reviews.append(
                            _review(
                                "NSE cross-reference",
                                host,
                                f"NSE script '{script.script_id}' output references {match}",
                                "Script output alone is not credible proof of a "
                                "production traffic flow",
                                "If this relationship is real, declare it in "
                                "defined_flows or expected_outbound so it becomes a "
                                "User-Defined flow",
                            )
                        )

    # -- assembly -----------------------------------------------------------

    def _dedupe_and_sort(self) -> None:
        best: Dict[Tuple, Flow] = {}
        for flow in self.flows:
            key = (flow.source, flow.destination, flow.protocol, flow.destination_port, flow.direction)
            existing = best.get(key)
            if existing is None:
                best[key] = flow
                continue
            rank = (EVIDENCE_PRIORITY.get(flow.evidence_class, 0), flow.confidence)
            existing_rank = (
                EVIDENCE_PRIORITY.get(existing.evidence_class, 0),
                existing.confidence,
            )
            keep = flow if rank > existing_rank else existing
            drop = existing if keep is flow else flow
            for sid in drop.related_scripts:
                if sid not in keep.related_scripts:
                    keep.related_scripts.append(sid)
            if drop.purpose and not keep.purpose:
                keep.purpose = drop.purpose
            best[key] = keep
            LOG.debug("Merged duplicate flow %s", key)
        self.flows = sort_and_assign_flow_ids(list(best.values()))

    def build(self) -> FlowBuildResult:
        self._observed_flows()
        self._user_defined_flows()
        self._inferred_outbound()
        self._nse_cross_references()
        self._dedupe_and_sort()
        LOG.info(
            "Built %s and %s",
            count_noun(len(self.flows), "flow"),
            count_noun(len(self.reviews), "manual-review item"),
        )
        return FlowBuildResult(flows=self.flows, reviews=self.reviews)


def _norm_stub(sr: ServiceRecord):
    """Adapter so policy matching can reuse ServiceRecord data."""
    from .normalization import NormalizedService

    return NormalizedService(
        expected=sr.expected_service,
        detected_raw=sr.detected_service,
        detected=sr.detected_service,
        final=sr.normalized_service,
        mismatch=sr.mismatch,
        note=sr.mismatch_note,
    )


def build_flows(
    hosts: List[Host],
    service_records: List[ServiceRecord],
    config: AnalyzerConfig,
    options: AnalysisOptions,
) -> FlowBuildResult:
    """Convenience wrapper around :class:`FlowBuilder`."""
    return FlowBuilder(hosts, service_records, config, options).build()


def sort_and_assign_flow_ids(flows: List[Flow]) -> List[Flow]:
    """Deterministically order flows and (re)assign F-#### identifiers.

    Used both by the builder and after Zeek correlation adds flows, so IDs
    stay deterministic across identical inputs.
    """
    ordered = sorted(
        flows,
        key=lambda f: (
            0 if f.direction == "inbound" else 1,
            ip_sort_key(f.destination.split("/")[0]),
            f.protocol,
            f.destination_port,
            f.source,
            f.perspective,
        ),
    )
    for index, flow in enumerate(ordered, start=1):
        flow.flow_id = f"F-{index:04d}"
    return ordered