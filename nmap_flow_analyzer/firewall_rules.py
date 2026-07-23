"""Candidate firewall exception generation.

Guarantees enforced here:

* No "Any/Any" rules are ever produced.  A source or destination of
  0.0.0.0/0, ::/0, or "any" is always diverted to manual review.
* Sources are never broadened beyond the scanner IP (or configured scanner
  zone) unless the configuration explicitly authorizes another scope.
* In strict mode, overly broad or ambiguous rules move to manual review
  instead of the proposed exception list.
* Stateful mode does not emit separate rules for response traffic;
  stateless mode emits explicit, clearly labeled return-path rules.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Dict, List, Optional, Tuple

from .config import AnalyzerConfig
from .flow_analysis import AnalysisOptions
from .policy_scope import (
    STATUS_AMBIGUOUS,
    STATUS_OUTSIDE,
    evaluate_rule_scope,
)
from .models import (
    EvidenceClass,
    compose_flow_evidence,
    FirewallRule,
    Flow,
    ManualReviewItem,
    RiskLevel,
    ip_sort_key,
)
from .risk_analysis import MANAGEMENT_SERVICES
from .pluralize import count_noun

LOG = logging.getLogger("nmap_flow_analyzer.firewall_rules")

RULE_EVIDENCE = {
    EvidenceClass.OBSERVED.value,
    EvidenceClass.USER_DEFINED.value,
    EvidenceClass.INFERRED.value,
}


def _parse_network(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _scope_problem(
    value: str, config: AnalyzerConfig, options: AnalysisOptions
) -> Tuple[str, str]:
    """Return (severity, message): severity is '', 'warn', or 'reject'."""
    token = value.strip().lower()
    if token in {"any", "*", "0.0.0.0/0", "::/0", ""} or token == "unknown":
        if token == "unknown":
            return (
                "reject",
                "Source could not be determined (scanner identity not configured)",
            )
        return ("reject", "'Any' sources/destinations are not permitted")
    net = _parse_network(value)
    if net is None:
        return ("reject", f"Not a valid IP or CIDR: {value!r}")
    if net.prefixlen == 0:
        return ("reject", "'Any' sources/destinations are not permitted")
    limit = (
        config.policy.max_source_prefixlen_ipv4
        if net.version == 4
        else config.policy.max_source_prefixlen_ipv6
    )
    if net.prefixlen < limit:
        return (
            "warn",
            f"Scope {net} is broader than the policy limit (/{limit}); "
            "confirm this breadth is intended",
        )
    return ("", "")


def _mgmt_action(service: str, config: AnalyzerConfig, fallback: str) -> str:
    if service in MANAGEMENT_SERVICES:
        mgmt = config.policy.management_source
        if mgmt:
            return f"Restrict source to the approved management subnet ({mgmt}) or a jump host"
        return "Restrict source to an approved management subnet or jump host"
    return fallback


def _sources_for_flow(
    flow: Flow, config: AnalyzerConfig
) -> List[Tuple[str, str, str]]:
    """Resolve rule sources: [(source_value, evidence_class, note)].

    Uses configured expected_inbound scopes when they match; otherwise the
    flow's own (scanner-scoped) source.  Never invents broader scopes.
    """
    host_cfg = config.host_cfg(flow.destination)
    if host_cfg:
        for entry in host_cfg.expected_inbound:
            if (
                str(entry.get("protocol", "tcp")).lower() == flow.protocol
                and int(entry.get("port", -1)) == flow.destination_port
            ):
                resolved: List[Tuple[str, str, str]] = []
                for token in entry.get("sources", []):
                    cidrs = config.resolve_source(str(token))
                    if not cidrs:
                        resolved.append(
                            (str(token), EvidenceClass.MANUAL_REVIEW.value,
                             f"Configured source {token!r} is not a known zone, IP, or CIDR")
                        )
                        continue
                    for cidr in cidrs:
                        resolved.append(
                            (cidr, EvidenceClass.USER_DEFINED.value,
                             f"Source scope authorized by configuration ({token})")
                        )
                if resolved:
                    return resolved
    sources: List[Tuple[str, str, str]] = []
    for part in flow.source.split(","):
        sources.append((part.strip(), flow.evidence_class, ""))
    return sources


def _propagate_zeek_fields(rule: FirewallRule, flow: Flow) -> None:
    """Copy append-only Zeek/correlation evidence from a flow onto its rule."""
    rule.evidence_sources = list(flow.evidence_sources)
    rule.nmap_observation = flow.nmap_observation
    rule.zeek_observation = flow.zeek_observation
    rule.correlation_status = flow.correlation_status
    rule.first_seen = flow.first_seen
    rule.last_seen = flow.last_seen
    rule.connection_count = flow.connection_count
    rule.successful_connections = flow.successful_connections
    rule.failed_connections = flow.failed_connections
    rule.one_way_connections = flow.one_way_connections
    rule.partial_connections = flow.partial_connections
    rule.originator_bytes = flow.originator_bytes
    rule.responder_bytes = flow.responder_bytes
    rule.originator_packets = flow.originator_packets
    rule.responder_packets = flow.responder_packets
    rule.zeek_conn_states = list(flow.zeek_conn_states)
    rule.zeek_services = list(flow.zeek_services)
    rule.sample_zeek_uids = list(flow.sample_zeek_uids)
    rule.dns_names = list(flow.dns_names)
    rule.tls_server_names = list(flow.tls_server_names)
    rule.http_hosts = list(flow.http_hosts)
    rule.sensor_quality = flow.sensor_quality


def _copy_flow_evidence(rule: FirewallRule, flow: Flow, config: AnalyzerConfig) -> None:
    """Carry per-component evidence and perspective onto the rule."""
    rule.service_evidence = flow.service_evidence
    rule.source_scope_evidence = flow.source_scope_evidence
    rule.destination_scope_evidence = flow.destination_scope_evidence
    rule.purpose_evidence = flow.purpose_evidence
    rule.role_evidence = flow.role_evidence
    rule.flow_evidence = flow.flow_evidence
    rule.perspective = flow.perspective or (
        "destination-inbound" if rule.direction == "inbound" else "source-outbound"
    )
    rule.enforcement_model = config.rule_generation.enforcement_model


def _apply_policy_scope(
    rule: FirewallRule,
    config: AnalyzerConfig,
    options: AnalysisOptions,
    target_ip: str,
) -> Optional[ManualReviewItem]:
    """Evaluate approved-network policy; return a review item to withhold.

    The rule object is annotated either way.  In strict mode a violation or
    an ambiguous policy withholds the rule entirely; otherwise the rule is
    kept but clearly flagged.
    """
    ev = evaluate_rule_scope(config, target_ip, rule.source, rule.destination)
    rule.source_scope_status = ev.source_status
    rule.destination_scope_status = ev.destination_status
    rule.matched_source_policy = ev.matched_source_policy
    rule.matched_destination_policy = ev.matched_destination_policy
    rule.policy_violation = ev.violation
    rule.policy_notes = "; ".join(ev.notes)
    withhold = ev.needs_review or (ev.violation and options.strict)
    if not withhold:
        if ev.violation and not rule.scope_warning:
            rule.scope_warning = "Outside approved networks; see policy_notes"
        return None
    problem = (
        "conflicting approval policies apply"
        if ev.needs_review
        else "the rule is outside the approved networks"
    )
    return ManualReviewItem(
        category="Approved-network policy",
        host=rule.target_hostname,
        ip=rule.target_ip,
        protocol=rule.protocol,
        port=rule.port,
        finding=(
            f"{rule.direction.capitalize()} {rule.protocol.upper()}/{rule.port} "
            f"({rule.service}) from {rule.source} to {rule.destination}: {problem}"
        ),
        reason=rule.policy_notes or problem,
        recommendation=(
            "Update approved_source_networks / approved_destination_networks "
            "or adjust the rule scope, then re-run"
        ),
        related_flow=rule.flow_id,
    )


def build_inbound(
    flows: List[Flow],
    config: AnalyzerConfig,
    options: AnalysisOptions,
) -> Tuple[List[FirewallRule], List[ManualReviewItem]]:
    """Build the inbound exception list from the destination's perspective."""
    rules: List[FirewallRule] = []
    reviews: List[ManualReviewItem] = []
    seen: Dict[Tuple, str] = {}

    for flow in flows:
        if flow.direction != "inbound" or flow.evidence_class not in RULE_EVIDENCE:
            continue
        if flow.manual_review_reason:
            reviews.append(
                ManualReviewItem(
                    category="Rule withheld",
                    host=flow.destination_name,
                    ip=flow.destination,
                    protocol=flow.protocol,
                    port=str(flow.destination_port),
                    finding=(
                        f"Candidate inbound rule for {flow.normalized_service} withheld"
                    ),
                    reason=flow.manual_review_reason,
                    recommendation="Resolve the noted concern, then re-run the analysis",
                    related_flow=flow.flow_id,
                )
            )
            continue

        for source_value, evidence_class, note in _sources_for_flow(flow, config):
            severity, message = _scope_problem(source_value, config, options)
            if severity == "reject" or (severity == "warn" and options.strict):
                reviews.append(
                    ManualReviewItem(
                        category="Overly broad rule" if severity == "warn" else "Unsafe rule scope",
                        host=flow.destination_name,
                        ip=flow.destination,
                        protocol=flow.protocol,
                        port=str(flow.destination_port),
                        finding=(
                            f"Inbound {flow.protocol.upper()}/{flow.destination_port} "
                            f"({flow.normalized_service}) from {source_value or 'unknown'}"
                        ),
                        reason=message,
                        recommendation=(
                            "Narrow the source to a specific host or approved subnet "
                            "before implementation"
                        ),
                        related_flow=flow.flow_id,
                    )
                )
                continue

            key = (flow.destination, source_value, flow.protocol, flow.destination_port)
            if key in seen:
                LOG.debug("Duplicate inbound rule suppressed: %s (first: %s)", key, seen[key])
                continue
            seen[key] = flow.flow_id

            source_zone = config.zone_for_ip(source_value.split("/")[0])
            rule = FirewallRule(
                direction="inbound",
                target_hostname=flow.destination_name,
                target_ip=flow.destination,
                target_zone=flow.destination_zone,
                source=source_value,
                source_hostname=flow.source_name if evidence_class == flow.evidence_class else "",
                source_zone=source_zone if source_zone != "Unknown" else flow.source_zone,
                destination=flow.destination,
                destination_hostname=flow.destination_name,
                destination_zone=flow.destination_zone,
                protocol=flow.protocol,
                port=str(flow.destination_port),
                service=flow.normalized_service,
                purpose=flow.purpose,
                evidence_class=evidence_class,
                evidence="; ".join(filter(None, [flow.evidence, note])),
                confidence=flow.confidence if evidence_class == flow.evidence_class else 80,
                encryption=flow.encryption,
                authentication=flow.authentication,
                risk_level=flow.risk_level,
                recommended_action=_mgmt_action(
                    flow.normalized_service, config, flow.recommended_action
                ),
                description=(
                    f"Allow {flow.protocol.upper()} {flow.destination_port} "
                    f"({flow.normalized_service}) from {source_value} to "
                    f"{flow.destination} ({flow.destination_name})"
                ),
                scope_warning=message if severity == "warn" else "",
                manual_review_notes="",
                flow_id=flow.flow_id,
            )
            _copy_flow_evidence(rule, flow, config)
            _propagate_zeek_fields(rule, flow)
            if evidence_class != flow.evidence_class:
                # Source came from expected_inbound configuration.
                rule.source_scope_evidence = EvidenceClass.USER_DEFINED.value
                rule.flow_evidence = compose_flow_evidence(
                    rule.service_evidence,
                    rule.source_scope_evidence,
                    rule.destination_scope_evidence,
                )
            withheld = _apply_policy_scope(rule, config, options, flow.destination)
            if withheld is not None:
                reviews.append(withheld)
                continue
            rules.append(rule)

    rules.sort(
        key=lambda r: (ip_sort_key(r.target_ip), r.protocol, int(r.port), r.source)
    )
    for index, rule in enumerate(rules, start=1):
        rule.rule_id = f"IN-{index:04d}"
    LOG.info("Generated %s", count_noun(len(rules), "candidate inbound rule"))
    return rules, reviews


def _return_rules(
    inbound: List[FirewallRule], config: AnalyzerConfig
) -> List[FirewallRule]:
    """Explicit return-path rules for stateless firewalls."""
    rules: List[FirewallRule] = []
    for rule in inbound:
        rules.append(
            FirewallRule(
                direction="outbound",
                target_hostname=rule.target_hostname,
                target_ip=rule.target_ip,
                target_zone=rule.target_zone,
                source=rule.target_ip,
                source_hostname=rule.target_hostname,
                source_zone=rule.target_zone,
                destination=rule.source,
                destination_hostname=rule.source_hostname,
                destination_zone=rule.source_zone,
                protocol=rule.protocol,
                port="1024-65535",
                service=f"{rule.service} (return traffic)",
                purpose=f"Stateless return path for {rule.rule_id}",
                evidence_class=rule.evidence_class,
                evidence=(
                    "Return path required only because firewall_mode=stateless; "
                    f"derived from inbound rule {rule.rule_id}"
                ),
                confidence=rule.confidence,
                encryption=rule.encryption,
                authentication=rule.authentication,
                risk_level=RiskLevel.LOW.value,
                recommended_action="Prefer a stateful firewall where possible",
                description=(
                    f"Allow {rule.protocol.upper()} from {rule.target_ip} source-port "
                    f"{rule.port} to {rule.source} ports 1024-65535 "
                    f"(return traffic for {rule.rule_id})"
                ),
                flow_id=rule.flow_id,
                perspective="stateless-return",
                enforcement_model=config.rule_generation.enforcement_model,
                service_evidence=rule.service_evidence,
                source_scope_evidence=rule.destination_scope_evidence,
                destination_scope_evidence=rule.source_scope_evidence,
                flow_evidence=rule.flow_evidence,
            )
        )
    return rules


def build_outbound(
    flows: List[Flow],
    inbound_rules: List[FirewallRule],
    config: AnalyzerConfig,
    options: AnalysisOptions,
) -> Tuple[List[FirewallRule], List[ManualReviewItem]]:
    """Build the (conservative) outbound exception list.

    Outbound rules come only from user-defined flows, opt-in inferred
    dependencies, or stateless-mode return paths — never from the mere fact
    that an inbound service was open.
    """
    rules: List[FirewallRule] = []
    reviews: List[ManualReviewItem] = []
    seen: Dict[Tuple, str] = {}

    for flow in flows:
        if flow.direction != "outbound" or flow.evidence_class not in RULE_EVIDENCE:
            continue
        if flow.manual_review_reason:
            reviews.append(
                ManualReviewItem(
                    category="Rule withheld",
                    host=flow.source_name,
                    ip=flow.source,
                    protocol=flow.protocol,
                    port=str(flow.destination_port),
                    finding=(
                        f"Candidate outbound rule for {flow.normalized_service} "
                        f"to {flow.destination} withheld"
                    ),
                    reason=flow.manual_review_reason,
                    recommendation="Resolve the noted concern, then re-run the analysis",
                    related_flow=flow.flow_id,
                )
            )
            continue
        severity, message = _scope_problem(flow.destination, config, options)
        if severity == "reject" or (severity == "warn" and options.strict):
            reviews.append(
                ManualReviewItem(
                    category="Overly broad rule" if severity == "warn" else "Unsafe rule scope",
                    host=flow.source_name,
                    ip=flow.source,
                    protocol=flow.protocol,
                    port=str(flow.destination_port),
                    finding=(
                        f"Outbound {flow.protocol.upper()}/{flow.destination_port} to "
                        f"{flow.destination}"
                    ),
                    reason=message,
                    recommendation="Narrow the destination before implementation",
                    related_flow=flow.flow_id,
                )
            )
            continue
        key = (flow.source, flow.destination, flow.protocol, flow.destination_port)
        if key in seen:
            LOG.debug("Duplicate outbound rule suppressed: %s", key)
            continue
        seen[key] = flow.flow_id
        rule = FirewallRule(
                direction="outbound",
                target_hostname=flow.source_name,
                target_ip=flow.source,
                target_zone=flow.source_zone,
                source=flow.source,
                source_hostname=flow.source_name,
                source_zone=flow.source_zone,
                destination=flow.destination,
                destination_hostname=flow.destination_name,
                destination_zone=flow.destination_zone,
                protocol=flow.protocol,
                port=str(flow.destination_port),
                service=flow.normalized_service,
                purpose=flow.purpose,
                evidence_class=flow.evidence_class,
                evidence=flow.evidence,
                confidence=flow.confidence,
                encryption=flow.encryption,
                authentication=flow.authentication,
                risk_level=flow.risk_level,
                recommended_action=flow.recommended_action
                or "Validate the dependency before implementation",
                description=(
                    f"Allow {flow.protocol.upper()} {flow.destination_port} "
                    f"({flow.normalized_service}) from {flow.source} "
                    f"({flow.source_name}) to {flow.destination} "
                    f"({flow.destination_name})"
                ),
                scope_warning=message if severity == "warn" else "",
                flow_id=flow.flow_id,
        )
        _copy_flow_evidence(rule, flow, config)
        _propagate_zeek_fields(rule, flow)
        withheld = _apply_policy_scope(rule, config, options, flow.source)
        if withheld is not None:
            reviews.append(withheld)
            del seen[key]
            continue
        rules.append(rule)

    if options.firewall_mode == "stateless":
        for rule in _return_rules(inbound_rules, config):
            key = (rule.source, rule.destination, rule.protocol, rule.port)
            if key not in seen:
                seen[key] = rule.flow_id
                rules.append(rule)
    # In stateful mode no separate response-traffic rules are generated.

    rules.sort(
        key=lambda r: (ip_sort_key(r.target_ip.split("/")[0]), r.protocol, r.port, r.destination)
    )
    for index, rule in enumerate(rules, start=1):
        rule.rule_id = f"OUT-{index:04d}"
    LOG.info("Generated %s", count_noun(len(rules), "candidate outbound rule"))
    return rules, reviews