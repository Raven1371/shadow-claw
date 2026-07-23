"""Tests for conservative firewall exception generation."""

from nmap_flow_analyzer.firewall_rules import build_inbound, build_outbound
from nmap_flow_analyzer.flow_analysis import AnalysisOptions, build_flows, enrich_hosts
from nmap_flow_analyzer.risk_analysis import build_service_records
from tests.fixtures import MULTI_HOST_XML, SINGLE_HOST_XML, base_config, parse_xml


def _pipeline(xml, config, options):
    _, hosts = parse_xml(xml)
    enrich_hosts(hosts, config)
    records = build_service_records(hosts, config)
    result = build_flows(hosts, records, config, options)
    inbound, in_reviews = build_inbound(result.flows, config, options)
    outbound, out_reviews = build_outbound(result.flows, inbound, config, options)
    return inbound, outbound, in_reviews + out_reviews


def test_inbound_source_is_scanner_never_any():
    cfg = base_config()
    inbound, _, _ = _pipeline(SINGLE_HOST_XML, cfg, AnalysisOptions())
    assert inbound
    for rule in inbound:
        assert rule.source not in ("any", "Any", "0.0.0.0/0", "::/0", "")
        assert "192.168.1.50" in rule.source


def test_no_any_any_rules_anywhere():
    cfg = base_config()
    opts = AnalysisOptions(include_inferred_outbound=True, firewall_mode="stateless")
    cfg.infrastructure = {"dns_servers": ["192.168.1.10"], "ntp_servers": ["192.168.1.11"]}
    inbound, outbound, _ = _pipeline(MULTI_HOST_XML, cfg, opts)
    for rule in inbound + outbound:
        assert rule.source.lower() != "any"
        assert rule.destination.lower() != "any"
        assert not (rule.port in ("any", "*") and rule.protocol == "any")


def test_broad_source_in_strict_mode_goes_to_review():
    cfg = base_config()
    from nmap_flow_analyzer.config import HostConfig

    cfg.hosts["192.168.10.20"] = HostConfig(
        expected_inbound=[
            {"protocol": "tcp", "port": 443, "sources": ["10.0.0.0/8"]}
        ]
    )
    strict_opts = AnalysisOptions(strict=True)
    inbound, _, reviews = _pipeline(SINGLE_HOST_XML, cfg, strict_opts)
    broad = [r for r in inbound if r.source == "10.0.0.0/8"]
    assert not broad  # withheld in strict mode
    assert any("10.0.0.0/8" in (rv.finding + rv.reason) for rv in reviews)
    # Non-strict: rule allowed but must carry a scope warning.
    lax_inbound, _, _ = _pipeline(SINGLE_HOST_XML, cfg, AnalysisOptions())
    flagged = [r for r in lax_inbound if r.source == "10.0.0.0/8"]
    assert flagged
    assert all(r.scope_warning for r in flagged)


def test_stateful_mode_creates_no_return_rules():
    cfg = base_config()
    inbound, outbound, _ = _pipeline(SINGLE_HOST_XML, cfg, AnalysisOptions())
    assert inbound
    assert not [r for r in outbound if "return" in r.purpose.lower()]


def test_stateless_mode_creates_labeled_return_rules():
    cfg = base_config()
    opts = AnalysisOptions(firewall_mode="stateless")
    inbound, outbound, _ = _pipeline(SINGLE_HOST_XML, cfg, opts)
    returns = [r for r in outbound if "return" in r.purpose.lower()]
    assert len(returns) == len(inbound)
    for rule in returns:
        assert rule.port == "1024-65535"
        assert any(rule.description.find(ib.rule_id) >= 0 or ib.rule_id in rule.purpose for ib in inbound)


def test_duplicate_flows_deduplicated_into_one_rule():
    cfg = base_config()
    cfg.defined_flows = [
        {"source": "192.168.1.50", "destination": "192.168.10.20", "protocol": "tcp", "port": 443}
    ]
    inbound, _, _ = _pipeline(SINGLE_HOST_XML, cfg, AnalysisOptions())
    matches = [r for r in inbound if r.destination == "192.168.10.20" and r.port == "443"]
    assert len(matches) == 1


def test_open_service_does_not_create_outbound_rule():
    cfg = base_config()
    _, outbound, _ = _pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    # Stateful, no config, no inferred flag: nothing may appear outbound.
    assert outbound == []
