"""Tests for scanner-source handling and open|filtered safety."""

from nmap_flow_analyzer.cli import build_arg_parser, main
from nmap_flow_analyzer.flow_analysis import AnalysisOptions
from nmap_flow_analyzer.models import EvidenceClass
from tests.fixtures import (
    IPV6_PAIR_XML,
    MULTI_HOST_XML,
    SINGLE_HOST_XML,
    base_config,
    run_pipeline,
)


def test_valid_scanner_ipv4():
    data = run_pipeline(SINGLE_HOST_XML, base_config(), AnalysisOptions())
    assert data["inbound"]
    assert all("192.168.1.50" in r.source for r in data["inbound"])


def test_valid_scanner_ipv6():
    cfg = base_config()
    cfg.scanner_ip = "2001:db8::1"
    cfg.scanner_zone = ""
    cfg.zones["V6"] = ["2001:db8::/64"]
    data = run_pipeline(IPV6_PAIR_XML, cfg, AnalysisOptions())
    assert data["inbound"]
    for rule in data["inbound"]:
        assert rule.source == "2001:db8::1"
        assert rule.source_zone == "V6"


def test_missing_scanner_ip_withholds_all_observed_inbound():
    cfg = base_config()
    cfg.scanner_ip = ""
    data = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    observed_rules = [
        r for r in data["inbound"]
        if r.evidence_class == EvidenceClass.OBSERVED.value
    ]
    assert not observed_rules
    for rule in data["inbound"] + data["outbound"]:
        assert rule.source.lower() != "any"
        assert "192.168.10." not in rule.source or rule.source != rule.destination
    assert any(
        "Scanner IP address is not configured" in rv.finding
        for rv in data["reviews"]
    )


def test_invalid_scanner_ip_rejected_by_cli():
    parser = build_arg_parser()
    args = parser.parse_args(
        ["--input", "x.xml", "--scanner-ip", "not-an-ip"]
    )
    from nmap_flow_analyzer.cli import _apply_cli_overrides
    import logging

    error = _apply_cli_overrides(base_config(), args, logging.getLogger("t"))
    assert error and "not-an-ip" in error


def test_scanner_zone_inferred_from_cidr_when_not_supplied():
    cfg = base_config()
    cfg.scanner_zone = ""
    data = run_pipeline(SINGLE_HOST_XML, cfg, AnalysisOptions())
    assert data["inbound"][0].source_zone == "Management"


def test_scanner_zone_conflict_warns_and_strict_withholds():
    cfg = base_config()
    cfg.scanner_zone = "Servers"  # CIDR mapping says Management
    data = run_pipeline(SINGLE_HOST_XML, cfg, AnalysisOptions())
    assert any("conflicts with CIDR-based zone mapping" in w for w in cfg.warnings)
    assert data["inbound"]  # non-strict: rules kept
    cfg2 = base_config()
    cfg2.scanner_zone = "Servers"
    strict = run_pipeline(SINGLE_HOST_XML, cfg2, AnalysisOptions(strict=True))
    observed = [
        r for r in strict["inbound"]
        if r.evidence_class == EvidenceClass.OBSERVED.value
    ]
    assert not observed
    assert any("Scanner zone" in rv.finding for rv in strict["reviews"])


# ---------------------------------------------------------------------------
# open|filtered safety
# ---------------------------------------------------------------------------

def test_open_filtered_never_becomes_a_rule_even_when_included():
    for strict in (False, True):
        data = run_pipeline(
            MULTI_HOST_XML,
            base_config(),
            AnalysisOptions(include_open_filtered=True, strict=strict),
        )
        for rule in data["inbound"] + data["outbound"]:
            assert rule.port != "161", "open|filtered port became a rule"
        uncertain = [f for f in data["flows"] if f.port_state == "open|filtered"]
        assert uncertain
        for flow in uncertain:
            assert flow.evidence_class == EvidenceClass.MANUAL_REVIEW.value
            assert flow.manual_review_reason


def test_open_filtered_in_service_inventory_but_marked():
    data = run_pipeline(MULTI_HOST_XML, base_config(), AnalysisOptions())
    records = [r for r in data["records"] if r.state == "open|filtered"]
    assert records
    for rec in records:
        assert rec.evidence_class == EvidenceClass.MANUAL_REVIEW.value
