"""Tests for approved source/destination network enforcement."""

from nmap_flow_analyzer.config import HostConfig
from nmap_flow_analyzer.flow_analysis import AnalysisOptions
from nmap_flow_analyzer.policy_scope import (
    STATUS_AMBIGUOUS,
    STATUS_APPROVED,
    STATUS_NO_POLICY,
    STATUS_OUTSIDE,
    evaluate_rule_scope,
)
from tests.fixtures import MULTI_HOST_XML, base_config, run_pipeline


def _db_host_cfg(**kwargs):
    cfg = base_config()
    cfg.hosts["192.168.10.30"] = HostConfig(hostname="db01.example.local", **kwargs)
    return cfg


def test_exact_slash32_match_is_approved():
    cfg = _db_host_cfg(approved_source_networks=["192.168.1.50/32"])
    ev = evaluate_rule_scope(cfg, "192.168.10.30", "192.168.1.50", "192.168.10.30")
    assert ev.source_status == STATUS_APPROVED
    assert "192.168.1.50/32" in ev.matched_source_policy
    assert not ev.violation


def test_slash32_policy_is_never_widened():
    cfg = _db_host_cfg(approved_source_networks=["192.168.1.50/32"])
    # A neighbouring address in the same /24 must NOT match the /32 approval.
    ev = evaluate_rule_scope(cfg, "192.168.10.30", "192.168.1.51", "192.168.10.30")
    assert ev.source_status == STATUS_OUTSIDE
    assert ev.violation


def test_subnet_match():
    cfg = _db_host_cfg(approved_source_networks=["192.168.50.0/24"])
    ev = evaluate_rule_scope(cfg, "192.168.10.30", "192.168.50.77", "192.168.10.30")
    assert ev.source_status == STATUS_APPROVED


def test_rule_outside_approved_subnet_is_violation():
    cfg = _db_host_cfg(approved_source_networks=["192.168.50.0/24"])
    ev = evaluate_rule_scope(cfg, "192.168.10.30", "10.9.8.7", "192.168.10.30")
    assert ev.source_status == STATUS_OUTSIDE
    assert ev.violation


def test_ipv6_policy_match():
    cfg = base_config()
    cfg.hosts["2001:db8::30"] = HostConfig(
        approved_source_networks=["2001:db8::/64"]
    )
    ev = evaluate_rule_scope(cfg, "2001:db8::30", "2001:db8::20", "2001:db8::30")
    assert ev.source_status == STATUS_APPROVED
    ev = evaluate_rule_scope(cfg, "2001:db8::30", "2001:db9::20", "2001:db8::30")
    assert ev.source_status == STATUS_OUTSIDE


def test_host_policy_overrides_zone_policy():
    cfg = _db_host_cfg(approved_source_networks=["192.168.50.0/24"])
    cfg.zone_policies["Servers"] = {"approved_source_networks": ["10.0.0.0/8"]}
    # Host allows 192.168.50.0/24; zone would allow 10/8. Host wins.
    ev = evaluate_rule_scope(cfg, "192.168.10.30", "10.1.2.3", "192.168.10.30")
    assert ev.source_status == STATUS_OUTSIDE
    ev = evaluate_rule_scope(cfg, "192.168.10.30", "192.168.50.5", "192.168.10.30")
    assert ev.source_status == STATUS_APPROVED
    assert "hosts.192.168.10.30" in ev.matched_source_policy


def test_zone_policy_overrides_global_policy():
    cfg = base_config()
    cfg.global_policy = {"approved_destination_networks": ["10.0.0.0/8"]}
    # Hosts in the Servers zone may only send to Management addresses.
    cfg.zone_policies["Servers"] = {
        "approved_destination_networks": ["192.168.1.0/24"]
    }
    # Target 192.168.10.30 is in Servers -> zone policy applies (not global).
    ev = evaluate_rule_scope(cfg, "192.168.10.30", "192.168.10.30", "192.168.1.10")
    assert ev.destination_status == STATUS_APPROVED
    assert "zone 'Servers'" in ev.matched_destination_policy
    ev = evaluate_rule_scope(cfg, "192.168.10.30", "192.168.10.30", "10.1.2.3")
    assert ev.destination_status == STATUS_OUTSIDE  # zone wins over global 10/8
    # A target in a zone with no policy falls through to global.
    ev = evaluate_rule_scope(cfg, "192.168.1.99", "192.168.1.99", "10.1.2.3")
    assert ev.destination_status == STATUS_APPROVED
    assert "global_policy" in ev.matched_destination_policy


def test_conflicting_equal_priority_zone_policies_are_ambiguous():
    cfg = base_config()
    # Two zones claim overlapping space at the same prefix length.
    cfg.zones["ZoneA"] = ["10.5.0.0/24"]
    cfg.zones["ZoneB"] = ["10.5.0.0/24"]
    cfg.zone_policies["ZoneA"] = {"approved_source_networks": ["192.168.1.0/24"]}
    cfg.zone_policies["ZoneB"] = {"approved_source_networks": ["172.16.0.0/16"]}
    # The TARGET host sits in both zones at equal specificity -> ambiguous.
    ev = evaluate_rule_scope(cfg, "10.5.0.9", "192.168.1.50", "10.5.0.9")
    assert ev.source_status == STATUS_AMBIGUOUS
    assert ev.needs_review


def test_no_policy_defined_warns_but_does_not_reject():
    cfg = base_config()
    ev = evaluate_rule_scope(cfg, "192.168.10.30", "192.168.1.50", "192.168.10.30")
    assert ev.source_status == STATUS_NO_POLICY
    assert ev.destination_status == STATUS_NO_POLICY
    assert not ev.violation
    assert any("No approved-network policy" in n for n in ev.notes)


def test_strict_mode_withholds_violations_to_manual_review():
    cfg = _db_host_cfg(approved_source_networks=["192.168.50.0/24"])
    data = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions(strict=True))
    # Scanner (192.168.1.50) is outside the approved list for db01 -> withheld.
    db_rules = [r for r in data["inbound"] if r.target_ip == "192.168.10.30"]
    assert not db_rules
    assert any(
        rv.category == "Approved-network policy" and rv.ip == "192.168.10.30"
        for rv in data["rule_reviews"]
    )


def test_non_strict_mode_keeps_rule_but_flags_violation():
    cfg = _db_host_cfg(approved_source_networks=["192.168.50.0/24"])
    data = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    db_rules = [r for r in data["inbound"] if r.target_ip == "192.168.10.30"]
    assert db_rules
    for rule in db_rules:
        assert rule.policy_violation
        assert rule.source_scope_status == STATUS_OUTSIDE
        assert rule.matched_source_policy
        assert rule.policy_notes


def test_approved_source_but_unapproved_destination():
    cfg = _db_host_cfg(
        approved_source_networks=["192.168.1.0/24"],
        approved_destination_networks=["192.168.99.0/24"],
    )
    # Peer endpoints are checked; the target itself is exempt from its own
    # peer lists (an inbound rule's destination IS the target).
    ev = evaluate_rule_scope(cfg, "192.168.10.30", "192.168.1.50", "10.7.7.7")
    assert ev.source_status == STATUS_APPROVED
    assert ev.destination_status == STATUS_OUTSIDE
    assert ev.violation


def test_unapproved_source_but_approved_destination():
    cfg = _db_host_cfg(
        approved_source_networks=["192.168.99.0/24"],
        approved_destination_networks=["192.168.77.10/32"],
    )
    ev = evaluate_rule_scope(cfg, "192.168.10.30", "192.168.1.50", "192.168.77.10")
    assert ev.source_status == STATUS_OUTSIDE
    assert ev.destination_status == STATUS_APPROVED
    assert ev.violation


def test_inbound_rule_to_target_itself_not_penalized_by_its_egress_list():
    # db01 has an outbound allowlist; that must NOT flag inbound rules whose
    # destination is db01 itself.
    cfg = _db_host_cfg(
        approved_source_networks=["192.168.1.0/24"],
        approved_destination_networks=["192.168.1.10/32"],
    )
    ev = evaluate_rule_scope(cfg, "192.168.10.30", "192.168.1.50", "192.168.10.30")
    assert ev.source_status == STATUS_APPROVED
    assert ev.destination_status == STATUS_NO_POLICY
    assert not ev.violation
