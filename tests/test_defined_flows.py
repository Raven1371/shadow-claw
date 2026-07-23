"""Tests for user-defined flow rule generation (both perspectives)."""

from nmap_flow_analyzer.flow_analysis import AnalysisOptions
from nmap_flow_analyzer.models import EvidenceClass
from tests.fixtures import (
    IPV6_PAIR_XML,
    MULTI_HOST_XML,
    base_config,
    run_pipeline,
)


def _flow_cfg(src="192.168.10.20", dst="192.168.10.30", port=5432, **extra):
    cfg = base_config()
    entry = {"source": src, "destination": dst, "protocol": "tcp", "port": port}
    entry.update(extra)
    cfg.defined_flows = [entry]
    return cfg


def _defined(rules):
    return [r for r in rules if r.evidence_class == EvidenceClass.USER_DEFINED.value]


def test_known_source_and_destination_yield_both_rules():
    data = run_pipeline(MULTI_HOST_XML, _flow_cfg(), AnalysisOptions())
    outbound = _defined(data["outbound"])
    inbound = _defined(data["inbound"])
    assert len(outbound) == 1 and len(inbound) == 1
    assert outbound[0].source == "192.168.10.20"
    assert outbound[0].destination == "192.168.10.30"
    assert outbound[0].perspective == "source-outbound"
    assert inbound[0].source == "192.168.10.20"
    assert inbound[0].destination == "192.168.10.30"
    assert inbound[0].perspective == "destination-inbound"
    assert inbound[0].port == outbound[0].port == "5432"


def test_unknown_destination_still_generates_both_perspectives():
    data = run_pipeline(
        MULTI_HOST_XML, _flow_cfg(dst="192.168.99.99"), AnalysisOptions()
    )
    assert len(_defined(data["outbound"])) == 1
    assert len(_defined(data["inbound"])) == 1


def test_unknown_source_still_generates_both_perspectives():
    data = run_pipeline(
        MULTI_HOST_XML, _flow_cfg(src="192.168.99.10"), AnalysisOptions()
    )
    assert len(_defined(data["outbound"])) == 1
    assert len(_defined(data["inbound"])) == 1


def test_cidr_source_and_destination():
    data = run_pipeline(
        MULTI_HOST_XML,
        _flow_cfg(src="192.168.20.0/24", dst="192.168.10.0/24"),
        AnalysisOptions(),
    )
    for rule in _defined(data["inbound"]) + _defined(data["outbound"]):
        assert rule.source == "192.168.20.0/24"
        assert rule.destination == "192.168.10.0/24"
        assert rule.source.lower() != "any"


def test_ipv6_defined_flow():
    cfg = base_config()
    cfg.zones["V6"] = ["2001:db8::/64"]
    cfg.defined_flows = [
        {"source": "2001:db8::20", "destination": "2001:db8::30",
         "protocol": "tcp", "port": 5432}
    ]
    data = run_pipeline(IPV6_PAIR_XML, cfg, AnalysisOptions())
    inbound = _defined(data["inbound"])
    outbound = _defined(data["outbound"])
    assert inbound and outbound
    assert inbound[0].destination == "2001:db8::30"


def test_stateful_mode_no_return_rules_for_defined_flows():
    data = run_pipeline(MULTI_HOST_XML, _flow_cfg(), AnalysisOptions())
    assert not [r for r in data["outbound"] if "return" in r.purpose.lower()]


def test_stateless_mode_labels_return_rules():
    data = run_pipeline(
        MULTI_HOST_XML, _flow_cfg(), AnalysisOptions(firewall_mode="stateless")
    )
    returns = [r for r in data["outbound"] if r.perspective == "stateless-return"]
    assert returns
    for rule in returns:
        assert "Stateless return path" in rule.purpose


def test_duplicate_defined_flows_deduplicate():
    cfg = _flow_cfg()
    cfg.defined_flows = cfg.defined_flows * 2  # exact duplicate entries
    data = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    assert len(_defined(data["inbound"])) == 1
    assert len(_defined(data["outbound"])) == 1


def test_conflicting_defined_flows_keep_distinct_rules():
    cfg = base_config()
    cfg.defined_flows = [
        {"source": "192.168.10.20", "destination": "192.168.10.30",
         "protocol": "tcp", "port": 5432, "purpose": "App A"},
        {"source": "192.168.10.20", "destination": "192.168.10.30",
         "protocol": "tcp", "port": 5433, "purpose": "App B"},
    ]
    data = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    ports = sorted(r.port for r in _defined(data["inbound"]))
    assert ports == ["5432", "5433"]


def test_disable_destination_inbound_generation():
    cfg = _flow_cfg()
    cfg.rule_generation.generate_destination_inbound = False
    data = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    assert not _defined(data["inbound"])
    assert len(_defined(data["outbound"])) == 1


def test_disable_source_outbound_generation():
    cfg = _flow_cfg()
    cfg.rule_generation.generate_source_outbound = False
    data = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    assert len(_defined(data["inbound"])) == 1
    assert not _defined(data["outbound"])


def test_enforcement_model_endpoint_and_network():
    cfg = _flow_cfg()
    cfg.rule_generation.enforcement_model = "endpoint_and_network"
    data = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    assert len(_defined(data["inbound"])) == 1
    assert len(_defined(data["outbound"])) == 1
    for rule in _defined(data["inbound"]) + _defined(data["outbound"]):
        assert rule.enforcement_model == "endpoint_and_network"


def test_enforcement_model_endpoint_only():
    cfg = _flow_cfg()
    cfg.rule_generation.enforcement_model = "endpoint_only"
    data = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    assert len(_defined(data["inbound"])) == 1
    assert len(_defined(data["outbound"])) == 1


def test_enforcement_model_network_only_single_rule():
    cfg = _flow_cfg()
    cfg.rule_generation.enforcement_model = "network_only"
    data = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    defined = _defined(data["inbound"]) + _defined(data["outbound"])
    assert len(defined) == 1  # one normalized network rule, no duplicates
    rule = defined[0]
    assert rule.perspective == "network"
    assert "network_only" in rule.evidence


def test_deterministic_rule_ids():
    cfg = _flow_cfg()
    first = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    second = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    assert [r.rule_id for r in first["inbound"]] == [r.rule_id for r in second["inbound"]]
    assert [r.rule_id for r in first["outbound"]] == [r.rule_id for r in second["outbound"]]
