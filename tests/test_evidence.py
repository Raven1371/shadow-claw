"""Tests for per-component evidence classification."""

from nmap_flow_analyzer.config import HostConfig
from nmap_flow_analyzer.flow_analysis import AnalysisOptions
from nmap_flow_analyzer.models import EvidenceClass, compose_flow_evidence
from tests.fixtures import (
    MULTI_HOST_XML,
    SINGLE_HOST_XML,
    base_config,
    run_pipeline,
)


def test_compose_examples_from_spec():
    assert compose_flow_evidence("Observed", "User-Defined") == "Observed + User-Defined"
    assert compose_flow_evidence("Unknown", "Inferred") == "Manual Review Required"
    assert compose_flow_evidence("Observed", "Observed", "Observed") == "Observed"
    assert (
        compose_flow_evidence("Observed", "Manual Review Required")
        == "Manual Review Required"
    )


def test_observed_service_with_user_defined_source():
    cfg = base_config()
    cfg.hosts["192.168.10.20"] = HostConfig(
        expected_inbound=[
            {"protocol": "tcp", "port": 443, "sources": ["192.168.20.0/24"]}
        ]
    )
    data = run_pipeline(SINGLE_HOST_XML, cfg, AnalysisOptions())
    cfg_rules = [r for r in data["inbound"] if r.source == "192.168.20.0/24"]
    assert cfg_rules
    rule = cfg_rules[0]
    assert rule.service_evidence == EvidenceClass.OBSERVED.value
    assert rule.source_scope_evidence == EvidenceClass.USER_DEFINED.value
    assert rule.flow_evidence == "Observed + User-Defined"
    # Back-compat: the original single evidence field still present & sane.
    assert rule.evidence_class in (
        EvidenceClass.OBSERVED.value, EvidenceClass.USER_DEFINED.value
    )


def test_pure_observed_rule_evidence():
    data = run_pipeline(SINGLE_HOST_XML, base_config(), AnalysisOptions())
    rule = data["inbound"][0]
    assert rule.service_evidence == EvidenceClass.OBSERVED.value
    assert rule.source_scope_evidence == EvidenceClass.OBSERVED.value
    assert rule.flow_evidence == "Observed"
    assert rule.evidence_class == EvidenceClass.OBSERVED.value  # unchanged


def test_user_defined_flow_components():
    cfg = base_config()
    cfg.defined_flows = [
        {"source": "192.168.10.20", "destination": "192.168.10.30",
         "protocol": "tcp", "port": 5432, "purpose": "App to DB"}
    ]
    data = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    flows = [
        f for f in data["flows"]
        if f.evidence_class == EvidenceClass.USER_DEFINED.value
    ]
    assert flows
    for flow in flows:
        assert flow.service_evidence == EvidenceClass.USER_DEFINED.value
        assert flow.source_scope_evidence == EvidenceClass.USER_DEFINED.value
        assert flow.purpose_evidence == EvidenceClass.USER_DEFINED.value
        assert flow.flow_evidence == "User-Defined"


def test_inferred_outbound_composition():
    cfg = base_config()
    cfg.infrastructure = {"dns_servers": ["192.168.1.10"]}
    data = run_pipeline(
        MULTI_HOST_XML, cfg, AnalysisOptions(include_inferred_outbound=True)
    )
    inferred = [
        f for f in data["flows"]
        if f.evidence_class == EvidenceClass.INFERRED.value
    ]
    assert inferred
    flow = inferred[0]
    assert flow.service_evidence == EvidenceClass.INFERRED.value
    assert flow.destination_scope_evidence == EvidenceClass.USER_DEFINED.value
    assert "Inferred" in flow.flow_evidence and "User-Defined" in flow.flow_evidence


def test_open_filtered_flow_is_manual_review_everywhere():
    data = run_pipeline(
        MULTI_HOST_XML, base_config(), AnalysisOptions(include_open_filtered=True)
    )
    uncertain = [f for f in data["flows"] if f.port_state == "open|filtered"]
    assert uncertain
    for flow in uncertain:
        assert flow.evidence_class == EvidenceClass.MANUAL_REVIEW.value
        assert flow.service_evidence == EvidenceClass.MANUAL_REVIEW.value
        assert flow.flow_evidence == EvidenceClass.MANUAL_REVIEW.value


def test_unknown_service_still_reports_components():
    data = run_pipeline(MULTI_HOST_XML, base_config(), AnalysisOptions())
    # tcp/9999 on db01 has no registered/detected service.
    flows = [f for f in data["flows"] if f.destination_port == 9999]
    assert flows
    assert flows[0].service_evidence == EvidenceClass.OBSERVED.value  # port open IS observed
    assert flows[0].flow_evidence


def test_backward_compatible_evidence_field_everywhere():
    data = run_pipeline(MULTI_HOST_XML, base_config(), AnalysisOptions())
    valid = {e.value for e in EvidenceClass}
    for flow in data["flows"]:
        assert flow.evidence_class in valid
    for rule in data["inbound"] + data["outbound"]:
        assert rule.evidence_class in valid
