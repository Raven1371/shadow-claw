"""Tests for transparent, threshold-based role inference."""

from nmap_flow_analyzer.role_inference import ASSIGNMENT_THRESHOLD, infer_role
from tests.fixtures import DC_HOST_XML, MISSING_SERVICE_XML, parse_xml


def test_domain_controller_inferred_with_evidence():
    _, hosts = parse_xml(DC_HOST_XML)
    result = infer_role(hosts[0])
    assert result.role == "Domain controller"
    assert result.confidence >= ASSIGNMENT_THRESHOLD
    assert result.evidence  # every assignment must cite its reasons
    assert result.source == "xml evidence"


def test_weak_evidence_yields_unknown_with_candidates():
    _, hosts = parse_xml(MISSING_SERVICE_XML)
    result = infer_role(hosts[0])
    assert result.role == "Unknown"
    assert result.confidence < ASSIGNMENT_THRESHOLD


def test_configured_role_overrides_inference():
    _, hosts = parse_xml(DC_HOST_XML)
    result = infer_role(hosts[0], configured_role="Backup server")
    assert result.role == "Backup server"
    assert result.confidence == 100
    assert result.source == "user configuration"
