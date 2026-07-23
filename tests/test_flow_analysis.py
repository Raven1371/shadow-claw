"""Tests for flow construction, evidence classes, and CLI toggles."""

from nmap_flow_analyzer.diagrams import group_edges
from nmap_flow_analyzer.flow_analysis import AnalysisOptions, build_flows, enrich_hosts
from nmap_flow_analyzer.models import EvidenceClass
from nmap_flow_analyzer.risk_analysis import build_service_records
from tests.fixtures import MULTI_HOST_XML, SINGLE_HOST_XML, base_config, parse_xml


def _prepare(xml, config, options):
    _, hosts = parse_xml(xml)
    enrich_hosts(hosts, config)
    records = build_service_records(hosts, config)
    return hosts, records, build_flows(hosts, records, config, options)


def test_observed_flow_is_scanner_to_target_only():
    cfg = base_config()
    _, _, result = _prepare(SINGLE_HOST_XML, cfg, AnalysisOptions())
    observed = [f for f in result.flows if f.evidence_class == EvidenceClass.OBSERVED.value]
    assert len(observed) == 1
    flow = observed[0]
    assert flow.source == "192.168.1.50"
    assert flow.destination == "192.168.10.20"
    assert flow.direction == "inbound"
    assert flow.destination_port == 443
    # Zones resolved from configuration prefixes.
    assert flow.source_zone == "Management"
    assert flow.destination_zone == "Servers"


def test_closed_and_filtered_ports_produce_no_flows():
    cfg = base_config()
    _, _, result = _prepare(MULTI_HOST_XML, cfg, AnalysisOptions())
    ports = {(f.destination, f.destination_port) for f in result.flows}
    assert ("192.168.10.20", 3306) not in ports  # closed
    assert ("192.168.10.20", 8443) not in ports  # filtered


def test_open_filtered_excluded_by_default_but_reviewed():
    cfg = base_config()
    _, _, result = _prepare(MULTI_HOST_XML, cfg, AnalysisOptions())
    ports = {(f.destination, f.destination_port) for f in result.flows}
    assert ("192.168.10.30", 161) not in ports
    assert any(r.port == "161" for r in result.reviews)


def test_open_filtered_included_only_as_manual_review():
    cfg = base_config()
    opts = AnalysisOptions(include_open_filtered=True)
    _, _, result = _prepare(MULTI_HOST_XML, cfg, opts)
    matches = [f for f in result.flows if f.destination_port == 161]
    assert matches
    assert all(
        f.evidence_class == EvidenceClass.MANUAL_REVIEW.value for f in matches
    )


def test_inferred_outbound_requires_flag_and_infrastructure():
    cfg = base_config()
    cfg.infrastructure = {"dns_servers": ["192.168.1.10"]}
    # Without the flag: no inferred flows at all.
    _, _, result = _prepare(SINGLE_HOST_XML, cfg, AnalysisOptions())
    assert not [
        f for f in result.flows if f.evidence_class == EvidenceClass.INFERRED.value
    ]
    # With the flag: DNS dependency inferred, clearly labeled, outbound.
    opts = AnalysisOptions(include_inferred_outbound=True)
    _, _, result = _prepare(SINGLE_HOST_XML, cfg, opts)
    inferred = [
        f for f in result.flows if f.evidence_class == EvidenceClass.INFERRED.value
    ]
    assert inferred
    dns = [f for f in inferred if f.destination == "192.168.1.10"]
    assert dns
    assert all(f.direction == "outbound" for f in dns)
    assert all("assum" in f.evidence.lower() or "inferred" in f.evidence.lower() for f in dns)


def test_user_defined_flow_classified_and_unverified():
    cfg = base_config()
    cfg.defined_flows = [
        {
            "source": "192.168.10.20",
            "destination": "192.168.10.30",
            "protocol": "tcp",
            "port": 5432,
            "purpose": "App to DB",
        }
    ]
    _, _, result = _prepare(MULTI_HOST_XML, cfg, AnalysisOptions())
    defined = [
        f for f in result.flows if f.evidence_class == EvidenceClass.USER_DEFINED.value
    ]
    # Requirement change (v1.1): one declared dependency yields BOTH a
    # source-side outbound and a destination-side inbound perspective.
    assert len(defined) == 2
    assert {f.direction for f in defined} == {"inbound", "outbound"}
    assert {f.perspective for f in defined} == {"source-outbound", "destination-inbound"}
    for flow in defined:
        assert flow.destination_port == 5432
        assert "not verified" in flow.evidence.lower()


def test_dedupe_keeps_highest_evidence():
    cfg = base_config()
    # Declare the same flow the scanner also observed: scanner -> web01:443.
    cfg.defined_flows = [
        {
            "source": "192.168.1.50",
            "destination": "192.168.10.20",
            "protocol": "tcp",
            "port": 443,
        }
    ]
    _, _, result = _prepare(SINGLE_HOST_XML, cfg, AnalysisOptions())
    matches = [
        f
        for f in result.flows
        if f.destination == "192.168.10.20"
        and f.destination_port == 443
        and f.direction == "inbound"
    ]
    # The inbound perspective deduplicates against the observed flow and the
    # higher evidence class wins; the outbound perspective is a separate,
    # source-side candidate and does not collide.
    assert len(matches) == 1
    assert matches[0].evidence_class == EvidenceClass.OBSERVED.value


def test_group_edges_deduplicates():
    cfg = base_config()
    _, _, result = _prepare(MULTI_HOST_XML, cfg, AnalysisOptions())
    summary = group_edges(result.flows, "summary")
    full = group_edges(result.flows, "full")
    keys = [(e.src, e.dst, e.evidence_class) for e in summary]
    assert len(keys) == len(set(keys))
    # web01 exposes two open ports; summary and full views share edge keys.
    assert {(e.src, e.dst) for e in summary} == {(e.src, e.dst) for e in full}
