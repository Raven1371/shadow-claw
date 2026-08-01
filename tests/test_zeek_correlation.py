"""Tests for Zeek <-> Nmap <-> configuration correlation (v1.2.0).

The Nmap fixture (MULTI_HOST_XML) provides:
  192.168.10.20 (web01): tcp/22 open, tcp/80 open, tcp/3306 closed,
                          tcp/8443 filtered
  192.168.10.30 (db01):  tcp/5432 open, udp/161 open|filtered, tcp/9999 open
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from nmap_flow_analyzer.models import EvidenceClass
from nmap_flow_analyzer.zeek_correlation import NOT_OBSERVED_TEXT
from tests.zeek_fixtures import conn, correlated, write_json_log, zeek_config


def _flows_for(data, dst, port, proto="tcp"):
    return [
        f for f in data["flows"]
        if f.destination == dst and f.destination_port == port
        and f.protocol == proto
    ]


def test_zeek_flow_to_nmap_open_service_is_corroborated():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432,
                 service="postgresql"),
        ])
        data = correlated(Path(tmp))
        flows = [f for f in _flows_for(data, "192.168.10.30", 5432)
                 if f.source == "192.168.20.15"]
        assert flows, "Zeek flow was not created"
        for flow in flows:
            assert flow.correlation_status == "nmap-and-zeek"
            assert flow.nmap_observation == "service open (Nmap)"
            assert flow.evidence_sources == ["nmap", "zeek"]
            assert flow.evidence_class == EvidenceClass.OBSERVED.value
        record = next(r for r in data["records"]
                      if r.ip == "192.168.10.30" and r.port == 5432)
        assert record.correlation_status == "nmap-and-zeek"
        assert record.zeek_observation == "active traffic observed"


def test_zeek_flow_to_closed_port_is_conflicting_and_reviewed():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.20", 3306),  # Nmap: closed
        ])
        data = correlated(Path(tmp))
        flows = _flows_for(data, "192.168.10.20", 3306)
        assert flows
        for flow in flows:
            assert flow.correlation_status == "conflicting-evidence"
            assert "closed" in flow.nmap_observation
            assert flow.manual_review_reason  # rules withheld
        assert any(f.category == "Correlation discrepancy"
                   for f in data["corr"].findings)
        assert any(r.category == "Correlation discrepancy"
                   for r in data["corr"].reviews)
        # Withheld: no candidate rule reaches the exception lists.
        from nmap_flow_analyzer.firewall_rules import build_inbound
        inbound, _ = build_inbound(data["flows"], data["config"], data["options"])
        assert not any(r.destination == "192.168.10.20" and r.port == "3306"
                       for r in inbound)


def test_zeek_flow_to_filtered_port_is_conflicting():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.20", 8443),  # Nmap: filtered
        ])
        data = correlated(Path(tmp))
        flows = _flows_for(data, "192.168.10.20", 8443)
        assert flows and all(
            f.correlation_status == "conflicting-evidence" for f in flows
        )
        assert any("filtered" in f.nmap_observation for f in flows)


def test_zeek_flow_outside_scope_becomes_external_dependency():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "203.0.113.50", 443, service="ssl"),
        ])
        data = correlated(Path(tmp))
        externals = data["corr"].external_dependencies
        assert [(a.responder, a.responder_port) for a in externals] == [
            ("203.0.113.50", 443)
        ]
        assert any(f.category == "External dependency"
                   for f in data["corr"].findings)
        flows = _flows_for(data, "203.0.113.50", 443)
        assert flows
        for flow in flows:
            assert flow.destination_zone == "External"
            assert flow.manual_review_reason  # external rules disabled by default


def test_external_rules_allowed_only_when_configured():
    cfg = zeek_config(include_external_dependencies_in_rules=True)
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "203.0.113.50", 443, service="ssl"),
        ])
        data = correlated(Path(tmp), cfg)
        flows = _flows_for(data, "203.0.113.50", 443)
        assert flows and all(not f.manual_review_reason for f in flows)
        # Still concrete IPs, never FQDNs.
        assert all(f.destination == "203.0.113.50" for f in flows)


def test_zeek_flow_to_unscanned_internal_host():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.40.9", 636, service="ssl"),
        ])
        data = correlated(Path(tmp))
        flows = _flows_for(data, "192.168.40.9", 636)
        assert flows and all(
            f.correlation_status == "zeek-traffic-only" for f in flows
        )
        assert any(f.category == "Unscanned dependency"
                   for f in data["corr"].findings)
        assert not data["corr"].external_dependencies  # inside monitored nets


def test_user_defined_flow_observed_by_zeek_is_merged():
    cfg = zeek_config()
    cfg.defined_flows = [{
        "source": "192.168.10.20", "destination": "192.168.10.30",
        "protocol": "tcp", "port": 5432, "purpose": "App DB",
    }]
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.10.20", "192.168.10.30", 5432,
                 service="postgresql"),
            conn("C2", "192.168.10.20", "192.168.10.30", 5432, ts=60.0,
                 service="postgresql"),
        ])
        data = correlated(Path(tmp), cfg)
        flows = [f for f in _flows_for(data, "192.168.10.30", 5432)
                 if f.source == "192.168.10.20"]
        assert flows, "declared flow disappeared"
        for flow in flows:
            assert flow.correlation_status == "user-defined-and-zeek"
            # v1.2.1 (defect 5): Nmap reports db01 tcp/5432 open, so its
            # corroboration is preserved in canonical order alongside the
            # declaration and the Zeek observation.
            assert flow.evidence_sources == [
                "nmap", "zeek", "user_configuration",
            ]
            assert flow.connection_count == 2
            assert flow.successful_connections == 2
            assert flow.purpose == "App DB"  # declared intent preserved
            assert flow.evidence_class == EvidenceClass.OBSERVED.value
            assert "declared dependency" in flow.evidence


def test_user_defined_flow_not_observed_gets_finding():
    cfg = zeek_config()
    cfg.defined_flows = [{
        "source": "192.168.10.20", "destination": "192.168.10.30",
        "protocol": "tcp", "port": 5432,
    }]
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.1.10", 53, proto="udp",
                 resp_bytes=100, resp_pkts=1),
        ])
        data = correlated(Path(tmp), cfg)
        declared = [f for f in _flows_for(data, "192.168.10.30", 5432)
                    if f.source == "192.168.10.20"
                    and f.evidence_class == EvidenceClass.USER_DEFINED.value]
        assert declared
        for flow in declared:
            assert flow.correlation_status == "user-defined-only"
            assert flow.zeek_observation == NOT_OBSERVED_TEXT
        finding = next(f for f in data["corr"].findings
                       if f.category == "Declared dependency not observed")
        assert "not proof it is unnecessary" in finding.recommendation


def test_nmap_only_exposure_never_labeled_unused():
    with tempfile.TemporaryDirectory() as tmp:
        # Zeek sees only db01:5432; web01's 22/80 get no traffic.
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        data = correlated(Path(tmp))
        untouched = [r for r in data["records"]
                     if r.ip == "192.168.10.20" and r.state == "open"]
        assert untouched
        for record in untouched:
            assert record.zeek_observation == NOT_OBSERVED_TEXT
            assert record.correlation_status == "nmap-reachability-only"
        findings = [f for f in data["corr"].findings
                    if f.category == "Exposed service without observed traffic"]
        assert findings
        for finding in findings:
            assert "Do NOT treat this as unused" in finding.recommendation
        # The word "unused" never appears as a bare label anywhere.
        for record in data["records"]:
            assert record.zeek_observation.lower() not in (
                "unused", "unneeded", "safe to remove"
            )
        # Nmap observed flows keep their reachability meaning.
        nmap_flows = [f for f in _flows_for(data, "192.168.10.20", 22)
                      if f.evidence_class == EvidenceClass.OBSERVED.value]
        assert all(f.correlation_status == "nmap-reachability-only"
                   for f in nmap_flows)
        assert all(f.zeek_observation == NOT_OBSERVED_TEXT for f in nmap_flows)


def test_service_identification_conflict_detected():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432, service="http"),
        ])
        data = correlated(Path(tmp))
        conflict = [f for f in data["corr"].findings
                    if f.category == "Service identification conflict"]
        assert conflict
        assert "http" in conflict[0].detail


def test_service_synonyms_do_not_false_positive():
    with tempfile.TemporaryDirectory() as tmp:
        # Zeek "postgresql" vs Nmap "PostgreSQL DB" must not conflict.
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432,
                 service="postgresql"),
        ])
        data = correlated(Path(tmp))
        assert not [f for f in data["corr"].findings
                    if f.category == "Service identification conflict"]


def test_dns_and_tls_identity_enrichment_on_endpoints():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("Cdns", "192.168.20.15", "192.168.1.10", 53, proto="udp",
                 resp_bytes=100, resp_pkts=1, service="dns"),
            conn("Ctls", "192.168.20.15", "192.168.10.30", 5432,
                 service="ssl"),
        ])
        write_json_log(Path(tmp), "dns.log", [
            {"ts": 1.0, "uid": "Cdns", "query": "db01.example.local",
             "qtype_name": "A", "rcode_name": "NOERROR",
             "answers": ["192.168.10.30"]},
        ])
        write_json_log(Path(tmp), "ssl.log", [
            {"ts": 1.0, "uid": "Ctls", "server_name": "db01.example.local",
             "version": "TLSv1.2", "subject": "CN=db01.example.local"},
        ])
        data = correlated(Path(tmp))
        endpoint = next(e for e in data["corr"].endpoints
                        if e.ip == "192.168.10.30")
        assert "db01.example.local" in endpoint.dns_aliases
        assert "db01.example.local" in endpoint.tls_server_names
        assert "CN=db01.example.local" in endpoint.certificate_identities
        # Nmap PTR hostname wins over DNS alias for the device identity.
        assert endpoint.device_hostname == "db01.example.local"
        assert endpoint.device_hostname_source in ("nmap", "configuration")


def test_sni_never_becomes_device_identity():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("Ctls", "192.168.20.15", "192.168.40.80", 443, service="ssl"),
        ])
        write_json_log(Path(tmp), "ssl.log", [
            {"ts": 1.0, "uid": "Ctls", "server_name": "shared.cdn.example",
             "version": "TLSv1.3"},
        ])
        data = correlated(Path(tmp))
        endpoint = next(e for e in data["corr"].endpoints
                        if e.ip == "192.168.40.80")
        assert "shared.cdn.example" in endpoint.tls_server_names
        assert endpoint.device_hostname != "shared.cdn.example"
        assert endpoint.display_name == "192.168.40.80"


def test_dhcp_hostname_beats_dns_alias_for_identity():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.40.7", "192.168.10.30", 5432),
        ])
        write_json_log(Path(tmp), "dhcp.log", [
            {"ts": 1.0, "uids": [], "host_name": "laptop-07",
             "assigned_addr": "192.168.40.7"},
        ])
        write_json_log(Path(tmp), "dns.log", [
            {"ts": 1.0, "uid": "C1", "query": "laptop-alias.example",
             "answers": ["192.168.40.7"]},
        ])
        data = correlated(Path(tmp))
        endpoint = next(e for e in data["corr"].endpoints
                        if e.ip == "192.168.40.7")
        assert endpoint.device_hostname == "laptop-07"
        assert endpoint.device_hostname_source == "dhcp"


def test_endpoint_observation_sources_distinguished():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
            conn("C2", "192.168.20.15", "203.0.113.50", 443),
        ])
        data = correlated(Path(tmp))
        sources = {e.ip: e.observation_source for e in data["corr"].endpoints}
        assert sources["192.168.10.30"] == "Nmap and Zeek"
        assert sources["192.168.10.20"] == "Nmap scanned"  # no Zeek traffic
        assert sources["192.168.20.15"] == "Zeek observed"
        assert sources["203.0.113.50"] == "External"


def test_different_originators_produce_distinct_flows():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
            conn("C2", "192.168.20.16", "192.168.10.30", 5432),
        ])
        data = correlated(Path(tmp))
        sources = {f.source for f in _flows_for(data, "192.168.10.30", 5432)}
        assert {"192.168.20.15", "192.168.20.16"} <= sources
        # And their statistics were not cross-polluted.
        for flow in _flows_for(data, "192.168.10.30", 5432):
            if flow.source in ("192.168.20.15", "192.168.20.16"):
                assert flow.connection_count == 1


def test_scanner_flow_not_merged_into_production_client_flow():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("Cscan", "192.168.1.50", "192.168.10.30", 5432),  # the scan
            conn("Cprod", "192.168.10.20", "192.168.10.30", 5432),  # a client
        ])
        data = correlated(Path(tmp))
        prod = [f for f in _flows_for(data, "192.168.10.30", 5432)
                if f.source == "192.168.10.20"]
        assert prod
        for flow in prod:
            assert flow.connection_count == 1  # scanner's conn not merged in
            assert "scanner" not in flow.zeek_observation
        scanner = [f for f in _flows_for(data, "192.168.10.30", 5432)
                   if f.source == "192.168.1.50"]
        # The Nmap-observed scanner flow carries the scanner-audit marking.
        assert scanner
        assert any(
            f.zeek_observation == "scanner-generated traffic observed by sensor"
            for f in scanner
        )


def test_scanner_traffic_creates_no_new_flow_by_default():
    with tempfile.TemporaryDirectory() as tmp:
        # Scanner talks to a port Nmap did not report (no existing flow).
        write_json_log(Path(tmp), "conn.log", [
            conn("Cscan", "192.168.1.50", "192.168.40.77", 8080),
        ])
        data = correlated(Path(tmp))
        assert not _flows_for(data, "192.168.40.77", 8080)


def test_attempted_traffic_collected_not_flowed():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 445, state="REJ",
                 resp_bytes=0, orig_bytes=0),
            conn("C2", "192.168.20.15", "192.168.10.20", 162, proto="udp",
                 state="S0", resp_bytes=0, resp_pkts=0),
        ])
        data = correlated(Path(tmp))
        attempted = {(a.responder, a.responder_port): a.outcome_label
                     for a in data["corr"].attempted}
        assert attempted[("192.168.10.30", 445)] == "rejected"
        assert attempted[("192.168.10.20", 162)] == "one-way"
        assert not _flows_for(data, "192.168.10.30", 445)
        assert not _flows_for(data, "192.168.10.20", 162, proto="udp")


def test_attempted_flows_in_diagram_when_configured():
    cfg = zeek_config(include_attempted_flows_in_diagram=True)
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 445, state="REJ"),
        ])
        data = correlated(Path(tmp), cfg)
        flows = _flows_for(data, "192.168.10.30", 445)
        assert flows
        for flow in flows:
            assert flow.correlation_status == "attempted-only"
            assert flow.evidence_class == EvidenceClass.MANUAL_REVIEW.value
            assert flow.manual_review_reason  # can never become a rule


def test_excessive_failed_attempts_finding():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn(f"C{i}", "192.168.20.15", "192.168.10.30", 445, state="REJ",
                 ts=float(i))
            for i in range(12)
        ])
        data = correlated(Path(tmp))
        assert any(f.category == "Excessive failed attempts"
                   for f in data["corr"].findings)


def test_icmp_gets_review_not_port_rules():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 8, proto="icmp",
                 resp_pkts=1, resp_bytes=56),
        ])
        data = correlated(Path(tmp))
        icmp_flows = _flows_for(data, "192.168.10.30", 8, proto="icmp")
        assert icmp_flows
        for flow in icmp_flows:
            assert flow.manual_review_reason
        assert any(r.category == "ICMP policy" for r in data["corr"].reviews)
        from nmap_flow_analyzer.firewall_rules import build_inbound, build_outbound
        inbound, _ = build_inbound(data["flows"], data["config"], data["options"])
        outbound, _ = build_outbound(data["flows"], inbound, data["config"],
                                     data["options"])
        assert not any(r.protocol == "icmp" for r in inbound + outbound)


def test_cleartext_protocol_finding():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.20", 80, service="http"),
        ])
        data = correlated(Path(tmp))
        assert any(f.category == "Cleartext protocol"
                   for f in data["corr"].findings)


def test_capture_loss_above_threshold_creates_review():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        write_json_log(Path(tmp), "capture_loss.log",
                       [{"ts": 1.0, "percent_lost": 5.0}])
        data = correlated(Path(tmp))
        assert any(r.category == "Zeek sensor health"
                   for r in data["corr"].reviews)
        assert any(f.category == "Sensor degradation"
                   for f in data["corr"].findings)
        # Degradation lowers confidence but never deletes observed flows.
        assert _flows_for(data, "192.168.10.30", 5432)


def test_findings_have_deterministic_ids():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "203.0.113.50", 443),
            conn("C2", "192.168.20.15", "192.168.10.20", 3306),
        ])
        first = correlated(Path(tmp))
        second = correlated(Path(tmp))
        ids_a = [(f.finding_id, f.category) for f in first["corr"].findings]
        ids_b = [(f.finding_id, f.category) for f in second["corr"].findings]
        assert ids_a == ids_b
        assert ids_a[0][0] == "CF-0001"
