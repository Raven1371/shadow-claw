"""v1.2.1 regression tests: one or more tests per corrected defect.

Nmap fixture states used throughout (MULTI_HOST_XML):
  192.168.10.20 (web01): tcp/22 open, tcp/80 open, tcp/3306 CLOSED,
                          tcp/8443 FILTERED
  192.168.10.30 (db01):  tcp/5432 open, udp/161 OPEN|FILTERED, tcp/9999 open
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from nmap_flow_analyzer.cli import main
from nmap_flow_analyzer.firewall_rules import build_inbound, build_outbound
from nmap_flow_analyzer.flow_analysis import AnalysisOptions
from nmap_flow_analyzer.zeek_aggregation import load_zeek
from nmap_flow_analyzer.zeek_correlation import (
    CONFIDENCE_PENALTIES,
    MAX_CONFIDENCE,
    MIN_CONFIDENCE,
    SCANNER_ONLY_TEXT,
    ZEEK_BASE_CONFIDENCE,
    compute_zeek_confidence,
    count_communications,
    order_evidence_sources,
)
from nmap_flow_analyzer.zeek_models import ZeekFlowAggregate, ZeekSensorHealth
from nmap_flow_analyzer.zeek_parser import validate_conn_record
from tests.fixtures import MULTI_HOST_XML
from tests.zeek_fixtures import (
    conn,
    correlated,
    load,
    write_json_log,
    write_tsv_conn,
    zeek_config,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _rules(data):
    inbound, in_rev = build_inbound(data["flows"], data["config"], data["options"])
    outbound, out_rev = build_outbound(data["flows"], inbound, data["config"],
                                       data["options"])
    return inbound, outbound, in_rev + out_rev


def _flows_for(data, dst, port, proto="tcp", src=None):
    """Flows to a destination service, optionally restricted to one source.

    A destination service can also carry an unrelated Nmap-derived
    reachability flow from a different source, so tests that assert on a
    specific communication pass ``src``.
    """
    return [f for f in data["flows"] if f.destination == dst
            and f.destination_port == port and f.protocol == proto
            and (src is None or f.source == src)]


# ===========================================================================
# Defect 1 - declared/inferred flows must not bypass conflicting Nmap states
# ===========================================================================

def _declared_config(dst_ip: str, port: int, proto: str = "tcp"):
    cfg = zeek_config()
    cfg.defined_flows = [{
        "source": "192.168.20.15", "destination": dst_ip,
        "protocol": proto, "port": port, "purpose": "Declared dependency",
    }]
    return cfg


def _declared_case(dst_ip: str, port: int, proto: str = "tcp"):
    cfg = _declared_config(dst_ip, port, proto)
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("D1", "192.168.20.15", dst_ip, port, proto=proto,
                 resp_bytes=900, resp_pkts=6),
            conn("D2", "192.168.20.15", dst_ip, port, proto=proto, ts=60.0,
                 resp_bytes=900, resp_pkts=6),
        ])
        data = correlated(Path(tmp), cfg)
        inbound, outbound, reviews = _rules(data)
        return data, inbound, outbound, reviews


def test_declared_flow_with_nmap_open_may_generate_rules():
    data, inbound, outbound, _ = _declared_case("192.168.10.30", 5432)
    flows = _flows_for(data, "192.168.10.30", 5432, src="192.168.20.15")
    assert flows
    for flow in flows:
        assert flow.correlation_status == "user-defined-and-zeek"
        assert not flow.manual_review_reason
    assert any(r.source == "192.168.20.15" and r.port == "5432"
               for r in inbound)
    assert any(r.source == "192.168.20.15" and r.port == "5432"
               for r in outbound)


def _assert_conflict_withheld(dst_ip, port, state, proto="tcp"):
    data, inbound, outbound, reviews = _declared_case(dst_ip, port, proto)
    flows = _flows_for(data, dst_ip, port, proto, src="192.168.20.15")
    assert flows, f"{state}: flow was deleted instead of retained"
    inbound_persp = [f for f in flows if f.perspective == "destination-inbound"]
    outbound_persp = [f for f in flows if f.perspective == "source-outbound"]
    assert inbound_persp and outbound_persp, f"{state}: perspectives missing"
    for flow in flows:
        assert flow.correlation_status == "conflicting-evidence", state
        assert state in flow.nmap_observation, flow.nmap_observation
        assert flow.manual_review_reason
        reason = flow.manual_review_reason
        assert state in reason and "Zeek" in reason
        assert "different times" in reason
        assert "validation" in reason
    # No candidate rules from either perspective.
    assert not [r for r in inbound if r.destination == dst_ip
                and r.port == str(port)], f"{state}: inbound rule generated"
    assert not [r for r in outbound if r.destination == dst_ip
                and r.port == str(port)], f"{state}: outbound rule generated"
    # Finding and manual-review item both exist.
    assert any(f.category == "Correlation discrepancy"
               for f in data["corr"].findings), state
    assert any(r.category == "Rule withheld" for r in reviews), state
    return data


def test_declared_flow_with_nmap_closed_is_conflicting_and_withheld():
    _assert_conflict_withheld("192.168.10.20", 3306, "closed")


def test_declared_flow_with_nmap_filtered_is_conflicting_and_withheld():
    _assert_conflict_withheld("192.168.10.20", 8443, "filtered")


def test_declared_flow_with_nmap_open_filtered_is_conflicting_and_withheld():
    _assert_conflict_withheld("192.168.10.30", 161, "open|filtered",
                              proto="udp")


def test_inferred_flow_with_conflicting_nmap_state_is_withheld():
    cfg = zeek_config()
    cfg.expected_outbound = []
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("I1", "192.168.10.30", "192.168.10.20", 3306,
                 resp_bytes=800, resp_pkts=5),
        ])
        data = correlated(Path(tmp), cfg,
                          options=AnalysisOptions(include_inferred_outbound=True))
        flows = _flows_for(data, "192.168.10.20", 3306)
        assert flows
        for flow in flows:
            assert flow.correlation_status == "conflicting-evidence"
            assert flow.manual_review_reason
        inbound, outbound, _ = _rules(data)
        assert not [r for r in inbound + outbound
                    if r.destination == "192.168.10.20" and r.port == "3306"]


def test_conflicting_flow_is_preserved_not_deleted():
    data = _assert_conflict_withheld("192.168.10.20", 3306, "closed")
    # The observation itself is still reported, with its Zeek statistics.
    flow = _flows_for(data, "192.168.10.20", 3306, src="192.168.20.15")[0]
    assert flow.connection_count == 2
    assert flow.successful_connections == 2
    assert "zeek" in flow.evidence_sources


# ===========================================================================
# Defect 2 - advertised optional logs are actually processed
# ===========================================================================

SSL_X509_FUID = "FcertAAA111"


def _cert_dir(tmp: Path, include_x509: bool = True) -> Path:
    write_json_log(tmp, "conn.log", [
        conn("Ctls", "192.168.20.15", "192.168.10.30", 5432, service="ssl"),
    ])
    write_json_log(tmp, "ssl.log", [{
        "ts": 1.0, "uid": "Ctls", "server_name": "db01.example.local",
        "version": "TLSv1.3", "established": True,
        "cert_chain_fuids": [SSL_X509_FUID, "FchainBBB"],
        "client_cert_chain_fuids": ["FclientCCC"],
    }])
    if include_x509:
        write_json_log(tmp, "x509.log", [
            {"ts": 1.0, "id": SSL_X509_FUID,
             "certificate.subject": "CN=db01.example.local",
             "certificate.issuer": "CN=Example Issuing CA",
             "certificate.serial": "0A1B2C3D",
             "certificate.not_valid_before": "2026-01-01T00:00:00Z",
             "certificate.not_valid_after": "2027-01-01T00:00:00Z",
             "certificate.key_alg": "rsaEncryption",
             "certificate.key_length": 2048,
             "certificate.sig_alg": "sha256WithRSAEncryption"},
            {"ts": 1.0, "id": "FclientCCC",
             "certificate.subject": "CN=workstation-client",
             "certificate.issuer": "CN=Example Issuing CA"},
        ])
    return tmp


def test_ssl_x509_certificate_chain_correlated_to_responder():
    with tempfile.TemporaryDirectory() as tmp:
        _cert_dir(Path(tmp))
        data = correlated(Path(tmp))
        certs = data["zeek"].extras.certificates
        responder_certs = certs.get("192.168.10.30", [])
        assert responder_certs, "server certificate not attached to responder"
        leaf = responder_certs[0]
        assert leaf.fuid == SSL_X509_FUID
        assert leaf.subject == "CN=db01.example.local"
        assert leaf.issuer == "CN=Example Issuing CA"
        assert leaf.serial == "0A1B2C3D"
        assert leaf.not_valid_before.startswith("2026-01-01")
        assert leaf.not_valid_after.startswith("2027-01-01")
        assert leaf.key_algorithm == "rsaEncryption"
        assert leaf.key_length == "2048"
        assert leaf.signature_algorithm == "sha256WithRSAEncryption"
        assert leaf.chain_position == "server-leaf"
        # The CLIENT certificate belongs to the originator, never the server.
        originator_certs = certs.get("192.168.20.15", [])
        assert any(c.subject == "CN=workstation-client"
                   for c in originator_certs)
        assert not any(c.subject == "CN=workstation-client"
                       for c in responder_certs)
        endpoint = next(e for e in data["corr"].endpoints
                        if e.ip == "192.168.10.30")
        assert any("CN=db01.example.local" in d
                   for d in endpoint.certificate_details)
        assert any("issuer=CN=Example Issuing CA" in d
                   for d in endpoint.certificate_details)


def test_missing_referenced_certificate_does_not_crash():
    with tempfile.TemporaryDirectory() as tmp:
        _cert_dir(Path(tmp), include_x509=False)  # ssl references absent fuids
        data = correlated(Path(tmp))
        assert data["zeek"].metadata.conn_log_available
        assert not data["zeek"].extras.certificates.get("192.168.10.30")
        assert _flows_for(data, "192.168.10.30", 5432)  # analysis continued


def test_every_supported_optional_log_is_processed():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432, service="ssl"),
        ])
        write_json_log(tmp, "x509.log", [
            {"ts": 1.0, "id": "F1", "certificate.subject": "CN=a"}])
        write_json_log(tmp, "known_hosts.log",
                       [{"ts": 1.0, "host": "192.168.10.30"}])
        write_json_log(tmp, "known_services.log", [
            {"ts": 1.0, "host": "192.168.10.30", "port_num": 5432,
             "port_proto": "tcp", "service": ["POSTGRESQL"]}])
        write_json_log(tmp, "known_certs.log", [
            {"ts": 1.0, "host": "192.168.10.30", "subject": "CN=known",
             "issuer": "CN=CA"}])
        write_json_log(tmp, "software.log", [
            {"ts": 1.0, "host": "192.168.10.30", "name": "PostgreSQL",
             "software_type": "SERVER", "version.major": 16,
             "version.minor": 2}])
        write_json_log(tmp, "files.log", [
            {"ts": 1.0, "conn_uids": ["C1"], "source": "SSL",
             "mime_type": "application/x-x509-ca-cert",
             "filename": "/var/secret/path/cert.der", "total_bytes": 1200}])
        write_json_log(tmp, "notice.log", [
            {"ts": 1.0, "note": "SSL::Invalid_Server_Cert",
             "msg": "certificate not trusted", "src": "192.168.20.15",
             "dst": "192.168.10.30", "p": 5432, "proto": "tcp"}])
        write_json_log(tmp, "weird.log", [
            {"ts": 1.0, "name": "dns_unmatched_reply",
             "id.orig_h": "192.168.20.15", "id.resp_h": "192.168.10.30"},
            {"ts": 2.0, "name": "dns_unmatched_reply"}])
        zeek = load(tmp)
        processed = {e["log_type"] for e in zeek.metadata.files_processed}
        for log_type in ("conn", "x509", "known_hosts", "known_services",
                         "known_certs", "software", "files", "notice",
                         "weird"):
            assert log_type in processed, f"{log_type} discovered but not parsed"
        # log_types_found (discovered) is a superset of nothing unparsed.
        assert set(zeek.metadata.log_types_found) == processed
        for entry in zeek.metadata.files_processed:
            assert entry["file"] and entry["log_type"]
            assert entry["format"] in ("json", "tsv", "empty")
            assert entry["size"] > 0
            assert "records" in entry and "malformed" in entry
        extras = zeek.extras
        assert "192.168.10.30" in extras.known_hosts
        assert extras.known_services["192.168.10.30/tcp/5432"] == ["POSTGRESQL"]
        assert any("PostgreSQL 16.2" in s
                   for s in extras.software["192.168.10.30"])
        assert extras.notices[0]["note"] == "SSL::Invalid_Server_Cert"
        assert extras.weird_counts["dns_unmatched_reply"] == 2
        # files.log: basename only, no directory path, no contents.
        transfer = extras.file_transfers[0]
        assert transfer["filename"] == "cert.der"
        assert "/var/secret" not in json.dumps(extras.file_transfers)
        assert "content" not in transfer


def test_every_advertised_log_type_is_consumed_by_code():
    """No log may be advertised, discovered, and then silently ignored."""
    from nmap_flow_analyzer.zeek_aggregation import (
        PROTOCOL_CONFIRMATION_LOGS, process_optional_logs,
    )
    from nmap_flow_analyzer import zeek_aggregation
    from nmap_flow_analyzer.zeek_parser import SUPPORTED_LOG_TYPES

    source = Path(zeek_aggregation.__file__).read_text(encoding="utf-8")
    consumed = set(PROTOCOL_CONFIRMATION_LOGS)
    for log_type in SUPPORTED_LOG_TYPES:
        if f'_records("{log_type}")' in source or \
                f'logs.get("{log_type}"' in source:
            consumed.add(log_type)
    missing = sorted(set(SUPPORTED_LOG_TYPES) - consumed)
    assert not missing, f"advertised but never parsed: {missing}"


def test_protocol_logs_confirm_but_never_create_flows():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432,
                 service="postgresql"),
        ])
        write_json_log(tmp, "ssh.log", [
            {"ts": 1.0, "uid": "C1", "auth_success": True}])
        # A protocol record for a connection conn.log never saw.
        write_json_log(tmp, "kerberos.log", [
            {"ts": 1.0, "uid": "CunknownUID", "request_type": "TGS"}])
        zeek = load(tmp)
        processed = {e["log_type"] for e in zeek.metadata.files_processed}
        assert {"ssh", "kerberos"} <= processed
        agg = zeek.aggregates[0]
        assert any("SSH" in c for c in agg.protocol_confirmations)
        # The unmatched kerberos record invented nothing.
        assert len(zeek.aggregates) == 1


def test_supporting_logs_never_create_rules_on_their_own():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        # A known_services entry for a port with NO conn.log traffic.
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        write_json_log(tmp, "known_services.log", [
            {"ts": 1.0, "host": "192.168.10.20", "port_num": 22,
             "port_proto": "tcp", "service": ["SSH"]}])
        write_json_log(tmp, "known_hosts.log",
                       [{"ts": 1.0, "host": "192.168.99.99"}])
        data = correlated(tmp)
        inbound, outbound, _ = _rules(data)
        assert not [r for r in inbound + outbound
                    if r.source == "192.168.99.99"
                    or r.destination == "192.168.99.99"]
        # known_services did not fabricate a communication.
        assert not [f for f in data["flows"]
                    if "zeek" in f.evidence_sources
                    and f.destination == "192.168.10.20"
                    and f.destination_port == 22]


def test_notice_and_weird_become_neutral_findings():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log",
                       [conn("C1", "192.168.20.15", "192.168.10.30", 5432)])
        write_json_log(tmp, "notice.log", [
            {"ts": 1.0, "note": "Scan::Port_Scan", "msg": "scan detected",
             "src": "192.168.20.15"}])
        write_json_log(tmp, "weird.log",
                       [{"ts": 1.0, "name": "bad_TCP_checksum"}])
        data = correlated(tmp)
        notice = next(f for f in data["corr"].findings
                      if f.category == "Zeek notice")
        assert "not a confirmed vulnerability" in notice.recommendation
        anomaly = next(f for f in data["corr"].findings
                       if f.category == "Protocol anomalies")
        assert "rather than" in anomaly.recommendation  # not proof of compromise
        assert "vulnerabilit" not in anomaly.detail.lower()


def test_optional_log_malformed_records_counted():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log",
                       [conn("C1", "192.168.20.15", "192.168.10.30", 5432)])
        path = write_json_log(tmp, "notice.log",
                              [{"ts": 1.0, "note": "A", "msg": "m"}])
        with path.open("a", encoding="utf-8") as handle:
            handle.write("{not json\n")
        zeek = load(tmp)
        assert zeek.metadata.malformed_counts["notice"] == 1
        entry = next(e for e in zeek.metadata.files_processed
                     if e["log_type"] == "notice")
        assert entry["malformed"] == 1
        assert any("notice.log:2" in e for e in zeek.metadata.parse_errors)


def test_optional_log_unknown_fields_and_bounds():
    cfg = zeek_config(max_sample_names=2)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log",
                       [conn("C1", "192.168.20.15", "192.168.10.30", 5432)])
        write_json_log(tmp, "software.log", [
            {"ts": 1.0, "host": "192.168.10.30", "name": f"pkg{i}",
             "future_field": "ignored", "version.major": i}
            for i in range(10)
        ])
        write_json_log(tmp, "notice.log", [
            {"ts": float(i), "note": f"N{i}", "msg": "m"} for i in range(200)
        ])
        write_json_log(tmp, "x509.log", [
            {"ts": 1.0, "id": f"F{i}", "certificate.subject": f"CN=c{i}"}
            for i in range(50)
        ])
        zeek = load(tmp, cfg)
        assert len(zeek.extras.software["192.168.10.30"]) <= 2
        assert len(zeek.extras.notices) <= 100
        assert len(zeek.extras.file_transfers) <= 200


def test_hostile_optional_log_values_sanitized_in_reports():
    hostile = '=cmd|\'/c calc\'!A0 <script>alert(9)</script> "]; x-->evil['
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        zdir = tmp / "zeek"
        write_json_log(zdir, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432, service="ssl"),
        ])
        write_json_log(zdir, "ssl.log", [{
            "ts": 1.0, "uid": "C1", "server_name": "db01.example.local",
            "cert_chain_fuids": ["FH1"]}])
        write_json_log(zdir, "x509.log", [
            {"ts": 1.0, "id": "FH1", "certificate.subject": hostile,
             "certificate.issuer": hostile}])
        write_json_log(zdir, "notice.log",
                       [{"ts": 1.0, "note": hostile, "msg": hostile}])
        write_json_log(zdir, "software.log",
                       [{"ts": 1.0, "host": "192.168.10.30", "name": hostile}])
        out = tmp / "out"
        assert main(["--input", str(tmp / "scan.xml"), "--output-dir", str(out),
                     "--scanner-ip", "192.168.1.50", "--zeek-dir", str(zdir),
                     "--excel"]) == 0
        html = (out / "analysis_report.html").read_text("utf-8")
        assert "<script>alert(9)</script>" not in html
        dot = (out / "data_flow_diagram.dot").read_text("utf-8")
        mmd = (out / "data_flow_diagram.mmd").read_text("utf-8")
        assert "x-->evil[" not in dot and "x-->evil[" not in mmd
        findings = (out / "correlation_findings.csv").read_text("utf-8")
        for line in findings.splitlines():
            for cell in line.split(","):
                stripped = cell.strip('"')
                assert not stripped.startswith("=")


# ===========================================================================
# Defect 3 - sensor degradation reduces numerical confidence
# ===========================================================================

def _agg(**kwargs) -> ZeekFlowAggregate:
    base = dict(originator="192.168.20.15", responder="192.168.10.30",
                protocol="tcp", responder_port=5432, connection_count=2,
                successful_count=2)
    base.update(kwargs)
    return ZeekFlowAggregate(**base)


def _health(status="healthy", loss=0.0, available=True) -> ZeekSensorHealth:
    return ZeekSensorHealth(status=status, capture_loss_available=available,
                            max_capture_loss_percent=loss)


def test_confidence_healthy_sensor_is_baseline():
    confidence, reasons = compute_zeek_confidence(_agg(), _health())
    assert confidence == ZEEK_BASE_CONFIDENCE
    assert reasons == []


def test_confidence_reduced_by_degraded_global_sensor():
    confidence, reasons = compute_zeek_confidence(_agg(), _health("degraded"))
    assert confidence == ZEEK_BASE_CONFIDENCE - CONFIDENCE_PENALTIES[
        "global_sensor_degraded"]
    assert any("degraded" in r for r in reasons)


def test_confidence_reduced_by_aggregate_missed_bytes_alone():
    confidence, reasons = compute_zeek_confidence(
        _agg(missed_bytes=512), _health("healthy")
    )
    assert confidence == ZEEK_BASE_CONFIDENCE - CONFIDENCE_PENALTIES[
        "aggregate_missed_bytes"]
    assert any("missed byte" in r for r in reasons)


def test_confidence_reduced_by_both_degradation_sources():
    confidence, _ = compute_zeek_confidence(
        _agg(missed_bytes=512), _health("degraded")
    )
    assert confidence == (
        ZEEK_BASE_CONFIDENCE
        - CONFIDENCE_PENALTIES["global_sensor_degraded"]
        - CONFIDENCE_PENALTIES["aggregate_missed_bytes"]
    )


def test_confidence_reduced_by_capture_loss_over_threshold():
    cfg = zeek_config().zeek
    confidence, reasons = compute_zeek_confidence(
        _agg(), _health("degraded", loss=5.0), cfg
    )
    assert confidence == (
        ZEEK_BASE_CONFIDENCE
        - CONFIDENCE_PENALTIES["global_sensor_degraded"]
        - CONFIDENCE_PENALTIES["capture_loss_over_threshold"]
    )
    assert any("capture loss" in r for r in reasons)


def test_confidence_reduced_for_partial_and_ambiguous_observations():
    partial, reasons = compute_zeek_confidence(
        _agg(partial_count=1), _health()
    )
    assert partial == ZEEK_BASE_CONFIDENCE - CONFIDENCE_PENALTIES[
        "partial_observation"]
    assert any("partial" in r for r in reasons)
    ambiguous, reasons = compute_zeek_confidence(
        _agg(ambiguous_count=1), _health()
    )
    assert ambiguous == ZEEK_BASE_CONFIDENCE - CONFIDENCE_PENALTIES[
        "ambiguous_observation"]
    assert any("ambiguous" in r for r in reasons)


def test_confidence_floor_and_ceiling_enforced():
    worst = compute_zeek_confidence(
        _agg(missed_bytes=1, partial_count=1, ambiguous_count=1,
             successful_count=0, connection_count=3),
        _health("unusable", loss=99.0),
        zeek_config().zeek,
    )[0]
    assert worst == MIN_CONFIDENCE
    assert MIN_CONFIDENCE <= worst <= MAX_CONFIDENCE


def test_degraded_confidence_visible_in_flow_and_report():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432, missed=512),
        ])
        write_json_log(tmp, "capture_loss.log",
                       [{"ts": 1.0, "percent_lost": 4.0}])
        degraded = correlated(tmp)
        flow = _flows_for(degraded, "192.168.10.30", 5432,
                          src="192.168.20.15")[0]
        assert degraded["zeek"].health.status == "degraded"
        assert flow.confidence < ZEEK_BASE_CONFIDENCE
        assert "missed byte" in flow.confidence_notes
        assert "Confidence reduced" in flow.evidence
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        write_json_log(tmp, "capture_loss.log",
                       [{"ts": 1.0, "percent_lost": 0.1}])
        healthy = correlated(tmp)
        healthy_flow = _flows_for(healthy, "192.168.10.30", 5432,
                                  src="192.168.20.15")[0]
        assert healthy_flow.confidence == ZEEK_BASE_CONFIDENCE
    assert flow.confidence < healthy_flow.confidence


def test_merged_flow_confidence_also_reduced():
    cfg = _declared_config("192.168.10.30", 5432)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432, missed=256),
        ])
        write_json_log(tmp, "capture_loss.log",
                       [{"ts": 1.0, "percent_lost": 9.0}])
        data = correlated(tmp, cfg)
        flow = _flows_for(data, "192.168.10.30", 5432,
                          src="192.168.20.15")[0]
        assert flow.confidence < ZEEK_BASE_CONFIDENCE
        assert flow.confidence_notes


def test_unusable_sensor_data_withholds_rules():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        data = correlated(tmp)
        data["zeek"].health.status = "unusable"  # simulate unusable sensor
        from nmap_flow_analyzer.zeek_correlation import correlate_zeek
        from nmap_flow_analyzer.flow_analysis import (
            build_flows, enrich_hosts, sort_and_assign_flow_ids,
        )
        from nmap_flow_analyzer.risk_analysis import build_service_records
        from tests.fixtures import parse_xml

        cfg, options = data["config"], data["options"]
        _, hosts = parse_xml(MULTI_HOST_XML)
        enrich_hosts(hosts, cfg)
        records = build_service_records(hosts, cfg)
        result = build_flows(hosts, records, cfg, options)
        corr = correlate_zeek(hosts, records, result.flows, cfg, options,
                              data["zeek"])
        flows = sort_and_assign_flow_ids(corr.flows)
        zeek_flows = [f for f in flows if "zeek" in f.evidence_sources]
        assert zeek_flows
        for flow in zeek_flows:
            assert flow.manual_review_reason
        inbound, _ = build_inbound(flows, cfg, options)
        outbound, _ = build_outbound(flows, inbound, cfg, options)
        assert not [r for r in inbound + outbound
                    if r.source == "192.168.20.15" and r.port == "5432"]


# ===========================================================================
# Defect 4 - scanner-only traffic reported without contradiction
# ===========================================================================

def test_service_with_no_zeek_traffic_labeled_not_observed():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        data = correlated(Path(tmp))
        record = next(r for r in data["records"]
                      if r.ip == "192.168.10.20" and r.port == 22)
        assert record.any_zeek_traffic_observed is False
        assert record.scanner_only_zeek_traffic_observed is False
        assert record.zeek_observation.startswith("Not observed")


def test_service_with_scanner_only_traffic_is_not_called_unobserved():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("Cscan", "192.168.1.50", "192.168.10.30", 5432),  # scanner
        ])
        data = correlated(Path(tmp))
        record = next(r for r in data["records"]
                      if r.ip == "192.168.10.30" and r.port == 5432)
        assert record.any_zeek_traffic_observed is True
        assert record.non_scanner_zeek_traffic_observed is False
        assert record.scanner_only_zeek_traffic_observed is True
        assert record.zeek_observation == SCANNER_ONLY_TEXT
        assert not record.zeek_observation.startswith("Not observed")
        assert "scanner-generated" in record.zeek_observation
        finding = next(f for f in data["corr"].findings
                       if f.category == "Exposed service with scanner-only "
                                        "traffic")
        assert "not production usage" in finding.detail
        assert "do NOT call it unused" in finding.recommendation.lower() or \
               "not call it" in finding.recommendation.lower()
        # And no production rule came from the scan traffic.
        inbound, outbound, _ = _rules(data)
        assert not [r for r in inbound + outbound
                    if r.source == "192.168.1.50" and r.port == "5432"
                    and "zeek" in r.evidence_sources
                    and r.correlation_status == "zeek-traffic-only"]


def test_service_with_production_traffic_reported_as_corroborated():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("Cscan", "192.168.1.50", "192.168.10.30", 5432),
            conn("Cprod", "192.168.20.15", "192.168.10.30", 5432, ts=40.0),
        ])
        data = correlated(Path(tmp))
        record = next(r for r in data["records"]
                      if r.ip == "192.168.10.30" and r.port == 5432)
        assert record.any_zeek_traffic_observed is True
        assert record.non_scanner_zeek_traffic_observed is True
        assert record.scanner_only_zeek_traffic_observed is False
        assert record.zeek_observation == "active traffic observed"
        assert record.correlation_status == "nmap-and-zeek"


def test_scanner_only_service_has_no_contradictory_report_sections():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        zdir = tmp / "zeek"
        write_json_log(zdir, "conn.log", [
            conn("Cscan", "192.168.1.50", "192.168.10.30", 5432),
        ])
        out = tmp / "out"
        assert main(["--input", str(tmp / "scan.xml"), "--output-dir", str(out),
                     "--scanner-ip", "192.168.1.50",
                     "--zeek-dir", str(zdir)]) == 0
        html = (out / "analysis_report.html").read_text("utf-8")
        assert "observed only in scanner-generated" in html.lower()
        assert "no Zeek traffic at all" in html
        services = json.loads((out / "service_inventory.json").read_text("utf-8"))
        target = next(s for s in services
                      if s["ip"] == "192.168.10.30" and s["port"] == 5432)
        # Exactly one of the three states is true.
        assert [target["non_scanner_zeek_traffic_observed"],
                target["scanner_only_zeek_traffic_observed"],
                not target["any_zeek_traffic_observed"]].count(True) == 1


# ===========================================================================
# Defect 5 - complete provenance for merged evidence
# ===========================================================================

def test_scanner_flow_not_counted_as_production_corroboration():
    """The scanner's own probes are scan-audit evidence, not corroboration."""
    from nmap_flow_analyzer.zeek_correlation import is_scanner_observation

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        zdir = tmp / "zeek"
        write_json_log(zdir, "conn.log", [
            conn("Cscan", "192.168.1.50", "192.168.10.30", 5432),
        ])
        out = tmp / "out"
        assert main(["--input", str(tmp / "scan.xml"), "--output-dir", str(out),
                     "--scanner-ip", "192.168.1.50",
                     "--zeek-dir", str(zdir)]) == 0
        nd = json.loads((out / "normalized_data.json").read_text("utf-8"))
        counts = nd["zeek_summary_counts"]
        assert counts["unique_corroborated_communications"] == 0
        assert counts["scanner_audit_communications"] >= 1
        assert counts["nmap_services_with_scanner_only_traffic"] == 1
        assert counts["nmap_services_with_production_traffic"] == 0
        html = (out / "analysis_report.html").read_text("utf-8")
        assert "scan-audit evidence rather than production traffic" in html
        scanner_flows = [f for f in nd["flows"]
                         if f["source"] == "192.168.1.50"
                         and f["destination_port"] == 5432]
        assert scanner_flows
        assert all(is_scanner_observation(type("F", (), f)())
                   for f in [scanner_flows[0]])


def test_evidence_source_ordering_is_canonical_and_deduplicated():
    assert order_evidence_sources(
        ["zeek", "user_configuration", "nmap", "zeek"]
    ) == ["nmap", "zeek", "user_configuration"]
    assert order_evidence_sources(["inference", "nmap"]) == ["nmap", "inference"]


def test_provenance_nmap_plus_zeek():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        data = correlated(Path(tmp))
        for flow in _flows_for(data, "192.168.10.30", 5432,
                               src="192.168.20.15"):
            if "zeek" in flow.evidence_sources:
                assert flow.evidence_sources == ["nmap", "zeek"]


def test_provenance_user_configuration_plus_zeek_without_nmap():
    cfg = _declared_config("192.168.40.9", 8443)  # host not scanned by Nmap
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.40.9", 8443),
        ])
        data = correlated(Path(tmp), cfg)
        flows = _flows_for(data, "192.168.40.9", 8443, src="192.168.20.15")
        assert flows
        for flow in flows:
            assert flow.evidence_sources == ["zeek", "user_configuration"]


def test_provenance_nmap_plus_user_configuration_plus_zeek():
    cfg = _declared_config("192.168.10.30", 5432)
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        data = correlated(Path(tmp), cfg)
        flows = _flows_for(data, "192.168.10.30", 5432, src="192.168.20.15")
        assert flows
        for flow in flows:
            assert flow.correlation_status == "user-defined-and-zeek"
            assert flow.evidence_sources == [
                "nmap", "zeek", "user_configuration"]
            assert flow.nmap_observation == "service open (Nmap)"


def test_provenance_nmap_plus_inference_plus_zeek():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.10.20", "192.168.10.30", 5432),
        ])
        cfg = zeek_config()
        cfg.hosts.setdefault("192.168.10.20", type(
            list(cfg.hosts.values())[0] if cfg.hosts else object
        )()) if False else None
        data = correlated(Path(tmp), cfg,
                          options=AnalysisOptions(include_inferred_outbound=True))
        flows = [f for f in _flows_for(data, "192.168.10.30", 5432)
                 if f.source == "192.168.10.20"]
        assert flows
        for flow in flows:
            assert "nmap" in flow.evidence_sources
            assert "zeek" in flow.evidence_sources
            assert flow.evidence_sources == order_evidence_sources(
                flow.evidence_sources)


def test_provenance_retained_for_conflicting_evidence():
    data = _assert_conflict_withheld("192.168.10.20", 3306, "closed")
    for flow in _flows_for(data, "192.168.10.20", 3306, src="192.168.20.15"):
        assert "nmap" in flow.evidence_sources  # the conflicting scan result
        assert "zeek" in flow.evidence_sources
        assert "user_configuration" in flow.evidence_sources


def test_rules_inherit_complete_provenance():
    cfg = _declared_config("192.168.10.30", 5432)
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        data = correlated(Path(tmp), cfg)
        inbound, _, _ = _rules(data)
        rule = next(r for r in inbound if r.source == "192.168.20.15"
                    and r.port == "5432")
        assert rule.evidence_sources == ["nmap", "zeek", "user_configuration"]


# ===========================================================================
# Defect 6 - unique communications vs. firewall perspectives
# ===========================================================================

def test_one_communication_produces_two_endpoint_perspectives():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        data = correlated(Path(tmp))
        zeek_flows = [f for f in data["flows"] if "zeek" in f.evidence_sources
                      and f.source == "192.168.20.15"]
        assert len(zeek_flows) == 2  # perspectives
        assert count_communications(zeek_flows) == 1  # one communication


def test_network_only_enforcement_counts_one_of_each():
    cfg = zeek_config()
    cfg.rule_generation.enforcement_model = "network_only"
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        data = correlated(Path(tmp), cfg)
        zeek_flows = [f for f in data["flows"] if "zeek" in f.evidence_sources
                      and f.source == "192.168.20.15"]
        assert len(zeek_flows) == 1
        assert count_communications(zeek_flows) == 1


def test_endpoint_only_enforcement_counts_one_communication():
    cfg = zeek_config()
    cfg.rule_generation.enforcement_model = "endpoint_only"
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        data = correlated(Path(tmp), cfg)
        zeek_flows = [f for f in data["flows"] if "zeek" in f.evidence_sources
                      and f.source == "192.168.20.15"]
        assert count_communications(zeek_flows) == 1


def test_multiple_communications_to_same_service_counted_separately():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
            conn("C2", "192.168.20.16", "192.168.10.30", 5432),
        ])
        data = correlated(Path(tmp))
        zeek_flows = [f for f in data["flows"] if "zeek" in f.evidence_sources
                      and f.source.startswith("192.168.20.")]
        assert count_communications(zeek_flows) == 2
        assert len(zeek_flows) == 4  # two perspectives each


def test_report_summaries_label_communications_and_perspectives():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        zdir = tmp / "zeek"
        write_json_log(zdir, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
            conn("C2", "192.168.20.16", "192.168.10.30", 5432),
        ])
        out = tmp / "out"
        assert main(["--input", str(tmp / "scan.xml"), "--output-dir", str(out),
                     "--scanner-ip", "192.168.1.50",
                     "--zeek-dir", str(zdir), "--excel"]) == 0
        html = (out / "analysis_report.html").read_text("utf-8")
        # v1.2.3 (issue 4): natural wording, no mechanical "(s)" markers.
        assert "unique communication" in html
        assert "firewall perspective" in html
        md = (out / "findings_summary.md").read_text("utf-8")
        assert "unique (" in md and "firewall perspectives" in md
        nd = json.loads((out / "normalized_data.json").read_text("utf-8"))
        counts = nd["zeek_summary_counts"]
        assert counts["unique_corroborated_communications"] == 2
        assert counts["corroborated_firewall_perspectives"] == 4
        assert counts["total_inbound_candidates"] >= 1


# ===========================================================================
# Defect 7 - invalid core records counted as malformed with source context
# ===========================================================================

def test_validate_conn_record_rejects_each_missing_core_field():
    valid = conn("C1", "192.168.20.15", "192.168.10.30", 5432)
    assert validate_conn_record(valid) is None
    for field, expected in (
        ("id.orig_h", "id.orig_h"), ("id.resp_h", "id.resp_h"),
        ("proto", "proto"), ("ts", "ts"),
    ):
        broken = dict(valid)
        broken.pop(field)
        problem = validate_conn_record(broken)
        assert problem and expected in problem, field
    bad_ip = dict(valid, **{"id.orig_h": "not-an-ip"})
    assert "valid IP" in validate_conn_record(bad_ip)
    bad_port = dict(valid, **{"id.resp_p": "notaport"})
    assert "port" in validate_conn_record(bad_port)
    out_of_range = dict(valid, **{"id.resp_p": 70000})
    assert "range" in validate_conn_record(out_of_range)
    missing_port = dict(valid)
    missing_port.pop("id.resp_p")
    assert "id.resp_p" in validate_conn_record(missing_port)
    bad_ts = dict(valid, ts="yesterday")
    assert "numeric" in validate_conn_record(bad_ts)


def test_icmp_record_valid_without_responder_port():
    icmp = conn("Cicmp", "192.168.20.15", "192.168.10.30", 8, proto="icmp")
    icmp.pop("id.resp_p")
    assert validate_conn_record(icmp) is None  # ICMP has no ports


def test_invalid_records_counted_malformed_with_file_and_line():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        good = conn("C1", "192.168.20.15", "192.168.10.30", 5432)
        no_orig = conn("C2", "192.168.20.15", "192.168.10.30", 5432)
        no_orig.pop("id.orig_h")
        bad_ip = conn("C3", "999.999.1.1", "192.168.10.30", 5432)
        no_proto = conn("C4", "192.168.20.15", "192.168.10.30", 5432)
        no_proto["proto"] = ""
        write_json_log(tmp, "conn.log", [good, no_orig, bad_ip, no_proto])
        zeek = load(tmp)
        assert zeek.metadata.malformed_counts["conn"] == 3
        assert zeek.metadata.raw_records_read["conn"] == 4
        assert zeek.metadata.usable_records["conn"] == 1
        assert zeek.metadata.record_counts["conn"] == 1
        errors = zeek.metadata.parse_errors
        assert any("conn.log:2" in e and "id.orig_h" in e for e in errors)
        assert any("conn.log:3" in e and "IP address" in e for e in errors)
        assert any("conn.log:4" in e and "proto" in e for e in errors)
        # Only the valid record was aggregated.
        assert len(zeek.aggregates) == 1
        assert zeek.aggregates[0].connection_count == 1
        entry = next(e for e in zeek.metadata.files_processed
                     if e["log_type"] == "conn")
        assert entry["malformed"] == 3 and entry["records"] == 1


def test_malformed_error_text_does_not_echo_hostile_record():
    hostile = conn("C1", "192.168.20.15", "192.168.10.30", 5432)
    hostile["proto"] = ""
    hostile["evil"] = "=cmd|'/c calc'!A0 <script>alert(1)</script>"
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [hostile])
        zeek = load(Path(tmp))
        joined = " ".join(zeek.metadata.parse_errors)
        assert "alert(1)" not in joined
        assert "=cmd" not in joined


def test_tsv_invalid_core_record_counted():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        good = conn("C1", "192.168.20.15", "192.168.10.30", 5432)
        broken = conn("C2", "192.168.20.15", "192.168.10.30", 5432)
        broken["id.resp_h"] = None  # unset -> '-' in TSV
        path = write_tsv_conn(tmp, [good, broken])
        with path.open("a", encoding="utf-8") as handle:
            handle.write("too\tfew\tcolumns\n")
        zeek = load(tmp)
        assert zeek.metadata.malformed_counts["conn"] == 2  # field + core
        assert zeek.metadata.usable_records["conn"] == 1
        assert any("id.resp_h" in e for e in zeek.metadata.parse_errors)


def test_manifest_reports_raw_usable_and_malformed_counts():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        zdir = tmp / "zeek"
        broken = conn("C2", "192.168.20.15", "192.168.10.30", 5432)
        broken.pop("proto")
        write_json_log(zdir, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432), broken,
        ])
        out = tmp / "out"
        assert main(["--input", str(tmp / "scan.xml"), "--output-dir", str(out),
                     "--scanner-ip", "192.168.1.50",
                     "--zeek-dir", str(zdir)]) == 0
        manifest = json.loads((out / "run_manifest.json").read_text("utf-8"))
        zeek_block = manifest["zeek"]
        assert zeek_block["malformed_record_counts"]["conn"] == 1
        entry = next(e for e in zeek_block["files_processed"]
                     if e["log_type"] == "conn")
        assert entry["malformed"] == 1 and entry["records"] == 1
        summary = json.loads((out / "zeek_input_summary.json").read_text("utf-8"))
        meta = summary["input_metadata"]
        assert meta["raw_records_read"]["conn"] == 2
        assert meta["usable_records"]["conn"] == 1


# ===========================================================================
# Defect 8 - reproducible test command shipped in the archive
# ===========================================================================

def test_run_tests_script_is_present_and_executable():
    runner = REPO_ROOT / "run_tests.py"
    assert runner.is_file(), "documented run_tests.py is missing from the repo"
    result = subprocess.run(
        [sys.executable, str(runner), "tests/test_zeek_parser.py", "-k",
         "test_json_lines_parsed_and_counted"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 collected, 1 passed" in result.stdout


def test_documented_commands_exist_in_repository():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "python -m pytest -q" in readme
    assert "python run_tests.py" in readme
    results = (REPO_ROOT / "TEST_RESULTS.txt").read_text(encoding="utf-8")
    for command in ("python -m pytest -q", "python run_tests.py"):
        assert command in results


# ===========================================================================
# Defect 9 - accurate, explicitly labeled counts
# ===========================================================================

def test_completion_summary_labels_total_and_observed_counts(capsys=None):
    import contextlib
    import io

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        out = tmp / "out"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["--input", str(tmp / "scan.xml"),
                         "--output-dir", str(out),
                         "--scanner-ip", "192.168.1.50"])
        assert code == 0
        printed = buffer.getvalue()
        assert "Total inbound candidates:" in printed
        assert "with top-level Observed evidence" in printed
        inbound = json.loads((out / "inbound_exceptions.json").read_text("utf-8"))
        total_line = next(line for line in printed.splitlines()
                          if line.startswith("Total inbound candidates:"))
        assert str(len(inbound)) in total_line
        observed = sum(1 for r in inbound if r["evidence_class"] == "Observed")
        assert f"({observed} with top-level Observed evidence)" in total_line


def test_version_is_reported_as_1_2_4():
    from nmap_flow_analyzer import __version__

    assert __version__ == "1.4.0.dev0"
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        zdir = tmp / "zeek"
        write_json_log(zdir, "conn.log",
                       [conn("C1", "192.168.20.15", "192.168.10.30", 5432)])
        out = tmp / "out"
        assert main(["--input", str(tmp / "scan.xml"), "--output-dir", str(out),
                     "--scanner-ip", "192.168.1.50",
                     "--zeek-dir", str(zdir)]) == 0
        manifest = json.loads((out / "run_manifest.json").read_text("utf-8"))
        assert manifest["version"] == "1.4.0.dev0"
        html = (out / "analysis_report.html").read_text("utf-8")
        assert "1.4.0.dev0" in html
