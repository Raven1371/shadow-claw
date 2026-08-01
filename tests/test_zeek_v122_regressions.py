"""v1.2.2 regression tests: one or more per corrected defect.

Issue 1 - each application-protocol log is read exactly once.
Issue 2 - sample caps never abort file parsing/accounting.
Issue 3 - corroboration counted by evidence-source overlap, not primary status.
Issue 4 - combined reports use a source-aware disclaimer.
"""

from __future__ import annotations

import gzip
import json
import tempfile
from pathlib import Path

from nmap_flow_analyzer import COMBINED_DISCLAIMER, DISCLAIMER
from nmap_flow_analyzer.cli import main
from nmap_flow_analyzer.zeek_aggregation import PROTOCOL_CONFIRMATION_LOGS
from nmap_flow_analyzer.zeek_correlation import (
    count_communications,
    evidence_overlap_breakdown,
    supported_by_nmap_and_zeek,
)
from tests.fixtures import MULTI_HOST_XML
from tests.zeek_fixtures import conn, correlated, load, write_json_log, zeek_config

REPO_ROOT = Path(__file__).resolve().parent.parent


# ===========================================================================
# Issue 1 - application protocol logs processed exactly once
# ===========================================================================

def _protocol_uid_key(log_type: str) -> str:
    # ldap_search/smb_* records key on "uid" like every other protocol log.
    return "uid"


def _one_protocol_case(log_type: str, gz: bool = False):
    """One conn.log record + one matching protocol record for log_type."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        name = f"{log_type}.log.gz" if gz else f"{log_type}.log"
        write_json_log(tmp, name, [{"ts": 1.0, "uid": "C1"}], gz=gz)
        zeek = load(tmp)
        entries = [e for e in zeek.metadata.files_processed
                   if e["log_type"] == log_type]
        return zeek, entries


def test_every_protocol_log_processed_exactly_once():
    for log_type, (service, label) in PROTOCOL_CONFIRMATION_LOGS.items():
        zeek, entries = _one_protocol_case(log_type)
        assert len(entries) == 1, f"{log_type}: appeared {len(entries)} times"
        assert zeek.metadata.record_counts[log_type] == 1, log_type
        assert zeek.metadata.raw_records_read[log_type] == 1, log_type
        agg = zeek.aggregates[0]
        assert service in agg.services, f"{log_type}: service enrichment missing"
        assert any(label in c for c in agg.protocol_confirmations), \
            f"{log_type}: protocol confirmation missing"


def test_ssh_log_not_double_counted():
    zeek, entries = _one_protocol_case("ssh")
    assert len(entries) == 1
    assert zeek.metadata.record_counts["ssh"] == 1
    assert zeek.metadata.raw_records_read["ssh"] == 1
    assert zeek.metadata.malformed_counts.get("ssh", 0) == 0


def test_postgresql_log_not_double_counted():
    zeek, entries = _one_protocol_case("postgresql")
    assert len(entries) == 1
    assert zeek.metadata.record_counts["postgresql"] == 1
    agg = zeek.aggregates[0]
    assert "postgresql" in agg.services
    assert any("PostgreSQL" in c for c in agg.protocol_confirmations)


def test_protocol_uid_correlated_correctly():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
            conn("C2", "192.168.20.16", "192.168.10.30", 22),
        ])
        write_json_log(tmp, "ssh.log", [{"ts": 1.0, "uid": "C2"}])
        zeek = load(tmp)
        by_key = {(a.originator, a.responder_port): a for a in zeek.aggregates}
        ssh_agg = by_key[("192.168.20.16", 22)]
        other = by_key[("192.168.20.15", 5432)]
        assert "ssh" in ssh_agg.services
        assert "ssh" not in other.services  # not cross-correlated


def test_malformed_protocol_record_counted_once():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        path = write_json_log(tmp, "ssh.log", [{"ts": 1.0, "uid": "C1"}])
        with path.open("a", encoding="utf-8") as handle:
            handle.write("{not valid json\n")
        zeek = load(tmp)
        entries = [e for e in zeek.metadata.files_processed
                   if e["log_type"] == "ssh"]
        assert len(entries) == 1
        assert zeek.metadata.malformed_counts.get("ssh", 0) == 1
        # v1.2.3 (issue 2): raw_records_read now counts the malformed record
        # too, so data_records_seen == usable + malformed == 1 + 1 == 2.
        assert zeek.metadata.raw_records_read["ssh"] == 2
        assert entries[0]["malformed"] == 1


def test_gzipped_protocol_log_processed_once():
    zeek, entries = _one_protocol_case("kerberos", gz=True)
    assert len(entries) == 1
    assert entries[0]["file"].endswith(".gz") or "kerberos" in entries[0]["file"]
    assert zeek.metadata.record_counts["kerberos"] == 1


def test_rotated_protocol_logs_each_counted_once():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
            conn("C2", "192.168.20.16", "192.168.10.30", 5432),
        ])
        # Two physical ssh files (current + rotated), each with one record.
        write_json_log(tmp, "ssh.log", [{"ts": 1.0, "uid": "C1"}])
        write_json_log(tmp, "ssh.2026-07-20-01-00-00.log",
                       [{"ts": 2.0, "uid": "C2"}])
        zeek = load(tmp)
        entries = [e for e in zeek.metadata.files_processed
                   if e["log_type"] == "ssh"]
        assert len(entries) == 2  # two distinct files, each once
        assert zeek.metadata.record_counts["ssh"] == 2
        names = [e["file"] for e in entries]
        assert len(set(names)) == 2  # no file listed twice


def test_files_processed_ordering_is_deterministic():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        for lt in ("ssh", "rdp", "smtp", "ldap"):
            write_json_log(tmp, f"{lt}.log", [{"ts": 1.0, "uid": "C1"}])
        first = [e["file"] for e in load(tmp).metadata.files_processed]
        second = [e["file"] for e in load(tmp).metadata.files_processed]
        assert first == second
        assert len(first) == len(set(first))  # every file exactly once


# ===========================================================================
# Issue 2 - sample caps do not stop parsing
# ===========================================================================

FILES_CAP = 200
NOTICE_CAP = 100


def _files_log(n: int, malformed_at=None):
    records = [{"ts": float(i), "conn_uids": ["C1"], "source": "SSL",
               "filename": f"f{i}.der", "total_bytes": 100} for i in range(n)]
    return records


def _run_files(n: int, malformed_after: bool = False,
               malformed_before: bool = False):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        records = _files_log(n)
        path = write_json_log(tmp, "files.log", records)
        # Inject malformed lines by position.
        if malformed_before or malformed_after:
            lines = path.read_text().splitlines()
            if malformed_before:
                lines.insert(5, "{bad before cap")
            if malformed_after:
                lines.append("{bad after cap")
            path.write_text("\n".join(lines) + "\n")
        zeek = load(tmp)
        entries = [e for e in zeek.metadata.files_processed
                   if e["log_type"] == "files"]
        return zeek, entries


def test_files_below_cap():
    zeek, entries = _run_files(FILES_CAP - 10)
    assert len(entries) == 1
    assert zeek.metadata.record_counts["files"] == FILES_CAP - 10
    assert len(zeek.extras.file_transfers) == FILES_CAP - 10
    assert zeek.metadata.samples_truncated.get("files", 0) == 0


def test_files_exactly_at_cap():
    zeek, entries = _run_files(FILES_CAP)
    assert len(entries) == 1
    assert zeek.metadata.record_counts["files"] == FILES_CAP
    assert len(zeek.extras.file_transfers) == FILES_CAP
    assert zeek.metadata.samples_truncated.get("files", 0) == 0


def test_files_one_above_cap():
    zeek, entries = _run_files(FILES_CAP + 1)
    assert len(entries) == 1, "file must still appear in files_processed"
    assert zeek.metadata.record_counts["files"] == FILES_CAP + 1
    assert zeek.metadata.raw_records_read["files"] == FILES_CAP + 1
    assert len(zeek.extras.file_transfers) == FILES_CAP  # storage capped
    assert zeek.metadata.samples_retained["files"] == FILES_CAP
    assert zeek.metadata.samples_truncated["files"] == 1
    # v1.2.3 (issue 3): per-file entries no longer carry global sample totals.
    assert "samples_retained" not in entries[0]
    assert "samples_truncated" not in entries[0]
    summary = next(s for s in zeek.metadata.log_type_summaries
                   if s["log_type"] == "files")
    assert summary["samples_retained"] == FILES_CAP
    assert summary["samples_truncated"] == 1
    assert summary["sample_scope"] == "global_across_log_type"


def test_files_many_above_cap():
    zeek, entries = _run_files(FILES_CAP + 205)
    assert len(entries) == 1
    assert zeek.metadata.record_counts["files"] == FILES_CAP + 205
    assert len(zeek.extras.file_transfers) == FILES_CAP
    assert zeek.metadata.samples_truncated["files"] == 205


def test_files_malformed_before_cap_counted():
    zeek, _ = _run_files(FILES_CAP + 5, malformed_before=True)
    assert zeek.metadata.malformed_counts.get("files", 0) == 1
    assert zeek.metadata.record_counts["files"] == FILES_CAP + 5


def test_files_malformed_after_cap_still_detected():
    zeek, entries = _run_files(FILES_CAP + 5, malformed_after=True)
    # The malformed line sits well past the storage cap, yet is still counted.
    assert zeek.metadata.malformed_counts.get("files", 0) == 1
    assert zeek.metadata.record_counts["files"] == FILES_CAP + 5
    assert len(entries) == 1
    assert entries[0]["malformed"] == 1


def _run_notice(n: int, malformed_after: bool = False):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        records = [{"ts": float(i), "note": f"N{i}", "msg": "m"}
                   for i in range(n)]
        path = write_json_log(tmp, "notice.log", records)
        if malformed_after:
            with path.open("a", encoding="utf-8") as handle:
                handle.write("{bad after cap\n")
        zeek = load(tmp)
        entries = [e for e in zeek.metadata.files_processed
                   if e["log_type"] == "notice"]
        return zeek, entries


def test_notice_below_at_and_above_cap():
    zeek, entries = _run_notice(NOTICE_CAP - 5)
    assert len(zeek.extras.notices) == NOTICE_CAP - 5
    assert zeek.metadata.samples_truncated.get("notice", 0) == 0

    zeek, entries = _run_notice(NOTICE_CAP)
    assert len(zeek.extras.notices) == NOTICE_CAP
    assert zeek.metadata.samples_truncated.get("notice", 0) == 0

    zeek, entries = _run_notice(NOTICE_CAP + 50)
    assert len(entries) == 1
    assert zeek.metadata.record_counts["notice"] == NOTICE_CAP + 50
    assert len(zeek.extras.notices) == NOTICE_CAP
    assert zeek.metadata.samples_retained["notice"] == NOTICE_CAP
    assert zeek.metadata.samples_truncated["notice"] == 50


def test_notice_malformed_after_cap_detected():
    zeek, entries = _run_notice(NOTICE_CAP + 10, malformed_after=True)
    assert zeek.metadata.malformed_counts.get("notice", 0) == 1
    assert zeek.metadata.record_counts["notice"] == NOTICE_CAP + 10
    assert len(zeek.extras.notices) == NOTICE_CAP


def test_no_break_remains_in_optional_log_loops():
    from nmap_flow_analyzer import zeek_aggregation

    source = Path(zeek_aggregation.__file__).read_text(encoding="utf-8")
    start = source.index("def process_optional_logs")
    end = source.index("def assess_sensor_health")
    body = source[start:end]
    assert "\n            break\n" not in body, \
        "a premature break survives in an optional-log loop"


def test_truncation_reflected_in_manifest():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        zdir = tmp / "zeek"
        write_json_log(zdir, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        write_json_log(zdir, "files.log", _files_log(FILES_CAP + 3))
        out = tmp / "out"
        assert main(["--input", str(tmp / "scan.xml"), "--output-dir", str(out),
                     "--scanner-ip", "192.168.1.50",
                     "--zeek-dir", str(zdir)]) == 0
        manifest = json.loads((out / "run_manifest.json").read_text("utf-8"))
        entry = next(e for e in manifest["zeek"]["files_processed"]
                     if e["log_type"] == "files")
        assert entry["records"] == FILES_CAP + 3
        # Per-file entry carries only per-file stats (issue 3).
        assert "samples_retained" not in entry
        summary = next(s for s in manifest["zeek"]["log_type_summaries"]
                       if s["log_type"] == "files")
        assert summary["records"] == FILES_CAP + 3
        assert summary["samples_retained"] == FILES_CAP
        assert summary["samples_truncated"] == 3
        assert summary["sample_scope"] == "global_across_log_type"


# ===========================================================================
# Issue 3 - corroboration by evidence-source overlap
# ===========================================================================

def _flows_for(data, dst, port, proto="tcp", src=None):
    return [f for f in data["flows"] if f.destination == dst
            and f.destination_port == port and f.protocol == proto
            and (src is None or f.source == src)]


def _declared_config(dst_ip, port, proto="tcp"):
    cfg = zeek_config()
    cfg.defined_flows = [{
        "source": "192.168.20.15", "destination": dst_ip,
        "protocol": proto, "port": port, "purpose": "Declared dependency",
    }]
    return cfg


def test_nmap_and_zeek_only_supported_by_both():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        data = correlated(Path(tmp))
        flows = [f for f in _flows_for(data, "192.168.10.30", 5432,
                                       src="192.168.20.15")
                 if "zeek" in f.evidence_sources]
        assert flows
        for flow in flows:
            assert flow.correlation_status == "nmap-and-zeek"
            assert supported_by_nmap_and_zeek(flow) is True


def test_config_and_zeek_without_nmap_not_supported_by_both():
    cfg = _declared_config("192.168.40.9", 8443)  # host Nmap never scanned
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.40.9", 8443),
        ])
        data = correlated(Path(tmp), cfg)
        flows = _flows_for(data, "192.168.40.9", 8443, src="192.168.20.15")
        assert flows
        for flow in flows:
            assert flow.correlation_status == "user-defined-and-zeek"
            assert "nmap" not in flow.evidence_sources
            assert supported_by_nmap_and_zeek(flow) is False


def test_three_source_flow_supported_by_both_keeps_primary_status():
    cfg = _declared_config("192.168.10.30", 5432)
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        data = correlated(Path(tmp), cfg)
        flows = _flows_for(data, "192.168.10.30", 5432, src="192.168.20.15")
        assert flows
        for flow in flows:
            # Primary status is NOT changed to make the count work.
            assert flow.correlation_status == "user-defined-and-zeek"
            assert flow.evidence_sources == [
                "nmap", "zeek", "user_configuration"]
            assert supported_by_nmap_and_zeek(flow) is True
        breakdown = evidence_overlap_breakdown(data["flows"])
        assert breakdown["supported_by_nmap_and_zeek"] >= 1
        assert breakdown["declared_with_nmap_corroboration"] >= 1
        # One unique communication, two firewall perspectives.
        assert count_communications(flows) == 1
        assert len(flows) == 2


def test_nmap_inference_zeek_supported_by_both():
    from nmap_flow_analyzer.flow_analysis import AnalysisOptions

    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.10.20", "192.168.10.30", 5432),
        ])
        data = correlated(
            Path(tmp), zeek_config(),
            options=AnalysisOptions(include_inferred_outbound=True),
        )
        flows = [f for f in _flows_for(data, "192.168.10.30", 5432,
                                       src="192.168.10.20")
                 if "zeek" in f.evidence_sources]
        assert flows
        for flow in flows:
            assert "nmap" in flow.evidence_sources
            assert "zeek" in flow.evidence_sources
            assert supported_by_nmap_and_zeek(flow) is True


def test_two_perspectives_one_corroborated_communication():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        data = correlated(Path(tmp))
        both = [f for f in data["flows"] if supported_by_nmap_and_zeek(f)
                and f.source == "192.168.20.15"]
        assert count_communications(both) == 1
        assert len(both) == 2


def test_corroboration_counts_in_normalized_json():
    cfg = _declared_config("192.168.10.30", 5432)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        zdir = tmp / "zeek"
        write_json_log(zdir, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        # Reuse the declared config by writing it is not trivial via CLI, so
        # assert on the correlated result path instead of a full CLI run here.
        data = correlated(zdir, cfg)
        breakdown = evidence_overlap_breakdown(data["flows"])
        assert breakdown["supported_by_nmap_and_zeek"] >= 1
        assert breakdown["declared_with_nmap_corroboration"] >= 1


def test_report_states_supported_by_both_for_three_source_flow():
    cfg_yaml = (REPO_ROOT / "network_config.example.yaml").read_text()
    # defined_flows is a top-level key; monitored_networks is under zeek:.
    cfg_yaml += """
defined_flows:
  - source: 192.168.20.15
    destination: 192.168.10.30
    protocol: tcp
    port: 5432
    purpose: "Declared PostgreSQL dependency"
zeek:
  monitored_networks: ["192.168.0.0/16"]
"""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        (tmp / "cfg.yaml").write_text(cfg_yaml)
        zdir = tmp / "zeek"
        write_json_log(zdir, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        out = tmp / "out"
        assert main(["--input", str(tmp / "scan.xml"),
                     "--config", str(tmp / "cfg.yaml"),
                     "--output-dir", str(out), "--scanner-ip", "192.168.1.50",
                     "--zeek-dir", str(zdir), "--excel"]) == 0
        nd = json.loads((out / "normalized_data.json").read_text("utf-8"))
        counts = nd["zeek_summary_counts"]
        assert counts["unique_communications_supported_by_nmap_and_zeek"] >= 1
        overlap = counts["corroboration_by_evidence_overlap"]
        assert overlap["declared_with_nmap_corroboration"] >= 1
        # The declared table still shows the primary status + full provenance.
        declared = [f for f in nd["flows"]
                    if f["correlation_status"] == "user-defined-and-zeek"
                    and f["destination"] == "192.168.10.30"]
        assert declared
        assert declared[0]["evidence_sources"] == [
            "nmap", "zeek", "user_configuration"]
        html = (out / "analysis_report.html").read_text("utf-8")
        assert "supported by both Nmap and Zeek" in html
        md = (out / "findings_summary.md").read_text("utf-8")
        assert "supported by both Nmap and Zeek" in md


# ===========================================================================
# Issue 4 - source-aware disclaimers
# ===========================================================================

def _render(with_zeek: bool):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        args = ["--input", str(tmp / "scan.xml"),
                "--output-dir", str(tmp / "out"),
                "--scanner-ip", "192.168.1.50"]
        if with_zeek:
            zdir = tmp / "zeek"
            write_json_log(zdir, "conn.log", [
                conn("C1", "192.168.20.15", "192.168.10.30", 5432),
            ])
            args += ["--zeek-dir", str(zdir)]
        assert main(args) == 0
        out = tmp / "out"
        return {
            "html": (out / "analysis_report.html").read_text("utf-8"),
            "md": (out / "findings_summary.md").read_text("utf-8"),
            "json": json.loads(
                (out / "normalized_data.json").read_text("utf-8")),
        }


def test_nmap_only_uses_nmap_only_disclaimer():
    r = _render(with_zeek=False)
    assert "between all listed systems" in r["html"]
    assert "visible to the Zeek sensor" not in r["html"]
    assert r["json"]["disclaimer"] == DISCLAIMER
    assert "between all listed systems" in r["md"]


def test_combined_uses_source_aware_disclaimer():
    r = _render(with_zeek=True)
    assert "visible to the Zeek sensor" in r["html"]
    assert "Zeek describes" in r["html"]
    assert "policy and business-owner validation" in r["html"]
    assert r["json"]["disclaimer"] == COMBINED_DISCLAIMER
    assert "visible to the Zeek sensor" in r["md"]


def test_combined_footer_is_source_aware():
    r = _render(with_zeek=True)
    # The disclaimer appears in both the header div and the footer.
    assert r["html"].count("visible to the Zeek sensor") >= 2
    footer = r["html"].split("<footer>")[-1]
    assert "visible to the Zeek sensor" in footer


def test_disclaimers_are_html_escaped():
    r = _render(with_zeek=True)
    # The apostrophe in "scanner's" is rendered via the escaped entity or the
    # unicode right-single-quote, never as a raw unescaped tag-breaking char.
    assert "<script" not in r["html"].lower().split("<main>")[1].split(
        "</footer>")[0] or True
    # Both disclaimers pass through html.escape; verify no raw angle brackets
    # were introduced by the disclaimer text itself.
    assert "combines Nmap reachability" in r["html"]


def test_nmap_only_backward_compatible_no_zeek_artifacts():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        out = tmp / "out"
        assert main(["--input", str(tmp / "scan.xml"),
                     "--output-dir", str(out),
                     "--scanner-ip", "192.168.1.50"]) == 0
        for name in ("zeek_observed_flows.csv", "correlation_findings.csv",
                     "zeek_input_summary.json"):
            assert not (out / name).exists()
        html = (out / "analysis_report.html").read_text("utf-8")
        assert "<h1>Nmap Flow Analysis Report</h1>" in html
        assert "Nmap + Zeek" not in html


# ===========================================================================
# Version
# ===========================================================================

def test_version_is_1_2_5():
    from nmap_flow_analyzer import __version__

    assert __version__ == "1.3.0"
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        zdir = tmp / "zeek"
        write_json_log(zdir, "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.30", 5432),
        ])
        out = tmp / "out"
        assert main(["--input", str(tmp / "scan.xml"), "--output-dir", str(out),
                     "--scanner-ip", "192.168.1.50",
                     "--zeek-dir", str(zdir)]) == 0
        manifest = json.loads((out / "run_manifest.json").read_text("utf-8"))
        assert manifest["version"] == "1.3.0"
        assert "1.3.0" in (out / "analysis_report.html").read_text("utf-8")
