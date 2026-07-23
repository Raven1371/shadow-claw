"""v1.2.3 regression tests.

Issue 1 - blank-line / BOM-safe Zeek format auto-detection.
Issue 2 - raw/data-record accounting includes malformed records.
Issue 3 - per-file metadata is per-file; global caps summarized once.
Issue 4 - centralized, grammatically correct pluralization.
"""

from __future__ import annotations

import gzip
import json
import tempfile
from pathlib import Path

from nmap_flow_analyzer.cli import main
from nmap_flow_analyzer.pluralize import (
    count_noun,
    has,
    plural,
    verb,
    were,
)
from tests.fixtures import MULTI_HOST_XML
from tests.zeek_fixtures import conn, load, write_json_log, write_tsv_conn

REPO_ROOT = Path(__file__).resolve().parent.parent
CONN = conn("C1", "192.168.20.15", "192.168.10.30", 5432)


def _write(dirpath: Path, name: str, text: str, gz: bool = False) -> Path:
    dirpath.mkdir(parents=True, exist_ok=True)
    path = dirpath / name
    if gz:
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def _conn_json_line() -> str:
    return json.dumps(CONN)


# ===========================================================================
# Issue 1 - blank-line / BOM-safe format detection
# ===========================================================================

def _detect(dirpath: Path):
    zeek = load(dirpath)
    entry = next(e for e in zeek.metadata.files_processed
                 if e["log_type"] == "conn")
    return zeek, entry


def test_json_detected_with_no_leading_blank():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", _conn_json_line() + "\n")
        zeek, entry = _detect(tmp)
        assert entry["format"] == "json"
        assert zeek.metadata.usable_records["conn"] == 1


def test_json_detected_with_one_and_many_leading_blanks():
    for prefix in ("\n", "\n\n\n", "\n\n\n\n\n"):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            _write(tmp, "conn.log", prefix + _conn_json_line() + "\n")
            zeek, entry = _detect(tmp)
            assert entry["format"] == "json", repr(prefix)
            assert zeek.metadata.usable_records["conn"] == 1


def test_json_detected_with_whitespace_only_lines():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", "   \n\t\n  \t \n" + _conn_json_line() + "\n")
        zeek, entry = _detect(tmp)
        assert entry["format"] == "json"
        assert zeek.metadata.usable_records["conn"] == 1


def test_json_detected_with_whitespace_before_brace():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", "   " + _conn_json_line() + "\n")
        zeek, entry = _detect(tmp)
        assert entry["format"] == "json"
        assert zeek.metadata.usable_records["conn"] == 1


def test_json_detected_with_bom_and_bom_plus_blanks():
    for prefix in ("\ufeff", "\ufeff\n\n"):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            _write(tmp, "conn.log", prefix + _conn_json_line() + "\n")
            zeek, entry = _detect(tmp)
            assert entry["format"] == "json", repr(prefix)
            assert zeek.metadata.usable_records["conn"] == 1


def test_gzipped_json_with_leading_blanks():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log.gz", "\n\n" + _conn_json_line() + "\n", gz=True)
        zeek, entry = _detect(tmp)
        assert entry["format"] == "json"
        assert zeek.metadata.usable_records["conn"] == 1


def test_rotated_json_with_leading_blanks_each_detected():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", "\n" + _conn_json_line() + "\n")
        _write(tmp, "conn.2026-07-20-01-00-00.log",
               "\n\n" + json.dumps(
                   conn("C2", "192.168.20.16", "192.168.10.30", 5432)) + "\n")
        zeek = load(tmp)
        conn_entries = [e for e in zeek.metadata.files_processed
                        if e["log_type"] == "conn"]
        assert len(conn_entries) == 2
        assert all(e["format"] == "json" for e in conn_entries)
        assert zeek.metadata.usable_records["conn"] == 2


def test_tsv_detected_standard_and_with_leading_blanks():
    for prefix in ("", "\n\n", "\n"):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            path = write_tsv_conn(tmp, [CONN])
            body = prefix + path.read_text()
            path.write_text(body)
            zeek, entry = _detect(tmp)
            assert entry["format"] == "tsv", repr(prefix)
            assert zeek.metadata.usable_records["conn"] == 1


def test_gzipped_tsv_with_leading_blanks():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        plain = write_tsv_conn(tmp, [CONN], name="conn_plain.log")
        body = "\n\n" + plain.read_text()
        plain.unlink()
        _write(tmp, "conn.log.gz", body, gz=True)
        zeek, entry = _detect(tmp)
        assert entry["format"] == "tsv"
        assert zeek.metadata.usable_records["conn"] == 1


def test_blank_only_and_whitespace_only_files_are_indeterminate():
    for content in ("", "\n\n\n", "   \n\t\n"):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            _write(tmp, "conn.log", content)
            zeek = load(tmp)
            entry = next(e for e in zeek.metadata.files_processed
                         if e["log_type"] == "conn")
            assert entry["format"] == "empty"
            assert zeek.metadata.usable_records.get("conn", 0) == 0


def test_bom_only_file_is_empty():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", "\ufeff")
        zeek = load(tmp)
        entry = next(e for e in zeek.metadata.files_processed
                     if e["log_type"] == "conn")
        assert entry["format"] == "empty"


def test_random_text_not_classified_as_tsv():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", "this is not json or zeek tsv\nmore text\n")
        zeek = load(tmp)
        entry = next(e for e in zeek.metadata.files_processed
                     if e["log_type"] == "conn")
        assert entry["format"] == "indeterminate"
        assert zeek.metadata.usable_records.get("conn", 0) == 0
        assert any("could not determine log format" in w
                   for w in zeek.metadata.warnings)


def test_physical_line_numbers_preserved_after_leading_blanks():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        # Two blank lines, a valid record, then a malformed record on line 4.
        _write(tmp, "conn.log",
               "\n\n" + _conn_json_line() + "\n{bad json\n")
        zeek = load(tmp)
        assert zeek.metadata.usable_records["conn"] == 1
        assert zeek.metadata.malformed_counts["conn"] == 1
        # The malformed record is physical line 4, not line 2.
        assert any("conn.log:4" in e for e in zeek.metadata.parse_errors)


def test_leading_blanks_do_not_change_result():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", _conn_json_line() + "\n")
        plain = load(tmp)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", "\n\n\n" + _conn_json_line() + "\n")
        blanked = load(tmp)
    assert (plain.metadata.usable_records["conn"]
            == blanked.metadata.usable_records["conn"] == 1)
    assert len(plain.aggregates) == len(blanked.aggregates) == 1


# ===========================================================================
# Issue 2 - raw/data-record accounting includes malformed
# ===========================================================================

def _invariant(zeek, log_type="conn"):
    raw = zeek.metadata.raw_records_read.get(log_type, 0)
    usable = zeek.metadata.usable_records.get(log_type, 0)
    malformed = zeek.metadata.malformed_counts.get(log_type, 0)
    assert raw == usable + malformed, (raw, usable, malformed)
    return raw, usable, malformed


def test_one_valid_record_accounting():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [CONN])
        raw, usable, malformed = _invariant(load(tmp))
        assert (raw, usable, malformed) == (1, 1, 0)


def test_one_malformed_json_line_counted():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", "{bad json\n")
        raw, usable, malformed = _invariant(load(tmp))
        assert (raw, usable, malformed) == (1, 0, 1)


def test_valid_plus_malformed_json():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", _conn_json_line() + "\n{bad\n")
        raw, usable, malformed = _invariant(load(tmp))
        assert (raw, usable, malformed) == (2, 1, 1)


def test_wrong_top_level_json_type_counted():
    # File is detected as JSON (first meaningful line is an object), then a
    # later line is a valid JSON value of the wrong top-level type: that is a
    # malformed DATA record, counted, not a format-detection miss.
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", _conn_json_line() + "\n[1, 2, 3]\n\"x\"\n")
        raw, usable, malformed = _invariant(load(tmp))
        assert (raw, usable, malformed) == (3, 1, 2)


def test_leading_json_array_is_indeterminate_not_tsv():
    # A file that opens with a JSON array is neither JSON Lines nor Zeek TSV;
    # it must not be silently treated as TSV (issue 1 guard).
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", "[1, 2, 3]\n")
        zeek = load(tmp)
        entry = next(e for e in zeek.metadata.files_processed
                     if e["log_type"] == "conn")
        assert entry["format"] == "indeterminate"


def test_missing_core_field_counted_as_malformed():
    bad = dict(CONN)
    bad.pop("id.orig_h")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [CONN, bad])
        raw, usable, malformed = _invariant(load(tmp))
        assert (raw, usable, malformed) == (2, 1, 1)


def test_invalid_ip_timestamp_and_port_counted():
    cases = [
        dict(CONN, **{"id.orig_h": "999.1.1.1"}),
        dict(CONN, ts="not-a-time"),
        dict(CONN, **{"id.resp_p": 70000}),
    ]
    for bad in cases:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            write_json_log(tmp, "conn.log", [dict(CONN), bad])
            raw, usable, malformed = _invariant(load(tmp))
            assert (raw, usable, malformed) == (2, 1, 1), bad


def test_blank_lines_mixed_do_not_count_as_records():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log",
               "\n" + _conn_json_line() + "\n\n{bad\n\n")
        raw, usable, malformed = _invariant(load(tmp))
        assert (raw, usable, malformed) == (2, 1, 1)  # blanks excluded


def test_tsv_valid_and_wrong_field_count():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        path = write_tsv_conn(tmp, [CONN])
        with path.open("a", encoding="utf-8") as handle:
            handle.write("too\tfew\tcols\n")
        raw, usable, malformed = _invariant(load(tmp))
        assert (raw, usable, malformed) == (2, 1, 1)


def test_tsv_directives_and_blanks_never_count_as_records():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        path = write_tsv_conn(tmp, [CONN])
        body = path.read_text().replace("\n", "\n\n", 3)  # sprinkle blanks
        path.write_text(body)
        raw, usable, malformed = _invariant(load(tmp))
        # Only the one data row is a record; 7 directives + blanks excluded.
        assert (raw, usable, malformed) == (1, 1, 0)


def test_tsv_malformed_after_many_valid():
    rows = [conn(f"C{i}", "192.168.20.15", "192.168.10.30", 5432, ts=float(i))
            for i in range(50)]
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        path = write_tsv_conn(tmp, rows)
        with path.open("a", encoding="utf-8") as handle:
            handle.write("bad\trow\n")
        raw, usable, malformed = _invariant(load(tmp))
        assert (raw, usable, malformed) == (51, 50, 1)


def test_data_records_seen_field_present_and_consistent():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", _conn_json_line() + "\n{bad\n")
        zeek = load(tmp)
        entry = next(e for e in zeek.metadata.files_processed
                     if e["log_type"] == "conn")
        assert entry["data_records_seen"] == 2
        assert entry["records"] == 1
        assert entry["malformed"] == 1
        assert entry["data_records_seen"] == entry["records"] + entry["malformed"]


def test_accounting_surfaces_in_manifest_and_summary():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        zdir = tmp / "zeek"
        bad = dict(CONN)
        bad.pop("proto")
        write_json_log(zdir, "conn.log", [CONN, bad])
        out = tmp / "out"
        assert main(["--input", str(tmp / "scan.xml"), "--output-dir", str(out),
                     "--scanner-ip", "192.168.1.50",
                     "--zeek-dir", str(zdir)]) == 0
        manifest = json.loads((out / "run_manifest.json").read_text("utf-8"))
        zb = manifest["zeek"]
        assert zb["raw_records_read"]["conn"] == 2
        assert zb["usable_records"]["conn"] == 1
        assert zb["malformed_record_counts"]["conn"] == 1
        assert (zb["raw_records_read"]["conn"]
                == zb["usable_records"]["conn"]
                + zb["malformed_record_counts"]["conn"])
        summary = json.loads((out / "zeek_input_summary.json").read_text("utf-8"))
        meta = summary["input_metadata"]
        assert meta["raw_records_read"]["conn"] == 2
        assert meta["usable_records"]["conn"] == 1


# ===========================================================================
# Issue 3 - per-file vs global sample-cap metadata
# ===========================================================================

FILES_CAP = 200
NOTICE_CAP = 100


def _files_records(n, start=0):
    return [{"ts": float(i), "conn_uids": ["C1"], "source": "X",
             "filename": f"f{i}.der", "total_bytes": 1}
            for i in range(start, start + n)]


def _notice_records(n, start=0):
    return [{"ts": float(i), "note": f"N{i}", "msg": "m"}
            for i in range(start, start + n)]


def _rotated_files(sizes, malformed_after=None):
    """Build a dir with conn.log + rotated files.log parts of given sizes."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [CONN])
        names = ["files.log"] + [
            f"files.2026-07-20-0{i}-00-00.log" for i in range(1, len(sizes))
        ]
        offset = 0
        for name, size in zip(names, sizes):
            write_json_log(tmp, name, _files_records(size, offset))
            offset += size
        zeek = load(tmp)
        entries = [e for e in zeek.metadata.files_processed
                   if e["log_type"] == "files"]
        summary = next(s for s in zeek.metadata.log_type_summaries
                       if s["log_type"] == "files")
        return zeek, entries, summary


def test_rotated_files_each_appear_once_with_per_file_counts():
    _, entries, summary = _rotated_files([150, 100])
    assert len(entries) == 2
    by_name = {e["file"]: e for e in entries}
    assert by_name["files.log"]["records"] == 150
    assert by_name["files.2026-07-20-01-00-00.log"]["records"] == 100
    # No per-file entry carries the global sample totals.
    for entry in entries:
        assert "samples_retained" not in entry
        assert "samples_truncated" not in entry
    assert summary["files_processed"] == 2
    assert summary["records"] == 250


def test_two_files_below_total_cap():
    _, _, summary = _rotated_files([80, 90])  # 170 < 200
    assert summary["samples_retained"] == 170
    assert summary["samples_truncated"] == 0


def test_second_file_crosses_total_cap():
    _, _, summary = _rotated_files([150, 100])  # 250 > 200
    assert summary["samples_retained"] == FILES_CAP
    assert summary["samples_truncated"] == 50
    assert summary["sample_scope"] == "global_across_log_type"


def test_first_file_alone_exceeds_cap():
    _, _, summary = _rotated_files([250, 30])
    assert summary["samples_retained"] == FILES_CAP
    assert summary["samples_truncated"] == 80


def test_three_rotated_files_counted_once_each():
    _, entries, summary = _rotated_files([90, 90, 90])  # 270 total
    assert len(entries) == 3
    assert summary["files_processed"] == 3
    assert summary["records"] == 270
    assert summary["samples_retained"] == FILES_CAP
    assert summary["samples_truncated"] == 70


def test_rotated_notice_files_global_cap():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [CONN])
        write_json_log(tmp, "notice.log", _notice_records(70))
        write_json_log(tmp, "notice.2026-07-20-01-00-00.log",
                       _notice_records(60, start=70))
        zeek = load(tmp)
        entries = [e for e in zeek.metadata.files_processed
                   if e["log_type"] == "notice"]
        assert len(entries) == 2
        assert {e["records"] for e in entries} == {70, 60}
        for entry in entries:
            assert "samples_retained" not in entry
        summary = next(s for s in zeek.metadata.log_type_summaries
                       if s["log_type"] == "notice")
        assert summary["records"] == 130
        assert summary["samples_retained"] == NOTICE_CAP
        assert summary["samples_truncated"] == 30


def test_malformed_before_and_after_cap_across_rotated_files():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [CONN])
        p1 = write_json_log(tmp, "files.log", _files_records(150))
        with p1.open("a", encoding="utf-8") as handle:
            handle.write("{bad before cap\n")  # malformed in first file
        p2 = write_json_log(tmp, "files.2026-07-20-01-00-00.log",
                            _files_records(100, start=150))
        with p2.open("a", encoding="utf-8") as handle:
            handle.write("{bad after cap\n")  # malformed past the global cap
        zeek = load(tmp)
        assert zeek.metadata.malformed_counts["files"] == 2
        summary = next(s for s in zeek.metadata.log_type_summaries
                       if s["log_type"] == "files")
        assert summary["malformed"] == 2
        assert summary["records"] == 250
        assert summary["samples_retained"] == FILES_CAP


def test_gzip_and_plain_rotated_files_behave_identically():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_json_log(tmp, "conn.log", [CONN])
        write_json_log(tmp, "files.log", _files_records(150))
        write_json_log(tmp, "files.2026-07-20-01-00-00.log.gz",
                       _files_records(100, start=150), gz=True)
        zeek = load(tmp)
        entries = [e for e in zeek.metadata.files_processed
                   if e["log_type"] == "files"]
        assert len(entries) == 2
        summary = next(s for s in zeek.metadata.log_type_summaries
                       if s["log_type"] == "files")
        assert summary["records"] == 250
        assert summary["samples_retained"] == FILES_CAP
        assert summary["samples_truncated"] == 50


def test_global_retained_never_exceeds_cap():
    for sizes in ([300], [150, 150], [90, 90, 90, 90]):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            write_json_log(tmp, "conn.log", [CONN])
            offset = 0
            for idx, size in enumerate(sizes):
                name = "files.log" if idx == 0 else \
                    f"files.2026-07-20-0{idx}-00-00.log"
                write_json_log(tmp, name, _files_records(size, offset))
                offset += size
            zeek = load(tmp)
            summary = next(s for s in zeek.metadata.log_type_summaries
                           if s["log_type"] == "files")
            assert summary["samples_retained"] <= FILES_CAP
            assert (summary["samples_retained"] + summary["samples_truncated"]
                    == sum(sizes))


# ===========================================================================
# Issue 4 - pluralization helpers and clean report wording
# ===========================================================================

def test_plural_regular_and_irregular():
    assert plural("host", 1) == "host"
    assert plural("host", 0) == "hosts"
    assert plural("host", 2) == "hosts"
    assert plural("dependency", 1) == "dependency"
    assert plural("dependency", 2) == "dependencies"
    assert plural("discrepancy", 3) == "discrepancies"
    assert plural("anomaly", 2) == "anomalies"
    assert plural("service", 2) == "services"
    assert plural("perspective", 2) == "perspectives"
    # A vowel before trailing 'y' keeps the 's' form.
    assert plural("day", 2) == "days"


def test_count_noun_zero_one_many():
    assert count_noun(0, "communication") == "0 communications"
    assert count_noun(1, "communication") == "1 communication"
    assert count_noun(2, "communication") == "2 communications"
    assert count_noun(1, "dependency") == "1 dependency"
    assert count_noun(2, "dependency") == "2 dependencies"
    assert count_noun(1, "flow") == "1 flow"
    assert count_noun(6, "flow") == "6 flows"


def test_were_has_and_verb_agreement():
    assert were(0) == "were"
    assert were(1) == "was"
    assert were(2) == "were"
    assert has(1) == "has"
    assert has(0) == "have"
    assert has(2) == "have"
    assert verb(1, "is", "are") == "is"
    assert verb(2, "is", "are") == "are"


_BAD_WORDING = ["(s)", "(ies)", "was/were", "dependenc(ies)",
                "communication(s)", "flow(s)", "host(s)", "service(s)",
                "endpoint(s)", "item(s)", "connection(s)", "byte(s)",
                "aggregate(s)", "anomal(ies)", "perspective(s)", "type(s)"]


def _sample_texts(with_zeek: bool):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        args = ["--input", str(tmp / "scan.xml"),
                "--output-dir", str(tmp / "out"),
                "--scanner-ip", "192.168.1.50", "--excel"]
        if with_zeek:
            zdir = tmp / "zeek"
            write_json_log(zdir, "conn.log", [CONN])
            write_json_log(zdir, "notice.log", _notice_records(2))
            write_json_log(zdir, "weird.log",
                           [{"ts": 1.0, "name": "bad_TCP_checksum"}])
            args += ["--zeek-dir", str(zdir)]
        assert main(args) == 0
        out = tmp / "out"
        return (out / "analysis_report.html").read_text("utf-8") + \
            (out / "findings_summary.md").read_text("utf-8")


def test_combined_report_has_no_mechanical_wording():
    text = _sample_texts(with_zeek=True)
    for bad in _BAD_WORDING:
        assert bad not in text, f"combined report still contains {bad!r}"


def test_nmap_only_report_has_no_mechanical_wording():
    text = _sample_texts(with_zeek=False)
    for bad in _BAD_WORDING:
        assert bad not in text, f"nmap-only report still contains {bad!r}"


def test_singular_wording_when_exactly_one():
    # MULTI_HOST_XML + a single Zeek flow: exercise singular agreement paths.
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        zdir = tmp / "zeek"
        write_json_log(zdir, "conn.log", [CONN])
        out = tmp / "out"
        assert main(["--input", str(tmp / "scan.xml"), "--output-dir", str(out),
                     "--scanner-ip", "192.168.1.50",
                     "--zeek-dir", str(zdir)]) == 0
        html = (out / "analysis_report.html").read_text("utf-8")
        # Whatever the counts, no "(s)" scaffolding remains.
        for bad in _BAD_WORDING:
            assert bad not in html
