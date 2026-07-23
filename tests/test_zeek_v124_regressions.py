"""v1.2.4 regression tests.

Issue 1 - execution/diagnostic log messages use natural singular/plural.
Issue 2 - native Zeek TSV auto-detection requires a recognized directive.
"""

from __future__ import annotations

import gzip
import json
import logging
import tempfile
from pathlib import Path

from nmap_flow_analyzer.cli import main
from nmap_flow_analyzer.pluralize import count_noun, has, plural, verb, were
from nmap_flow_analyzer.zeek_parser import (
    ZEEK_TSV_DIRECTIVES,
    detect_zeek_format,
)
from tests.fixtures import MULTI_HOST_XML
from tests.zeek_fixtures import conn, load, write_json_log, write_tsv_conn

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


# ===========================================================================
# Issue 1 - pluralization helpers and clean log wording
# ===========================================================================

def test_plural_helper_zero_one_many():
    for noun in ("host", "service", "flow", "communication", "item", "rule",
                 "endpoint", "file", "record"):
        assert plural(noun, 1) == noun
        assert plural(noun, 0) == noun + "s"
        assert plural(noun, 2) == noun + "s"
    assert plural("dependency", 1) == "dependency"
    assert plural("dependency", 2) == "dependencies"


def test_count_noun_zero_one_many():
    assert count_noun(0, "host") == "0 hosts"
    assert count_noun(1, "host") == "1 host"
    assert count_noun(2, "host") == "2 hosts"
    assert count_noun(0, "dependency") == "0 dependencies"
    assert count_noun(1, "dependency") == "1 dependency"
    assert count_noun(2, "dependency") == "2 dependencies"
    assert count_noun(1, "external dependency") == "1 external dependency"
    assert count_noun(3, "external dependency") == "3 external dependencies"
    assert count_noun(1, "manual-review item") == "1 manual-review item"
    assert count_noun(12, "manual-review item") == "12 manual-review items"


def test_was_were_has_have_verb_agreement():
    assert were(1) == "was" and were(0) == "were" and were(2) == "were"
    assert has(1) == "has" and has(0) == "have" and has(2) == "have"
    assert verb(1, "is", "are") == "is" and verb(2, "is", "are") == "are"


_BAD = ["(s)", "(ies)", "was/were", "host(s)", "service(s)", "flow(s)",
        "communication(s)", "dependenc(ies)", "item(s)", "rule(s)",
        "zone(s)", "finding(s)", "observation(s)", "aggregate(s)",
        "endpoint(s)", "record(s)", "file(s)", "directorie(s)"]


def _run_and_capture_log(with_zeek: bool):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        args = ["--input", str(tmp / "scan.xml"),
                "--output-dir", str(tmp / "out"),
                "--scanner-ip", "192.168.1.50", "--excel"]
        if with_zeek:
            zdir = tmp / "zeek"
            write_json_log(zdir, "conn.log", [CONN])
            write_json_log(zdir, "notice.log",
                           [{"ts": 1.0, "note": "N", "msg": "m"}])
            write_json_log(zdir, "weird.log",
                           [{"ts": 1.0, "name": "bad_TCP_checksum"}])
            args += ["--zeek-dir", str(zdir)]
        assert main(args) == 0
        out = tmp / "out"
        exec_log = ""
        if (out / "execution.log").exists():
            exec_log = (out / "execution.log").read_text("utf-8")
        return exec_log


def test_execution_log_has_no_mechanical_wording_combined():
    text = _run_and_capture_log(with_zeek=True)
    assert text, "execution.log was empty"
    for bad in _BAD:
        assert bad not in text, f"execution.log contains {bad!r}"


def test_execution_log_has_no_mechanical_wording_nmap_only():
    text = _run_and_capture_log(with_zeek=False)
    assert text
    for bad in _BAD:
        assert bad not in text, f"execution.log contains {bad!r}"


def test_diagnostic_log_natural_forms_present():
    # execution.log is the real diagnostic log; confirm the polished natural
    # forms actually appear there (not just the absence of "(s)").
    text = _run_and_capture_log(with_zeek=True)
    # Natural forms present (counts vary, so match the count-agnostic stems).
    assert "hosts from" in text  # parser.py: count_noun("host"), 4 hosts
    assert "aggregated flow" in text  # cli.py: count_noun("aggregated flow")
    assert "candidate inbound rule" in text  # firewall_rules.py
    assert "external dependenc" in text  # cli.py: singular or plural
    for bad in _BAD:
        assert bad not in text


# ===========================================================================
# Issue 2 - strict native Zeek TSV directive recognition
# ===========================================================================

def test_detect_zeek_format_helper():
    assert detect_zeek_format('{"ts": 1}') == "json"
    for directive in ZEEK_TSV_DIRECTIVES:
        assert detect_zeek_format(f"{directive} \\x09") == "tsv", directive
        assert detect_zeek_format(directive) == "tsv", directive
    # A '#' that is not a recognized directive is never TSV.
    for bad in ("#random", "#comment", "#separator_fake", "#fieldsx",
                "#", "## double", "#separators"):
        assert detect_zeek_format(bad) == "indeterminate", bad
    # Neither JSON nor a directive.
    for other in ("plain text", "ts,uid,proto", "[1,2,3]", '"a string"', ""):
        assert detect_zeek_format(other) == "indeterminate", other


ALL_DIRECTIVES = sorted(ZEEK_TSV_DIRECTIVES)


def test_recognized_directive_set_is_complete_and_immutable():
    expected = {
        "#separator", "#set_separator", "#empty_field", "#unset_field",
        "#path", "#open", "#fields", "#types", "#close",
    }
    assert set(ZEEK_TSV_DIRECTIVES) == expected
    assert isinstance(ZEEK_TSV_DIRECTIVES, frozenset)


def _detect_file(content: str, gz: bool = False):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log.gz" if gz else "conn.log", content, gz=gz)
        zeek = load(tmp)
        entries = [e for e in zeek.metadata.files_processed
                   if e["log_type"] == "conn"]
        return zeek, entries


CONN_JSON = json.dumps(CONN)


def test_valid_json_variants_detected():
    for content in (CONN_JSON + "\n",
                    "\n\n" + CONN_JSON + "\n",
                    "   " + CONN_JSON + "\n",
                    "\ufeff" + CONN_JSON + "\n"):
        zeek, entries = _detect_file(content)
        assert len(entries) == 1
        assert entries[0]["format"] == "json"
        assert zeek.metadata.usable_records["conn"] == 1


def test_valid_json_gzip_and_rotated():
    zeek, entries = _detect_file("\n" + CONN_JSON + "\n", gz=True)
    assert entries[0]["format"] == "json"
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", CONN_JSON + "\n")
        _write(tmp, "conn.2026-07-20-01-00-00.log",
               json.dumps(conn("C2", "192.168.20.16", "192.168.10.30", 5432))
               + "\n")
        zeek = load(tmp)
        entries = [e for e in zeek.metadata.files_processed
                   if e["log_type"] == "conn"]
        assert len(entries) == 2
        assert all(e["format"] == "json" for e in entries)


def test_valid_tsv_variants_detected():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        base = write_tsv_conn(tmp, [CONN]).read_text()
    for prefix, gz in (("", False), ("\n\n", False), ("\ufeff", False),
                       ("", True)):
        zeek, entries = _detect_file(prefix + base, gz=gz)
        assert len(entries) == 1, (prefix, gz)
        assert entries[0]["format"] == "tsv", (prefix, gz)
        assert zeek.metadata.usable_records["conn"] == 1


def test_tsv_starting_with_fields_directive():
    # A file whose first meaningful directive is #fields (no #separator first)
    # is still recognized as TSV.
    body = (
        "#fields\tts\tuid\tid.orig_h\tid.resp_h\tproto\tid.resp_p\n"
        "#types\ttime\tstring\taddr\taddr\tenum\tport\n"
        "1721462410.0\tC1\t192.168.20.15\t192.168.10.30\ttcp\t5432\n"
    )
    zeek, entries = _detect_file(body)
    assert entries[0]["format"] == "tsv"


def test_rotated_tsv_files_detected():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_tsv_conn(tmp, [CONN])
        write_tsv_conn(tmp, [conn("C2", "192.168.20.16", "192.168.10.30", 5432)],
                       name="conn.2026-07-20-01-00-00.log")
        zeek = load(tmp)
        entries = [e for e in zeek.metadata.files_processed
                   if e["log_type"] == "conn"]
        assert len(entries) == 2
        assert all(e["format"] == "tsv" for e in entries)


def _assert_indeterminate(content: str, expect_line: int = 1):
    zeek, entries = _detect_file(content)
    assert len(entries) == 1, "duplicate files_processed entry"
    assert entries[0]["format"] == "indeterminate"
    assert zeek.metadata.usable_records.get("conn", 0) == 0
    assert zeek.metadata.record_counts.get("conn", 0) == 0
    warn = [w for w in zeek.metadata.warnings if "determine" in w]
    assert warn, "no bounded warning produced"
    assert f":{expect_line}:" in warn[0] or f"conn.log:{expect_line}" in warn[0]
    # The full untrusted line is not echoed back.
    assert "this is not a Zeek log" not in warn[0]
    return zeek


def test_hash_random_is_indeterminate_not_tsv():
    _assert_indeterminate("#random comment\nthis is not a Zeek log\n")


def test_hash_comment_is_indeterminate():
    _assert_indeterminate("#comment only\n")


def test_separator_fake_is_indeterminate():
    _assert_indeterminate("#separator_fake\n#fields\tts\n")


def test_ordinary_text_is_indeterminate():
    _assert_indeterminate("ordinary text line\nmore text\n")


def test_blank_only_and_bom_only_are_empty():
    for content in ("", "\n\n\n", "   \n\t\n", "\ufeff"):
        zeek, entries = _detect_file(content)
        assert len(entries) == 1
        assert entries[0]["format"] == "empty"


def test_indeterminate_reports_correct_physical_line():
    # Two leading blank lines then the bad header: physical line 3.
    _assert_indeterminate("\n\n#random\n", expect_line=3)


def test_indeterminate_creates_no_duplicate_entry_and_no_record():
    zeek, entries = _detect_file("#random\nsome data\nmore data\n")
    assert len(entries) == 1
    assert entries[0]["records"] == 0
    assert entries[0]["malformed"] == 0
    assert entries[0].get("data_records_seen", 0) == 0


# ---- Explicit format selection still works ----

def test_explicit_json_bypasses_detection_but_validates():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        # A file that auto-detect would call indeterminate, but forced json.
        _write(tmp, "conn.log", CONN_JSON + "\n{bad json\n")
        zeek = load(tmp, fmt="json")
        entry = next(e for e in zeek.metadata.files_processed
                     if e["log_type"] == "conn")
        assert entry["format"] == "json"
        assert zeek.metadata.usable_records["conn"] == 1
        assert zeek.metadata.malformed_counts["conn"] == 1


def test_explicit_tsv_bypasses_detection_but_validates():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_tsv_conn(tmp, [CONN])
        zeek = load(tmp, fmt="tsv")
        entry = next(e for e in zeek.metadata.files_processed
                     if e["log_type"] == "conn")
        assert entry["format"] == "tsv"
        assert zeek.metadata.usable_records["conn"] == 1
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        # Forced tsv on structurally broken TSV still applies validation.
        _write(tmp, "conn.log",
               "#fields\tts\tuid\tproto\n"
               "#types\ttime\tstring\tenum\n"
               "only\ttwo\n")  # wrong field count
        zeek = load(tmp, fmt="tsv")
        assert zeek.metadata.malformed_counts.get("conn", 0) >= 1


def test_explicit_tsv_on_json_content_is_not_silently_accepted():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        _write(tmp, "conn.log", CONN_JSON + "\n")
        zeek = load(tmp, fmt="tsv")
        # JSON body under forced TSV has no #fields header -> malformed, not a
        # usable record.
        assert zeek.metadata.usable_records.get("conn", 0) == 0


# ===========================================================================
# Version
# ===========================================================================

def test_version_is_1_2_5():
    from nmap_flow_analyzer import __version__

    assert __version__ == "1.2.5"
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scan.xml").write_text(MULTI_HOST_XML, encoding="utf-8")
        zdir = tmp / "zeek"
        write_json_log(zdir, "conn.log", [CONN])
        out = tmp / "out"
        assert main(["--input", str(tmp / "scan.xml"), "--output-dir", str(out),
                     "--scanner-ip", "192.168.1.50",
                     "--zeek-dir", str(zdir)]) == 0
        manifest = json.loads((out / "run_manifest.json").read_text("utf-8"))
        assert manifest["version"] == "1.2.5"
        assert "1.2.5" in (out / "analysis_report.html").read_text("utf-8")
