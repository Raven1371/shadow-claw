"""Tests for Zeek log discovery and streaming parsing (v1.2.0)."""

from __future__ import annotations

import gzip
import os
import tempfile
from pathlib import Path

from nmap_flow_analyzer.zeek_models import ZeekInputMetadata
from nmap_flow_analyzer.zeek_parser import classify_filename, discover_logs, iter_log_records
from tests.zeek_fixtures import conn, load, write_json_log, write_tsv_conn, zeek_config


def test_json_lines_parsed_and_counted():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.10.20", "192.168.10.30", 5432),
            conn("C2", "192.168.10.20", "192.168.10.30", 5432, ts=20.0),
        ])
        zeek = load(tmp)
        assert zeek.metadata.conn_log_available
        assert zeek.metadata.record_counts["conn"] == 2
        assert len(zeek.aggregates) == 1
        assert zeek.aggregates[0].connection_count == 2


def test_tsv_parsed_with_headers_unset_and_empty():
    with tempfile.TemporaryDirectory() as tmp:
        record = conn("C1", "192.168.10.20", "192.168.10.30", 5432,
                      service="postgresql")
        record["duration"] = None  # unset -> '-'
        empty = conn("C2", "192.168.10.20", "192.168.10.30", 5432, ts=20.0)
        empty["service"] = ""  # -> (empty)
        write_tsv_conn(Path(tmp), [record, empty])
        zeek = load(tmp)
        assert zeek.metadata.conn_log_available
        agg = zeek.aggregates[0]
        assert agg.connection_count == 2
        assert agg.services == ["postgresql"]  # empty value stayed empty
        assert zeek.metadata.files_processed[0]["format"] == "tsv"


def test_gzipped_json_and_tsv_streamed():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp) / "a", "conn.log.gz",
                       [conn("C1", "192.168.10.20", "192.168.10.30", 5432)],
                       gz=True)
        write_tsv_conn(Path(tmp) / "b",
                       [conn("C2", "192.168.20.15", "192.168.10.30", 5432)],
                       name="conn.log.gz", gz=True)
        zeek = load([Path(tmp) / "a", Path(tmp) / "b"])
        assert zeek.metadata.record_counts["conn"] == 2
        assert len(zeek.aggregates) == 2  # different originators never merge


def test_rotated_filenames_recognized():
    assert classify_filename("conn.log") == ("conn", False)
    assert classify_filename("conn.log.gz") == ("conn", True)
    assert classify_filename("conn.2026-07-20-01-00-00.log") == ("conn", False)
    assert classify_filename("dns.2026-07-20-01-00-00.log.gz") == ("dns", True)
    assert classify_filename("conn.log.1") == ("conn", False)
    assert classify_filename("conn-20260720.log.gz") == ("conn", True)
    assert classify_filename("random.txt") is None
    assert classify_filename("notzeek.log") is None  # unsupported log type


def test_multiple_and_rotated_files_of_same_type():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log",
                       [conn("C1", "192.168.10.20", "192.168.10.30", 5432)])
        write_json_log(Path(tmp), "conn.2026-07-20-01-00-00.log",
                       [conn("C2", "192.168.10.20", "192.168.10.30", 5432, ts=99.0)])
        zeek = load(tmp)
        assert zeek.aggregates[0].connection_count == 2


def test_unknown_fields_ignored_without_error():
    with tempfile.TemporaryDirectory() as tmp:
        record = conn("C1", "192.168.10.20", "192.168.10.30", 5432,
                      future_zeek_field="whatever", nested={"x": 1})
        write_json_log(Path(tmp), "conn.log", [record])
        zeek = load(tmp)
        assert zeek.metadata.conn_log_available
        assert not zeek.metadata.parse_errors


def test_malformed_json_counted_with_location():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "conn.log"
        good = write_json_log(Path(tmp), "conn.log",
                              [conn("C1", "192.168.10.20", "192.168.10.30", 5432)])
        with good.open("a", encoding="utf-8") as handle:
            handle.write("{this is not json}\n")
            handle.write('["a json array, not an object"]\n')
        zeek = load(tmp)
        assert zeek.metadata.malformed_counts["conn"] == 2
        assert any("conn.log:2" in e for e in zeek.metadata.parse_errors)
        assert zeek.aggregates[0].connection_count == 1


def test_malformed_tsv_row_counted():
    with tempfile.TemporaryDirectory() as tmp:
        path = write_tsv_conn(Path(tmp),
                              [conn("C1", "192.168.10.20", "192.168.10.30", 5432)])
        with path.open("a", encoding="utf-8") as handle:
            handle.write("only\tthree\tcolumns\n")
        zeek = load(tmp)
        assert zeek.metadata.malformed_counts["conn"] == 1
        assert zeek.aggregates[0].connection_count == 1


def test_blank_lines_ignored():
    with tempfile.TemporaryDirectory() as tmp:
        path = write_json_log(Path(tmp), "conn.log",
                              [conn("C1", "192.168.10.20", "192.168.10.30", 5432)])
        path.write_text(path.read_text() + "\n\n\n", encoding="utf-8")
        zeek = load(tmp)
        assert zeek.metadata.malformed_counts.get("conn", 0) == 0
        assert zeek.metadata.record_counts["conn"] == 1


def test_empty_file_warned_not_fatal():
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "conn.log").write_text("", encoding="utf-8")
        zeek = load(tmp)
        assert not zeek.metadata.conn_log_available
        assert any("empty" in w or "no usable" in w
                   for w in zeek.metadata.warnings)


def test_missing_conn_log_flagged_not_fatal():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "dns.log", [{"uid": "X", "query": "a.example"}])
        zeek = load(tmp)
        assert not zeek.metadata.conn_log_available
        assert zeek.health.status == "unusable"
        assert any("conn.log" in w for w in zeek.metadata.warnings)


def test_duplicate_uids_skipped_and_warned():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("SAME", "192.168.10.20", "192.168.10.30", 5432),
            conn("SAME", "192.168.10.20", "192.168.10.30", 5432, ts=30.0),
        ])
        zeek = load(tmp)
        assert zeek.aggregates[0].connection_count == 1
        assert any("duplicate" in w.lower() for w in zeek.metadata.warnings)


def test_ipv6_records_supported():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log",
                       [conn("C6", "2001:db8::10", "2001:db8::20", 22)])
        zeek = load(tmp)
        agg = zeek.aggregates[0]
        assert agg.ip_version == 6
        assert agg.originator == "2001:db8::10"


def test_max_line_length_limit_stops_file_safely():
    cfg = zeek_config(max_line_length_bytes=2048)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "conn.log"
        import json as _json
        good = _json.dumps(conn("C1", "192.168.10.20", "192.168.10.30", 5432))
        hostile = '{"padding": "' + "A" * 10000 + '"}'
        path.write_text(good + "\n" + hostile + "\n", encoding="utf-8")
        zeek = load(tmp, cfg)
        assert zeek.aggregates[0].connection_count == 1
        assert any("max_line_length_bytes" in w for w in zeek.metadata.warnings)


def test_max_records_limit_enforced():
    cfg = zeek_config(max_records_per_file=3)
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn(f"C{i}", "192.168.10.20", "192.168.10.30", 5432, ts=float(i))
            for i in range(10)
        ])
        zeek = load(tmp, cfg)
        assert zeek.aggregates[0].connection_count <= 3
        assert any("max_records_per_file" in w for w in zeek.metadata.warnings)


def test_hostile_gzip_bomb_is_bounded():
    cfg = zeek_config(max_line_length_bytes=4096, max_records_per_file=100)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "conn.log.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write('{"x": "' + "B" * 5_000_000 + '"}\n')  # one huge line
        zeek = load(tmp, cfg)  # must not exhaust memory or crash
        assert any("max_line_length_bytes" in w for w in zeek.metadata.warnings)


def test_symlinked_files_and_directories_skipped():
    with tempfile.TemporaryDirectory() as tmp:
        real = Path(tmp) / "real"
        write_json_log(real, "conn.log",
                       [conn("C1", "192.168.10.20", "192.168.10.30", 5432)])
        link_file = real / "dns.log"
        target = Path(tmp) / "outside.log"
        target.write_text('{"uid": "X"}\n', encoding="utf-8")
        try:
            os.symlink(target, link_file)
        except (OSError, NotImplementedError, AttributeError) as exc:
            import pytest
            pytest.skip(
                "platform cannot create symbolic links required by this "
                f"security setup: {exc}"
            )
        link_dir = Path(tmp) / "linkdir"
        os.symlink(real, link_dir)
        zeek = load([real, link_dir])
        assert zeek.metadata.record_counts.get("dns", 0) == 0
        assert sum(1 for w in zeek.metadata.warnings if "symbolic link" in w) >= 2
        assert zeek.aggregates[0].connection_count == 1  # not double-counted


def test_mixed_formats_in_one_directory_auto_detected():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log",
                       [conn("C1", "192.168.10.20", "192.168.10.30", 5432)])
        write_tsv_conn(Path(tmp),
                       [conn("C2", "192.168.10.20", "192.168.10.30", 5432, ts=20.0)],
                       name="conn.2026-07-20-01-00-00.log")
        zeek = load(tmp, fmt="auto")
        formats = {f["format"] for f in zeek.metadata.files_processed}
        assert formats == {"json", "tsv"}
        assert zeek.aggregates[0].connection_count == 2


def test_deterministic_discovery_and_aggregate_ordering():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C3", "192.168.10.99", "192.168.10.30", 5432),
            conn("C1", "192.168.10.20", "192.168.10.30", 5432),
            conn("C2", "192.168.10.20", "192.168.10.30", 443),
        ])
        first = load(tmp)
        second = load(tmp)
        keys = [a.key for a in first.aggregates]
        assert keys == [a.key for a in second.aggregates]
        assert keys == sorted(keys, key=lambda k: (k[1], k[2], k[3], k[0]))


def test_tsv_separator_decoding():
    with tempfile.TemporaryDirectory() as tmp:
        meta = ZeekInputMetadata()
        path = write_tsv_conn(Path(tmp),
                              [conn("C1", "192.168.10.20", "192.168.10.30", 5432,
                                    **{"tunnel_parents": ["P1", "P2"]})])
        records = list(iter_log_records(path, "conn", meta))
        assert records[0]["id.orig_h"] == "192.168.10.20"
        assert records[0]["tunnel_parents"] == ["P1", "P2"]  # set decoded


def test_discovery_ignores_unsupported_and_hidden_entries():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log",
                       [conn("C1", "192.168.10.20", "192.168.10.30", 5432)])
        (Path(tmp) / "notes.txt").write_text("x", encoding="utf-8")
        (Path(tmp) / "subdir").mkdir()
        meta = ZeekInputMetadata()
        logs = discover_logs([Path(tmp)], meta)
        assert set(logs) == {"conn"}
