"""Tests for connection-outcome classification and aggregation (v1.2.0)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from nmap_flow_analyzer.zeek_aggregation import assess_sensor_health, classify_connection
from nmap_flow_analyzer.zeek_models import (
    OUTCOME_AMBIGUOUS,
    OUTCOME_FAILED,
    OUTCOME_ONE_WAY,
    OUTCOME_PARTIAL,
    OUTCOME_REJECTED,
    OUTCOME_SUCCESSFUL,
)
from tests.zeek_fixtures import conn, load, write_json_log, zeek_config

# Every supported TCP conn_state and its conservative classification.
TCP_EXPECTATIONS = {
    "SF": OUTCOME_SUCCESSFUL,
    "S1": OUTCOME_SUCCESSFUL,
    "S2": OUTCOME_SUCCESSFUL,
    "S3": OUTCOME_SUCCESSFUL,
    "RSTO": OUTCOME_SUCCESSFUL,
    "RSTR": OUTCOME_SUCCESSFUL,
    "S0": OUTCOME_FAILED,
    "REJ": OUTCOME_REJECTED,
    "RSTOS0": OUTCOME_FAILED,
    "SH": OUTCOME_ONE_WAY,
    "SHR": OUTCOME_AMBIGUOUS,
    "RSTRH": OUTCOME_AMBIGUOUS,
    "OTH": OUTCOME_PARTIAL,
}


def test_every_tcp_state_classified():
    for state, expected in TCP_EXPECTATIONS.items():
        assert classify_connection("tcp", state) == expected, state
    # Unknown/future states classify conservatively, never as success.
    assert classify_connection("tcp", "XYZ") == OUTCOME_AMBIGUOUS
    assert classify_connection("tcp", "") == OUTCOME_AMBIGUOUS
    # Case-insensitive state handling.
    assert classify_connection("tcp", "sf") == OUTCOME_SUCCESSFUL


def test_udp_needs_responder_evidence():
    assert classify_connection("udp", "SF", resp_pkts=1) == OUTCOME_SUCCESSFUL
    assert classify_connection("udp", "SF", resp_bytes=10) == OUTCOME_SUCCESSFUL
    # No responder packets/bytes: one-way, never a success.
    assert classify_connection("udp", "SF") == OUTCOME_ONE_WAY
    assert classify_connection("udp", "S0", orig_pkts=5) == OUTCOME_ONE_WAY
    assert classify_connection("udp", "REJ") == OUTCOME_REJECTED


def test_icmp_never_successful():
    assert classify_connection("icmp", "OTH") == OUTCOME_ONE_WAY
    assert classify_connection("icmp", "OTH", resp_pkts=2) == OUTCOME_PARTIAL
    for state in ("SF", "S0", ""):
        assert classify_connection("icmp", state) in (
            OUTCOME_ONE_WAY, OUTCOME_PARTIAL
        )


def test_unknown_protocol_ambiguous():
    assert classify_connection("sctp", "SF") == OUTCOME_AMBIGUOUS


def test_aggregation_counts_bytes_packets_durations():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.10.20", "192.168.10.30", 5432, ts=10.0,
                 orig_bytes=100, resp_bytes=200, orig_pkts=3, resp_pkts=4,
                 duration=1.5, state="SF"),
            conn("C2", "192.168.10.20", "192.168.10.30", 5432, ts=90.0,
                 orig_bytes=50, resp_bytes=60, orig_pkts=1, resp_pkts=2,
                 duration=4.0, state="RSTO"),
            conn("C3", "192.168.10.20", "192.168.10.30", 5432, ts=50.0,
                 state="REJ", orig_bytes=0, resp_bytes=0, duration=0.0),
        ])
        agg = load(tmp).aggregates[0]
        assert agg.connection_count == 3
        assert agg.successful_count == 2
        assert agg.rejected_count == 1
        assert agg.originator_bytes == 150 and agg.responder_bytes == 260
        assert agg.originator_packets == 12 and agg.responder_packets == 13
        assert agg.total_duration == 5.5 and agg.max_duration == 4.0
        assert agg.conn_states == ["REJ", "RSTO", "SF"]  # distinct, sorted
        assert abs(agg.success_ratio - 2 / 3) < 1e-9
        assert agg.outcome_label == OUTCOME_SUCCESSFUL


def test_first_and_last_seen_are_utc_iso():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C2", "192.168.10.20", "192.168.10.30", 5432, ts=300.0),
            conn("C1", "192.168.10.20", "192.168.10.30", 5432, ts=10.0),
        ])
        agg = load(tmp).aggregates[0]
        assert agg.first_seen == "2026-07-20T08:00:10+00:00"
        assert agg.last_seen == "2026-07-20T08:05:00+00:00"


def test_one_way_udp_kept_separate_from_success():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.20.15", "192.168.10.20", 162, proto="udp",
                 state="S0", resp_bytes=0, resp_pkts=0),
            conn("C2", "192.168.20.15", "192.168.10.20", 162, proto="udp",
                 state="S0", resp_bytes=0, resp_pkts=0, ts=20.0),
        ])
        agg = load(tmp).aggregates[0]
        assert agg.one_way_count == 2
        assert agg.successful_count == 0
        assert agg.outcome_label == OUTCOME_ONE_WAY


def test_distinct_originators_never_merged():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.10.20", "192.168.10.30", 5432),
            conn("C2", "192.168.20.15", "192.168.10.30", 5432),
        ])
        aggs = load(tmp).aggregates
        assert len(aggs) == 2
        assert {a.originator for a in aggs} == {"192.168.10.20", "192.168.20.15"}


def test_scanner_traffic_marked():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.1.50", "192.168.10.20", 443),
            conn("C2", "192.168.20.15", "192.168.10.20", 443),
        ])
        aggs = load(tmp, scanner_ip="192.168.1.50").aggregates
        marks = {a.originator: a.scanner_traffic for a in aggs}
        assert marks["192.168.1.50"] is True
        assert marks["192.168.20.15"] is False


def test_tunnel_parents_vlan_community_id_captured():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.10.20", "192.168.10.30", 5432,
                 **{"tunnel_parents": ["Ctun1"], "vlan": 42,
                    "community_id": "1:abc="}),
        ])
        agg = load(tmp).aggregates[0]
        assert agg.tunnel_parents == ["Ctun1"]
        assert agg.vlans == ["42"]
        assert agg.community_ids == ["1:abc="]


def test_sample_uid_cap_respected():
    cfg = zeek_config(max_sample_uids=2)
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn(f"C{i}", "192.168.10.20", "192.168.10.30", 5432, ts=float(i))
            for i in range(6)
        ])
        agg = load(tmp, cfg).aggregates[0]
        assert len(agg.sample_uids) == 2
        assert agg.connection_count == 6  # counting is not capped


def test_missed_bytes_degrade_aggregate_quality():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.10.20", "192.168.10.30", 5432, missed=512),
            conn("C2", "192.168.20.15", "192.168.10.30", 5432),
        ])
        aggs = {a.originator: a for a in load(tmp).aggregates}
        assert aggs["192.168.10.20"].sensor_quality == "degraded"
        assert aggs["192.168.20.15"].sensor_quality == "ok"


def test_ignored_sources_flagged_but_counted():
    cfg = zeek_config(ignored_sources=["192.168.99.0/24"])
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log", [
            conn("C1", "192.168.99.5", "192.168.10.30", 5432),
            conn("C2", "192.168.10.20", "192.168.10.30", 5432),
        ])
        zeek = load(tmp, cfg)
        assert zeek.metadata.record_counts["conn"] == 2  # still in stats
        flags = {a.originator: a.ignored_by_config for a in zeek.aggregates}
        assert flags["192.168.99.5"] is True
        assert flags["192.168.10.20"] is False


def test_sensor_health_unknown_without_capture_loss():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log",
                       [conn("C1", "192.168.10.20", "192.168.10.30", 5432)])
        health = load(tmp).health
        assert health.status == "unknown"  # never assumed healthy
        assert any("capture_loss" in n for n in health.notes)
        assert any("visible to its sensor" in n for n in health.notes)


def test_sensor_health_healthy_below_threshold():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log",
                       [conn("C1", "192.168.10.20", "192.168.10.30", 5432)])
        write_json_log(Path(tmp), "capture_loss.log",
                       [{"ts": 1.0, "peer": "zeek", "percent_lost": 0.2}])
        health = load(tmp).health
        assert health.status == "healthy"
        assert health.capture_loss_available
        assert health.max_capture_loss_percent == 0.2


def test_sensor_health_degraded_above_threshold():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log",
                       [conn("C1", "192.168.10.20", "192.168.10.30", 5432)])
        write_json_log(Path(tmp), "capture_loss.log",
                       [{"ts": 1.0, "peer": "zeek", "percent_lost": 3.7}])
        health = load(tmp).health
        assert health.status == "degraded"
        assert any("exceeds" in n for n in health.notes)


def test_sensor_health_degraded_by_missed_bytes_and_reporter_errors():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log",
                       [conn("C1", "192.168.10.20", "192.168.10.30", 5432,
                             missed=64)])
        write_json_log(Path(tmp), "capture_loss.log",
                       [{"ts": 1.0, "percent_lost": 0.0}])
        health = load(tmp).health
        assert health.status == "degraded"
        assert health.aggregates_with_missed_bytes == 1
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "conn.log",
                       [conn("C1", "192.168.10.20", "192.168.10.30", 5432)])
        write_json_log(Path(tmp), "capture_loss.log",
                       [{"ts": 1.0, "percent_lost": 0.0}])
        write_json_log(Path(tmp), "reporter.log",
                       [{"ts": 1.0, "level": "Reporter::ERROR",
                         "message": "packet source failure"}])
        health = load(tmp).health
        assert health.status == "degraded"
        assert health.reporter_errors == ["packet source failure"]


def test_sensor_health_unusable_without_conn():
    with tempfile.TemporaryDirectory() as tmp:
        write_json_log(Path(tmp), "capture_loss.log",
                       [{"ts": 1.0, "percent_lost": 0.0}])
        health = load(tmp).health
        assert health.status == "unusable"
