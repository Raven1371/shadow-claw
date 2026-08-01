"""Tests for service normalization and mismatch detection."""

from nmap_flow_analyzer.models import PortRecord
from nmap_flow_analyzer.normalization import (
    normalize_detected,
    normalize_port,
    normalize_service,
)


def test_probed_detection_wins_over_registry():
    rec = PortRecord(
        protocol="tcp",
        port=8080,
        state="open",
        service_name="http",
        detection_method="probed",
    )
    norm = normalize_service(rec)
    assert norm.final == "HTTP"
    assert not norm.mismatch


def test_registry_fallback_when_not_probed():
    rec = PortRecord(
        protocol="tcp",
        port=443,
        state="open",
        service_name="https",
        detection_method="table",
    )
    norm = normalize_service(rec)
    assert norm.final == "HTTPS"
    assert not norm.mismatch
    assert "port table" in norm.note.lower()


def test_ssl_tunnel_upgrades_http_to_https():
    rec = PortRecord(
        protocol="tcp",
        port=443,
        state="open",
        service_name="http",
        tunnel="ssl",
        detection_method="probed",
    )
    norm = normalize_service(rec)
    assert norm.final == "HTTPS"
    assert not norm.mismatch


def test_mismatch_flagged_for_probed_unexpected_service():
    rec = PortRecord(
        protocol="tcp",
        port=443,
        state="open",
        service_name="ssh",
        detection_method="probed",
    )
    norm = normalize_service(rec)
    assert norm.mismatch
    assert norm.final == "SSH"
    assert "443" in norm.note or "mismatch" in norm.note.lower() or norm.note


def test_no_mismatch_without_probing():
    # A table-derived name that differs must not be treated as confirmed drift.
    rec = PortRecord(
        protocol="tcp",
        port=443,
        state="open",
        service_name="ssh",
        detection_method="table",
    )
    norm = normalize_service(rec)
    assert not norm.mismatch
    assert norm.final == "HTTPS"


def test_unidentified_names_ignored():
    assert normalize_detected("unknown") == ""
    assert normalize_detected("tcpwrapped") == ""
    rec = PortRecord(protocol="tcp", port=9999, state="open", service_name="unknown")
    norm = normalize_service(rec)
    assert norm.final  # never empty in reports
    assert not norm.mismatch


def test_unregistered_port_has_no_expected_service():
    assert normalize_port("tcp", 9999) == ""
    assert normalize_port("udp", 161) != ""
