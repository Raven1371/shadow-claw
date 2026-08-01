"""Parser tests: hosts, ports, states, IPv6, duplicates, invalid/empty XML."""

from pathlib import Path

import pytest

from nmap_flow_analyzer.parser import ParserError, parse_nmap_xml
from tests.fixtures import (
    DUPLICATE_PORT_XML,
    EMPTY_SCAN_XML,
    INVALID_XML,
    IPV6_HOST_XML,
    MISSING_SERVICE_XML,
    MULTI_HOST_XML,
    NO_IP_HOST_XML,
    SCRIPT_XML,
    SINGLE_HOST_XML,
    SPECIAL_CHARS_XML,
    parse_xml,
)


def test_single_host_single_open_tcp_port():
    metadata, hosts = parse_xml(SINGLE_HOST_XML)
    assert metadata.nmap_version == "7.95"
    assert metadata.command_line.startswith("nmap -sS -sV")
    assert metadata.start_time == "Mon Jul  1 10:00:00 2026"
    assert metadata.end_time == "Mon Jul  1 10:01:40 2026"
    assert metadata.scan_types == ["syn"]
    assert len(hosts) == 1
    host = hosts[0]
    assert host.ipv4 == "192.168.10.20"
    assert host.mac == "AA:BB:CC:DD:EE:FF"
    assert host.mac_vendor == "Dell Inc."
    # multiple hostnames retained
    assert host.hostnames == ["web01.example.local", "intranet.example.local"]
    assert len(host.ports) == 1
    port = host.ports[0]
    assert (port.protocol, port.port, port.state, port.reason) == (
        "tcp", 443, "open", "syn-ack",
    )
    assert port.service_name == "http"
    assert port.tunnel == "ssl"
    assert port.cpes == ["cpe:/a:nginx:nginx:1.24.0"]
    # OS match retained
    assert host.os_matches[0].name == "Linux 5.X"
    assert host.os_matches[0].accuracy == 95


def test_multiple_hosts_tcp_udp_and_states():
    _, hosts = parse_xml(MULTI_HOST_XML)
    assert [h.ipv4 for h in hosts] == ["192.168.10.20", "192.168.10.30"]
    web, db = hosts
    states = {(p.protocol, p.port): p.state for p in web.ports}
    assert states[("tcp", 22)] == "open"
    assert states[("tcp", 3306)] == "closed"
    assert states[("tcp", 8443)] == "filtered"
    db_states = {(p.protocol, p.port): p.state for p in db.ports}
    assert db_states[("udp", 161)] == "open|filtered"
    assert db_states[("tcp", 5432)] == "open"


def test_ipv6_host():
    _, hosts = parse_xml(IPV6_HOST_XML)
    assert hosts[0].ipv6 == "2001:db8::20"
    assert hosts[0].ip_version == 6
    assert hosts[0].ports[0].state == "open"


def test_missing_service_name():
    _, hosts = parse_xml(MISSING_SERVICE_XML)
    port = hosts[0].ports[0]
    assert port.port == 4444 and port.state == "open"
    assert port.service_name == ""


def test_duplicate_ports_are_merged_keeping_richest():
    _, hosts = parse_xml(DUPLICATE_PORT_XML)
    ports = hosts[0].ports
    assert len(ports) == 1
    assert ports[0].service_name == "ssh"
    assert [s.script_id for s in ports[0].scripts] == ["ssh-hostkey"]


def test_nse_script_output_parsed():
    _, hosts = parse_xml(SCRIPT_XML)
    host = hosts[0]
    port_scripts = {s.script_id for s in host.ports[0].scripts}
    assert {"smb-protocols", "smb-vuln-ms17-010"} <= port_scripts
    assert host.host_scripts[0].script_id == "smb-os-discovery"


def test_special_characters_are_decoded():
    _, hosts = parse_xml(SPECIAL_CHARS_XML)
    assert hosts[0].ports[0].product == "Caf\u00e9 & Server <beta>"


def test_empty_scan_returns_no_hosts():
    metadata, hosts = parse_xml(EMPTY_SCAN_XML)
    assert hosts == []
    assert metadata.summary == "scan finished"


def test_host_without_ip_is_skipped():
    _, hosts = parse_xml(NO_IP_HOST_XML)
    assert hosts == []


def test_invalid_xml_raises_parser_error():
    with pytest.raises(ParserError):
        parse_xml(INVALID_XML)


def test_missing_file_raises_parser_error():
    with pytest.raises(ParserError):
        parse_nmap_xml(Path("/nonexistent/does-not-exist.xml"))
