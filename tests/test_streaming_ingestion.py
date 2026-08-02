import json
import socket
import struct
from pathlib import Path

import pytest

from shadow_core.ingestion import AdapterContext, EvidenceSource, ResourceBudget

from nmap_flow_analyzer.ingestion import (
    PcapAdapter,
    PcapngAdapter,
    SuricataEveAdapter,
    parse_suricata_rules,
)


def ethernet_udp_dns() -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    udp = struct.pack("!HHHH", 53000, 53, 8, 0)
    ip = bytes([0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0]) + socket.inet_aton("192.0.2.10") + socket.inet_aton("198.51.100.53")
    return ethernet + ip + udp


def write_pcap(path: Path, endian: str = "<", nanos: bool = False) -> bytes:
    frame = ethernet_udp_dns()
    magic = {("<", False): b"\xd4\xc3\xb2\xa1", (">", False): b"\xa1\xb2\xc3\xd4", ("<", True): b"\x4d\x3c\xb2\xa1", (">", True): b"\xa1\xb2\x3c\x4d"}[(endian, nanos)]
    raw = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, 1)
    raw += struct.pack(endian + "IIII", 1_700_000_000, 123_456_000 if nanos else 123_456, len(frame), len(frame)) + frame
    path.write_bytes(raw)
    return frame


def block(kind: int, body: bytes, endian: str = "<") -> bytes:
    padding = b"\0" * ((-len(body)) % 4)
    total = 12 + len(body) + len(padding)
    return struct.pack(endian + "II", kind, total) + body + padding + struct.pack(endian + "I", total)


def write_pcapng(path: Path) -> None:
    frame = ethernet_udp_dns()
    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(1, struct.pack("<HxxI", 1, 65535))
    units = 1_700_000_000_123_456
    packet = block(6, struct.pack("<IIIII", 0, units >> 32, units & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    unknown = block(0xBAD, b"safe")
    path.write_bytes(section + interface + packet + unknown)


def test_suricata_streaming_health_unknown_and_checkpoint(tmp_path: Path) -> None:
    path = tmp_path / "eve.data"
    rows = [
        {"timestamp": "2026-01-01T00:00:00-05:00", "event_type": "alert", "flow_id": 7, "host": "sensor-a", "alert": {"signature_id": 1}},
        {"timestamp": "2026-01-01T05:00:01Z", "event_type": "stats", "host": "sensor-a", "stats": {"capture": {"kernel_drops": 2}}},
        {"timestamp": "2026-01-01T05:00:02Z", "event_type": "future", "host": "sensor-a"},
    ]
    path.write_bytes(b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in rows))
    adapter = SuricataEveAdapter()
    records = list(adapter.records(EvidenceSource(path), AdapterContext()))
    assert [record.record_type for record in records] == ["suricata.alert", "suricata.stats", "suricata.future"]
    assert records[0].observed_at == "2026-01-01T05:00:00.000000Z"
    assert adapter.summary and adapter.summary.unknown_record_count == 1
    checkpoint = adapter.summary.last_checkpoint
    assert checkpoint and list(SuricataEveAdapter().records(EvidenceSource(path), AdapterContext(checkpoint=checkpoint))) == []


def test_suricata_partial_and_hostile_limits(tmp_path: Path) -> None:
    path = tmp_path / "eve"
    path.write_bytes(b'{"timestamp":"2026-01-01T00:00:00Z","event_type":"flow"}\n{bad}\n')
    adapter = SuricataEveAdapter()
    assert len(list(adapter.records(EvidenceSource(path), AdapterContext(strict=False)))) == 1
    assert adapter.summary and adapter.summary.status == "partial"
    limited = SuricataEveAdapter()
    list(limited.records(EvidenceSource(path), AdapterContext(ResourceBudget(max_line_bytes=8), strict=True)))
    assert limited.summary and limited.summary.status == "resource_limited"


@pytest.mark.parametrize(("endian", "nanos"), [("<", False), (">", False), ("<", True), (">", True)])
def test_classic_pcap_variants_stream_packet_metadata(tmp_path: Path, endian: str, nanos: bool) -> None:
    path = tmp_path / "capture.dat"
    write_pcap(path, endian, nanos)
    adapter = PcapAdapter()
    assert adapter.probe(EvidenceSource(path), AdapterContext()).magic_matched
    records = list(adapter.records(EvidenceSource(path), AdapterContext()))
    assert len(records) == 1
    assert records[0].data["protocols"] == ["ethernet", "ipv4", "udp", "dns"]
    assert records[0].location.packet_number == 1
    assert adapter.flows and len(adapter.flows.items()) == 1


def test_pcap_rejects_invalid_lengths(tmp_path: Path) -> None:
    path = tmp_path / "bad"
    write_pcap(path)
    raw = bytearray(path.read_bytes())
    raw[32:36] = struct.pack("<I", 999_999)
    path.write_bytes(raw)
    adapter = PcapAdapter()
    assert list(adapter.records(EvidenceSource(path), AdapterContext())) == []
    assert adapter.summary and adapter.summary.status == "resource_limited"


def test_pcapng_interfaces_timestamps_and_unknown_blocks(tmp_path: Path) -> None:
    path = tmp_path / "capture.bin"
    write_pcapng(path)
    adapter = PcapngAdapter()
    assert adapter.probe(EvidenceSource(path), AdapterContext()).magic_matched
    records = list(adapter.records(EvidenceSource(path), AdapterContext()))
    assert len(records) == 1
    assert records[0].location.interface_id == "0:0"
    assert records[0].data["timestamp_units"] == 1_700_000_000_123_456
    assert any(item.code == "unknown_block" for item in adapter.diagnostics)


def test_bounded_suricata_rule_metadata(tmp_path: Path) -> None:
    path = tmp_path / "rules"
    path.write_text('alert tcp any any -> any any (msg:"Example"; sid:42; rev:3; classtype:test; reference:url,example.invalid;)\n', encoding="utf-8")
    parsed = list(parse_suricata_rules(path))
    assert parsed[0]["sid"] == "42"
    assert parsed[0]["rev"] == "3"
    assert "rule_source_sha256" in parsed[0]
