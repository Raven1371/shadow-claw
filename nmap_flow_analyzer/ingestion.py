"""Reusable bounded streaming adapters; independent of Claw CLI/report layers."""

from __future__ import annotations

import ipaddress
import json
import struct
from collections import OrderedDict
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from shadow_core.ingestion import (
    CONTRACT_VERSION,
    AdapterCheckpoint,
    AdapterContext,
    AdapterDiagnostic,
    AdapterStatus,
    AdapterSummary,
    DiagnosticSeverity,
    EvidenceSource,
    ProbeResult,
    RecordEnvelope,
    RecordLocation,
    deterministic_record_id,
)

from . import __version__

SUPPORTED_EVE_TYPES = frozenset({"alert", "flow", "netflow", "dns", "http", "tls", "ssh", "fileinfo", "anomaly", "stats"})
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _utc(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include an offset")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _depth(value: Any, level: int = 0) -> int:
    if isinstance(value, Mapping):
        return max([level, *(_depth(item, level + 1) for item in value.values())])
    if isinstance(value, list):
        return max([level, *(_depth(item, level + 1) for item in value)])
    return level


def _validate_json_shape(value: Any, context: AdapterContext) -> None:
    if _depth(value) > context.budget.max_json_depth:
        raise ValueError("maximum JSON depth exceeded")
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str) and len(current.encode("utf-8")) > context.budget.max_string_bytes:
            raise ValueError("maximum JSON string size exceeded")
        if isinstance(current, list):
            if len(current) > context.budget.max_array_items:
                raise ValueError("maximum JSON array size exceeded")
            stack.extend(current)
        elif isinstance(current, Mapping):
            stack.extend(current.values())


class SuricataEveAdapter:
    name = "suricata-eve"
    version = __version__
    capabilities = frozenset({"streaming", "checkpoint", "sensor-health", "partial"})

    def __init__(self) -> None:
        self._diagnostics: list[AdapterDiagnostic] = []
        self._summary: AdapterSummary | None = None

    @property
    def diagnostics(self) -> tuple[AdapterDiagnostic, ...]:
        return tuple(self._diagnostics)

    @property
    def summary(self) -> AdapterSummary | None:
        return self._summary

    def probe(self, source: EvidenceSource, context: AdapterContext) -> ProbeResult:
        source.validate()
        with source.path.open("rb") as handle:
            raw = handle.read(context.budget.max_probe_bytes)
        first = raw.splitlines()[0] if raw.splitlines() else b""
        matched = first.lstrip().startswith(b"{") and b'"event_type"' in first
        return ProbeResult(self.name, 90 if matched else 0, "application/x-ndjson", matched, len(raw), "bounded EVE JSON object probe" if matched else "no EVE object signature")

    def _diagnose(self, code: str, message: str, line: int, offset: int, fatal: bool, limit: str | None = None) -> None:
        if len(self._diagnostics) < 1_000:
            self._diagnostics.append(AdapterDiagnostic(code, message, DiagnosticSeverity.FATAL if fatal else DiagnosticSeverity.RECOVERABLE, RecordLocation(byte_offset=offset, line_number=line), limit))

    def records(self, source: EvidenceSource, context: AdapterContext) -> Iterator[RecordEnvelope]:
        raw_hash = source.sha256(context.budget)
        start_offset = 0
        start_line = 0
        if context.checkpoint:
            cp = context.checkpoint
            if cp.adapter_name != self.name or cp.adapter_version != self.version or cp.source_sha256 != raw_hash:
                raise ValueError("incompatible EVE checkpoint")
            start_offset, start_line = cp.byte_offset, cp.record_number
        count = unknown = 0
        status = AdapterStatus.COMPLETE
        last = context.checkpoint
        with source.path.open("rb") as handle:
            handle.seek(start_offset)
            line = start_line
            while True:
                context.cancellation.raise_if_cancelled()
                offset = handle.tell()
                raw = handle.readline(context.budget.max_line_bytes + 1)
                if not raw:
                    break
                line += 1
                if len(raw) > context.budget.max_line_bytes:
                    self._diagnose("line_too_large", "EVE line exceeds maximum", line, offset, context.strict, "max_line_bytes")
                    status = AdapterStatus.RESOURCE_LIMITED
                    if context.strict:
                        break
                    handle.readline()
                    continue
                final_partial = not raw.endswith((b"\n", b"\r")) and handle.tell() == source.path.stat().st_size
                try:
                    value = json.loads(raw.decode("utf-8", "strict"))
                    if not isinstance(value, dict):
                        raise ValueError("EVE record must be an object")
                    _validate_json_shape(value, context)
                    timestamp = _utc(str(value["timestamp"]))
                except (UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError) as exc:
                    fatal = context.strict or final_partial
                    self._diagnose("malformed_eve", str(exc), line, offset, fatal)
                    status = AdapterStatus.FATAL if fatal else AdapterStatus.PARTIAL
                    if fatal:
                        break
                    continue
                event_type = str(value.get("event_type", "unknown"))
                if event_type not in SUPPORTED_EVE_TYPES:
                    unknown += 1
                count += 1
                if count > context.budget.max_records:
                    status = AdapterStatus.RESOURCE_LIMITED
                    self._diagnose("record_limit", "EVE record limit reached", line, offset, False, "max_records")
                    break
                flow_id = value.get("flow_id") or value.get("tx_id") or value.get("event_id") or ""
                sensor = str(value.get("host") or value.get("sensor_id") or source.sensor_id or "unknown")
                record_id = deterministic_record_id(sensor, raw_hash, event_type, flow_id, line, offset)
                last = AdapterCheckpoint(CONTRACT_VERSION, self.name, self.version, raw_hash, handle.tell(), line, {"sensor_id": sensor})
                yield RecordEnvelope(record_id, f"suricata.{event_type}", timestamp, value, raw_hash, source.parent_evidence_id or raw_hash, source.parent_evidence_id, "suricata", self.name, self.version, "shadow-claw-suricata", self.version, sensor_id=sensor, location=RecordLocation(offset, line))
        if context.cancellation.cancelled:
            status = AdapterStatus.CANCELLED
        self._summary = AdapterSummary(status, raw_hash, count, len(self._diagnostics), 1, 1, unknown, source.path.stat().st_size, last)


@dataclass
class _Flow:
    packets: int = 0
    bytes: int = 0
    first: str | None = None
    last: str | None = None
    direction: str = "unknown"
    incomplete: bool = True


class BoundedFlowTable:
    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self._flows: OrderedDict[tuple[str, str, int, int, int], _Flow] = OrderedDict()
        self.evicted = 0

    def observe(self, key: tuple[str, str, int, int, int], length: int, timestamp: str, syn: bool = False) -> tuple[tuple[str, str, int, int, int], _Flow] | None:
        evicted = None
        if key not in self._flows and len(self._flows) >= self.maximum:
            evicted = self._flows.popitem(last=False)
            evicted[1].incomplete = True
            self.evicted += 1
        flow = self._flows.setdefault(key, _Flow(first=timestamp))
        flow.packets += 1
        flow.bytes += length
        flow.last = timestamp
        if syn:
            flow.direction = "source_to_destination"
        self._flows.move_to_end(key)
        return evicted

    def items(self) -> tuple[tuple[tuple[str, str, int, int, int], _Flow], ...]:
        return tuple(self._flows.items())


def _packet_data(frame: bytes, link_type: int) -> dict[str, Any]:
    result: dict[str, Any] = {"link_type": link_type, "protocols": []}
    if link_type != 1 or len(frame) < 14:
        return result
    result["protocols"].append("ethernet")
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if ethertype in {0x8100, 0x88A8} and len(frame) >= 18:
        result["protocols"].append("vlan")
        result["vlan_id"] = struct.unpack("!H", frame[14:16])[0] & 0x0FFF
        ethertype, offset = struct.unpack("!H", frame[16:18])[0], 18
    protocol = src_port = dst_port = 0
    if ethertype == 0x0806:
        result["protocols"].append("arp")
    elif ethertype == 0x0800 and len(frame) >= offset + 20:
        result["protocols"].append("ipv4")
        ihl = (frame[offset] & 0x0F) * 4
        protocol = frame[offset + 9]
        result["src_ip"] = str(ipaddress.ip_address(frame[offset + 12:offset + 16]))
        result["dst_ip"] = str(ipaddress.ip_address(frame[offset + 16:offset + 20]))
        offset += ihl
    elif ethertype == 0x86DD and len(frame) >= offset + 40:
        result["protocols"].append("ipv6")
        protocol = frame[offset + 6]
        result["src_ip"] = str(ipaddress.ip_address(frame[offset + 8:offset + 24]))
        result["dst_ip"] = str(ipaddress.ip_address(frame[offset + 24:offset + 40]))
        offset += 40
    if protocol in {6, 17} and len(frame) >= offset + 4:
        src_port, dst_port = struct.unpack("!HH", frame[offset:offset + 4])
        result.update({"src_port": src_port, "dst_port": dst_port, "ip_protocol": protocol})
        result["protocols"].append("tcp" if protocol == 6 else "udp")
        if 53 in {src_port, dst_port}:
            result["protocols"].append("dns")
        if protocol == 6 and len(frame) >= offset + 14:
            result["tcp_syn"] = bool(frame[offset + 13] & 0x02)
    elif protocol in {1, 58}:
        result["ip_protocol"] = protocol
        result["protocols"].append("icmp" if protocol == 1 else "icmpv6")
    return result


class PcapAdapter:
    name = "pcap"
    version = __version__
    capabilities = frozenset({"streaming", "checkpoint", "flows", "packet-metadata"})

    def __init__(self) -> None:
        self._diagnostics: list[AdapterDiagnostic] = []
        self._summary: AdapterSummary | None = None
        self.flows: BoundedFlowTable | None = None

    @property
    def diagnostics(self) -> tuple[AdapterDiagnostic, ...]: return tuple(self._diagnostics)
    @property
    def summary(self) -> AdapterSummary | None: return self._summary

    def probe(self, source: EvidenceSource, context: AdapterContext) -> ProbeResult:
        source.validate()
        with source.path.open("rb") as handle: raw = handle.read(min(24, context.budget.max_probe_bytes))
        matched = raw[:4] in PCAP_MAGICS
        return ProbeResult(self.name, 100 if matched else 0, "application/vnd.tcpdump.pcap", matched, len(raw), "PCAP magic" if matched else "magic mismatch")

    def records(self, source: EvidenceSource, context: AdapterContext) -> Iterator[RecordEnvelope]:
        raw_hash = source.sha256(context.budget)
        count = 0
        status = AdapterStatus.COMPLETE
        last = context.checkpoint
        self.flows = BoundedFlowTable(context.budget.max_active_flows)
        with source.path.open("rb") as handle:
            header = handle.read(24)
            if len(header) != 24 or header[:4] not in PCAP_MAGICS: raise ValueError("malformed PCAP global header")
            endian, resolution = PCAP_MAGICS[header[:4]]
            _, _, _, _, snaplen, link_type = struct.unpack(endian + "HHIIII", header[4:])
            if snaplen <= 0 or snaplen > context.budget.max_packet_bytes: raise ValueError("invalid PCAP snap length")
            if context.checkpoint:
                cp = context.checkpoint
                if cp.adapter_name != self.name or cp.adapter_version != self.version or cp.source_sha256 != raw_hash: raise ValueError("incompatible PCAP checkpoint")
                handle.seek(cp.byte_offset); count = cp.record_number
            while True:
                context.cancellation.raise_if_cancelled()
                offset = handle.tell(); packet_header = handle.read(16)
                if not packet_header: break
                if len(packet_header) != 16:
                    self._diagnostics.append(AdapterDiagnostic("truncated_header", "truncated PCAP packet header", DiagnosticSeverity.FATAL, RecordLocation(offset, packet_number=count + 1))); status = AdapterStatus.PARTIAL; break
                seconds, fraction, captured, original = struct.unpack(endian + "IIII", packet_header)
                if captured > snaplen or captured > context.budget.max_packet_bytes or captured > original:
                    self._diagnostics.append(AdapterDiagnostic("invalid_packet_length", "invalid captured packet length", DiagnosticSeverity.FATAL, RecordLocation(offset, packet_number=count + 1), "max_packet_bytes")); status = AdapterStatus.RESOURCE_LIMITED; break
                frame = handle.read(captured)
                if len(frame) != captured:
                    self._diagnostics.append(AdapterDiagnostic("truncated_packet", "truncated PCAP packet", DiagnosticSeverity.FATAL, RecordLocation(offset, packet_number=count + 1))); status = AdapterStatus.PARTIAL; break
                count += 1
                if count > context.budget.max_records: status = AdapterStatus.RESOURCE_LIMITED; break
                observed = datetime.fromtimestamp(seconds + fraction / resolution, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
                data = _packet_data(frame, link_type)
                data.update({"captured_length": captured, "original_length": original, "truncated": captured < original})
                key = (str(data.get("src_ip", "")), str(data.get("dst_ip", "")), int(data.get("src_port", 0)), int(data.get("dst_port", 0)), int(data.get("ip_protocol", 0)))
                if key[0] and key[1]:
                    evicted = self.flows.observe(key, original, observed, bool(data.get("tcp_syn")))
                    if evicted: self._diagnostics.append(AdapterDiagnostic("flow_evicted", "bounded flow table evicted incomplete flow", DiagnosticSeverity.RECOVERABLE))
                location = RecordLocation(offset, packet_number=count, interface_id=source.interface_id or "0:0")
                last = AdapterCheckpoint(CONTRACT_VERSION, self.name, self.version, raw_hash, handle.tell(), count, {"link_type": link_type})
                yield RecordEnvelope(deterministic_record_id(raw_hash, count, offset), "packet", observed, data, raw_hash, source.parent_evidence_id or raw_hash, source.parent_evidence_id, "native-pcap", self.name, self.version, "shadow-claw-packet", self.version, sensor_id=source.sensor_id, location=location)
        if context.cancellation.cancelled: status = AdapterStatus.CANCELLED
        self._summary = AdapterSummary(status, raw_hash, count, len(self._diagnostics), 1, 1, bytes_processed=source.path.stat().st_size, last_checkpoint=last)


class PcapngAdapter(PcapAdapter):
    name = "pcapng"

    def probe(self, source: EvidenceSource, context: AdapterContext) -> ProbeResult:
        source.validate()
        with source.path.open("rb") as handle: raw = handle.read(min(12, context.budget.max_probe_bytes))
        matched = raw[:4] == PCAPNG_MAGIC and raw[8:12] in {b"\x1a\x2b\x3c\x4d", b"\x4d\x3c\x2b\x1a"}
        return ProbeResult(self.name, 100 if matched else 0, "application/x-pcapng", matched, len(raw), "PCAPNG section magic" if matched else "magic mismatch")

    def records(self, source: EvidenceSource, context: AdapterContext) -> Iterator[RecordEnvelope]:
        raw_hash = source.sha256(context.budget); count = block_index = section = 0
        status = AdapterStatus.COMPLETE; last = context.checkpoint; endian = "<"; interfaces: dict[int, tuple[int, float]] = {}
        with source.path.open("rb") as handle:
            if context.checkpoint:
                cp=context.checkpoint
                if cp.adapter_name != self.name or cp.adapter_version != self.version or cp.source_sha256 != raw_hash: raise ValueError("incompatible PCAPNG checkpoint")
                handle.seek(cp.byte_offset); count=cp.record_number; section=int(cp.state.get("section", 0)); endian=str(cp.state.get("endian", "<"))
            while True:
                context.cancellation.raise_if_cancelled(); offset=handle.tell(); prefix=handle.read(8)
                if not prefix: break
                if len(prefix)!=8: status=AdapterStatus.PARTIAL; self._diagnostics.append(AdapterDiagnostic("truncated_block", "truncated PCAPNG block header", DiagnosticSeverity.FATAL, RecordLocation(offset, block_index=block_index))); break
                raw_type=prefix[:4]
                if raw_type == PCAPNG_MAGIC:
                    bom=handle.read(4)
                    if bom==b"\x4d\x3c\x2b\x1a": endian="<"
                    elif bom==b"\x1a\x2b\x3c\x4d": endian=">"
                    else: raise ValueError("invalid PCAPNG byte-order magic")
                    total=struct.unpack(endian+"I",prefix[4:])[0]
                    body_start=bom; section += 1; interfaces={}
                else:
                    total=struct.unpack(endian+"I",prefix[4:])[0]; body_start=b""
                if total < 12 or total % 4 or total > context.budget.max_packet_bytes + 4096: raise ValueError("invalid PCAPNG block length")
                remainder=handle.read(total-8-len(body_start)); block=body_start+remainder
                if len(block)!=total-8 or struct.unpack(endian+"I",block[-4:])[0]!=total: raise ValueError("PCAPNG block length mismatch")
                body=block[:-4]; block_type=struct.unpack(endian+"I",raw_type)[0]; block_index+=1
                if block_type==1 and len(body)>=8:
                    link,snap=struct.unpack(endian+"HxxI",body[:8]); interfaces[len(interfaces)]=(link,1_000_000.0 if snap else 1_000_000.0)
                elif block_type==6 and len(body)>=20:
                    interface,high,low,captured,original=struct.unpack(endian+"IIIII",body[:20])
                    if interface not in interfaces: raise ValueError("invalid PCAPNG interface reference")
                    if captured>context.budget.max_packet_bytes or 20+captured>len(body): raise ValueError("invalid PCAPNG captured length")
                    frame=body[20:20+captured]; link,resolution=interfaces[interface]; units=(high<<32)|low
                    observed=datetime.fromtimestamp(units/resolution,timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")
                    data=_packet_data(frame,link); data.update({"captured_length":captured,"original_length":original,"section_index":section-1,"interface_index":interface,"timestamp_units":units,"timestamp_resolution":resolution,"truncated":captured<original})
                    count+=1; location=RecordLocation(offset,packet_number=count,block_index=block_index,interface_id=f"{section-1}:{interface}")
                    last=AdapterCheckpoint(CONTRACT_VERSION,self.name,self.version,raw_hash,handle.tell(),count,{"section":section,"endian":endian})
                    yield RecordEnvelope(deterministic_record_id(raw_hash,section,block_index,interface,count),"packet",observed,data,raw_hash,source.parent_evidence_id or raw_hash,source.parent_evidence_id,"native-pcapng",self.name,self.version,"shadow-claw-packet",self.version,sensor_id=source.sensor_id,location=location)
                elif block_type not in {0x0A0D0D0A,1,3,4,5}:
                    self._diagnostics.append(AdapterDiagnostic("unknown_block",f"safely skipped PCAPNG block {block_type:#x}",DiagnosticSeverity.RECOVERABLE,RecordLocation(offset,block_index=block_index)))
        if context.cancellation.cancelled: status=AdapterStatus.CANCELLED
        self._summary=AdapterSummary(status,raw_hash,count,len(self._diagnostics),1,1,bytes_processed=source.path.stat().st_size,last_checkpoint=last)


def parse_suricata_rules(path: Path, maximum_line_bytes: int = 64 * 1024) -> Iterator[dict[str, Any]]:
    """Parse bounded metadata only; never executes or fully interprets rules."""
    raw_hash = EvidenceSource(path).sha256(AdapterContext().budget)
    with path.open("r", encoding="utf-8", errors="strict") as handle:
        for line_number, line in enumerate(handle, 1):
            if len(line.encode()) > maximum_line_bytes: raise ValueError("Suricata rule line exceeds limit")
            stripped=line.strip()
            if not stripped or stripped.startswith("#"): continue
            options=stripped.rsplit("(",1)[-1].removesuffix(")")
            values: dict[str, Any]={"line_number":line_number,"rule_source_sha256":raw_hash}
            for item in options.split(";"):
                key,sep,value=item.strip().partition(":")
                if sep and key in {"sid","rev","msg","classtype","priority","metadata","reference"}: values[key]=value.strip().strip('"')
            yield values


__all__ = ["BoundedFlowTable", "PcapAdapter", "PcapngAdapter", "SUPPORTED_EVE_TYPES", "SuricataEveAdapter", "parse_suricata_rules"]
