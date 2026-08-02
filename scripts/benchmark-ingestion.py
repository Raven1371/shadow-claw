"""Generate bounded redistributable fixtures and record adapter baselines."""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import struct
import tempfile
import time
import tracemalloc
from pathlib import Path

from shadow_core.ingestion import AdapterContext, EvidenceSource, ResourceBudget

from nmap_flow_analyzer import __version__
from nmap_flow_analyzer.ingestion import PcapAdapter, PcapngAdapter, SuricataEveAdapter


def packet() -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    udp = struct.pack("!HHHH", 53000, 53, 8, 0)
    ip = bytes([0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0])
    return ethernet + ip + socket.inet_aton("192.0.2.10") + socket.inet_aton("198.51.100.53") + udp


def pcap(path: Path, count: int) -> None:
    frame = packet()
    with path.open("wb") as handle:
        handle.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        for index in range(count):
            handle.write(struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame)))
            handle.write(frame)


def eve(path: Path, count: int) -> None:
    event_types = ("flow", "alert", "dns", "http", "tls", "ssh", "fileinfo", "anomaly", "stats")
    with path.open("wb") as handle:
        for index in range(count):
            event_type = event_types[index % len(event_types)]
            value = {"timestamp": "2026-01-01T00:00:00Z", "event_type": event_type, "flow_id": index, "host": "synthetic-benchmark"}
            handle.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")


def _block(kind: int, body: bytes) -> bytes:
    padding = b"\0" * ((-len(body)) % 4)
    total = 12 + len(body) + len(padding)
    return struct.pack("<II", kind, total) + body + padding + struct.pack("<I", total)


def pcapng(path: Path, count: int) -> None:
    frame = packet()
    with path.open("wb") as handle:
        handle.write(_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        handle.write(_block(1, struct.pack("<HxxI", 1, 65535)))
        for index in range(count):
            timestamp = 1_700_000_000_000_000 + index
            body = struct.pack("<IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, len(frame), len(frame)) + frame
            handle.write(_block(6, body))
            if index and index % 10_000 == 0:
                handle.write(_block(0xBAD, b"synthetic-custom-block"))


def run(adapter: object, path: Path) -> dict[str, object]:
    tracemalloc.start()
    cpu_started = time.process_time()
    started = time.perf_counter()
    count = sum(1 for _ in adapter.records(EvidenceSource(path), AdapterContext(ResourceBudget(max_records=1_000_000))))  # type: ignore[attr-defined]
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"bytes": path.stat().st_size, "records": count, "seconds": elapsed, "cpu_seconds": time.process_time() - cpu_started, "bytes_per_second": path.stat().st_size / elapsed, "records_per_second": count / elapsed, "peak_traced_bytes": peak}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--records", type=int, default=10_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.records <= 1_000_000:
        parser.error("--records must be between 1 and 1000000")
    args.work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.work_dir) as temporary:
        root = Path(temporary)
        eve_path = root / "eve"
        pcap_path = root / "pcap"
        pcapng_path = root / "pcapng"
        eve(eve_path, args.records)
        pcap(pcap_path, args.records)
        pcapng(pcapng_path, args.records)
        result = {
            "host": platform.node() or "undisclosed", "operating_system": platform.platform(),
            "python": platform.python_version(), "parser_version": __version__, "dataset_seed": 1371,
            "dataset_records": args.records, "pid": os.getpid(),
            "suricata_eve": run(SuricataEveAdapter(), eve_path),
            "classic_pcap": run(PcapAdapter(), pcap_path),
            "pcapng": run(PcapngAdapter(), pcapng_path),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
