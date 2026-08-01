"""Shared fixtures and helpers for the Zeek test suite (v1.2.0)."""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nmap_flow_analyzer.config import AnalyzerConfig  # noqa: E402
from nmap_flow_analyzer.flow_analysis import (  # noqa: E402
    AnalysisOptions,
    build_flows,
    enrich_hosts,
    sort_and_assign_flow_ids,
)
from nmap_flow_analyzer.risk_analysis import build_service_records  # noqa: E402
from nmap_flow_analyzer.zeek_aggregation import load_zeek  # noqa: E402
from nmap_flow_analyzer.zeek_correlation import correlate_zeek  # noqa: E402
from tests.fixtures import MULTI_HOST_XML, base_config, parse_xml  # noqa: E402

BASE_TS = 1784534400.0  # 2026-07-20T08:00:00+00:00


def conn(uid: str, oh: str, rh: str, rp: int, proto: str = "tcp",
         state: str = "SF", service: str = "", op: int = 40000,
         ts: float = 10.0, orig_bytes: int = 500, resp_bytes: int = 800,
         orig_pkts: int = 8, resp_pkts: int = 7, missed: int = 0,
         duration: float = 1.0, **extra) -> Dict[str, object]:
    record = {
        "ts": BASE_TS + ts, "uid": uid, "id.orig_h": oh, "id.orig_p": op,
        "id.resp_h": rh, "id.resp_p": rp, "proto": proto, "service": service,
        "duration": duration, "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes, "conn_state": state, "missed_bytes": missed,
        "orig_pkts": orig_pkts, "orig_ip_bytes": orig_bytes + 400,
        "resp_pkts": resp_pkts, "resp_ip_bytes": resp_bytes + 400,
        "tunnel_parents": [],
    }
    record.update(extra)
    return record


def write_json_log(directory: Path, name: str, records: List[Dict],
                   gz: bool = False) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    text = "\n".join(json.dumps(r) for r in records) + ("\n" if records else "")
    path = directory / name
    if gz:
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


CONN_TSV_FIELDS = [
    ("ts", "time"), ("uid", "string"), ("id.orig_h", "addr"),
    ("id.orig_p", "port"), ("id.resp_h", "addr"), ("id.resp_p", "port"),
    ("proto", "enum"), ("service", "string"), ("duration", "interval"),
    ("orig_bytes", "count"), ("resp_bytes", "count"), ("conn_state", "string"),
    ("missed_bytes", "count"), ("orig_pkts", "count"),
    ("orig_ip_bytes", "count"), ("resp_pkts", "count"),
    ("resp_ip_bytes", "count"), ("tunnel_parents", "set[string]"),
]


def write_tsv_conn(directory: Path, records: List[Dict], name: str = "conn.log",
                   gz: bool = False) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    fields = [f for f, _ in CONN_TSV_FIELDS]
    types = [t for _, t in CONN_TSV_FIELDS]
    lines = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#path\tconn",
        "#fields\t" + "\t".join(fields),
        "#types\t" + "\t".join(types),
    ]
    for record in records:
        row = []
        for field in fields:
            value = record.get(field)
            if value is None:
                row.append("-")
            elif isinstance(value, list):
                row.append(",".join(str(v) for v in value) if value else "(empty)")
            else:
                row.append(str(value))
        lines.append("\t".join(row))
    text = "\n".join(lines) + "\n"
    path = directory / name
    if gz:
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def zeek_config(**overrides) -> AnalyzerConfig:
    cfg = base_config()
    cfg.zeek.monitored_networks = ["192.168.0.0/16"]
    for key, value in overrides.items():
        setattr(cfg.zeek, key, value)
    return cfg


def load(dirs, cfg: Optional[AnalyzerConfig] = None, fmt: str = "auto",
         scanner_ip: str = ""):
    cfg = cfg or zeek_config()
    if isinstance(dirs, (str, Path)):
        dirs = [dirs]
    return load_zeek([Path(d) for d in dirs], fmt, cfg,
                     scanner_ip=scanner_ip or cfg.scanner_ip)


def correlated(zeek_dir: Path, cfg: Optional[AnalyzerConfig] = None,
               xml: str = MULTI_HOST_XML, options: Optional[AnalysisOptions] = None):
    """Full in-process pipeline: parse Nmap, build flows, correlate Zeek."""
    cfg = cfg or zeek_config()
    options = options or AnalysisOptions()
    metadata, hosts = parse_xml(xml)
    enrich_hosts(hosts, cfg)
    records = build_service_records(hosts, cfg)
    result = build_flows(hosts, records, cfg, options)
    zeek = load([zeek_dir], cfg)
    corr = correlate_zeek(hosts, records, result.flows, cfg, options, zeek)
    corr.flows = sort_and_assign_flow_ids(corr.flows)
    return {
        "metadata": metadata, "hosts": hosts, "records": records,
        "flows": corr.flows, "corr": corr, "zeek": zeek, "config": cfg,
        "options": options,
    }
