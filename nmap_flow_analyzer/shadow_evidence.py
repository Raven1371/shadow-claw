"""Shadow Core-backed Shadow Evidence import and export adapters."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from shadow_core.evidence import export_package, import_package, validate_package
from shadow_core.hashing import sha256_bytes
from shadow_core.identifiers import stable_identifier
from shadow_core.provenance import validate_provenance
from shadow_core.serialization import canonical_json_bytes, canonical_jsonl_bytes

from . import __version__

_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _load(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _raw_payload(input_path: Path, zeek_dirs: Iterable[Path]) -> tuple[dict[str, bytes], list[dict[str, Any]]]:
    payload: dict[str, bytes] = {}
    provenance: list[dict[str, Any]] = []
    inputs = [("evidence/other/nmap.xml", input_path, "nmap")]
    for directory_index, directory in enumerate(zeek_dirs):
        for path in sorted(directory.iterdir()):
            if path.is_file() and not path.is_symlink():
                inputs.append((f"evidence/zeek/{directory_index}/{path.name}", path, "zeek"))
    for member, path, perspective in inputs:
        data = path.read_bytes()
        digest = sha256_bytes(data)
        source = stable_identifier("source", {"sha256": digest})
        payload[member] = data
        provenance.append({
            "id": stable_identifier("provenance", {"source": source, "perspective": perspective, "path": member}),
            "independent_source_id": source,
            "analysis_perspective": perspective,
            "observation_type": "direct",
            "raw_sha256": digest,
            "parent_evidence_id": None,
            "parser_name": "nmap-flow-analyzer",
            "parser_version": __version__,
        })
    return payload, provenance


def _events(normalized: Mapping[str, Any], provenance: list[dict[str, Any]], timestamp: str) -> list[dict[str, Any]]:
    nmap_source = provenance[0]["independent_source_id"]
    events: list[dict[str, Any]] = []
    sections = (
        ("service_inventory", "service_observation"),
        ("flows", "network_activity"),
        ("correlation_findings", "security_finding"),
    )
    for section, category in sections:
        for index, record in enumerate(normalized.get(section, [])):
            record_id = record.get("id") or record.get("flow_id") or stable_identifier(section, record)
            events.append({
                "id": stable_identifier("event", {"section": section, "record_id": record_id, "index": index}),
                "category": category,
                "time": timestamp,
                "message": f"Shadow Claw {section} record",
                "data": record,
                "shadow": {
                    "source_event_id": str(record_id),
                    "raw_sha256": provenance[0]["raw_sha256"],
                    "analysis_perspective": "nmap-flow-analyzer",
                    "independent_source_id": nmap_source,
                    "parser_name": "nmap-flow-analyzer",
                    "parser_version": __version__,
                    "normalizer_name": "shadow-claw",
                    "normalizer_version": __version__,
                },
            })
    return events


def export_shadow_evidence(
    staging: Path,
    input_path: Path,
    zeek_dirs: Iterable[Path],
    case_id: str,
    case_title: str,
) -> Path:
    """Add a deterministic Core-validated evidence package to staged outputs."""
    if not _CASE_ID.fullmatch(case_id):
        raise ValueError("--shadow-case-id must contain only letters, numbers, dot, underscore, or hyphen")
    normalized = _load(staging / "normalized_data.json", {})
    created_at = _utc_now()
    raw_payload, provenance = _raw_payload(input_path, zeek_dirs)
    events = _events(normalized, provenance, created_at)
    lineage = validate_provenance(provenance)
    assets = normalized.get("hosts", [])
    services = normalized.get("service_inventory", [])
    flows = normalized.get("flows", [])
    communications = normalized.get("zeek_flow_aggregates", [])
    findings = normalized.get("correlation_findings", [])
    payload = {
        **raw_payload,
        "case.json": canonical_json_bytes({"id": case_id, "title": case_title, "created_at": created_at, "status": "Open"}),
        "normalized/events.jsonl": canonical_jsonl_bytes(events),
        "assets/entities.json": canonical_json_bytes(assets),
        "network/services.json": canonical_json_bytes(services),
        "network/flows.json": canonical_json_bytes(flows),
        "network/communications.json": canonical_json_bytes(communications),
        "alerts/alerts.json": canonical_json_bytes([]),
        "detections/rules.json": canonical_json_bytes([]),
        "detections/matches.json": canonical_json_bytes([]),
        "timeline/timeline.json": canonical_json_bytes(findings),
        "provenance/provenance.json": canonical_json_bytes(provenance),
        "metadata/export.json": canonical_json_bytes({"exported_at": created_at, "producer": "shadow-claw", "producer_version": __version__}),
    }
    package_id = stable_identifier("package", {"case_id": case_id, "files": {name: sha256_bytes(data) for name, data in sorted(payload.items())}})
    fields = {
        "package_id": package_id,
        "case_id": case_id,
        "created_at": created_at,
        "created_by": "shadow-claw",
        "producer": "shadow-claw",
        "producer_version": __version__,
        "minimum_reader_version": "0.1.0.dev0",
        "content_types": sorted({name.split("/", 1)[0] for name in payload}),
        **lineage,
        "event_count": len(events),
        "asset_count": len(assets),
        "flow_count": len(flows),
        "service_count": len(services),
        "communication_count": len(communications),
        "alert_count": 0,
    }
    output = staging / f"{case_id}.shadowevidence.zip"
    export_package(output, fields, payload)
    validation = validate_package(output)
    if not validation.valid:
        raise ValueError("Shadow Core rejected exported package: " + "; ".join(issue.message for issue in validation.issues))
    return output


def verify_shadow_evidence(path: Path) -> dict[str, object]:
    return validate_package(path).as_dict()


def import_shadow_evidence(path: Path, destination: Path) -> Path:
    return import_package(path, destination)

