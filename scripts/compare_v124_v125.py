#!/usr/bin/env python3
"""Compare v1.2.4 and v1.2.5 analyzer outputs without hiding semantics."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


VOLATILE_KEYS = {"run_id", "started_at", "completed_at", "generated_at"}
VERSION_RE = re.compile(r"\b1\.2\.[45]\b")


def normalize_value(value: Any, key: Optional[str] = None) -> Any:
    """Normalize only approved metadata differences, never security fields."""
    if isinstance(value, dict):
        return {
            item_key: normalize_value(item_value, item_key)
            for item_key, item_value in sorted(value.items())
            if item_key not in VOLATILE_KEYS
        }
    if isinstance(value, list):
        if key == "generated_files":
            return [
                {"path": item["path"]} if isinstance(item, dict) else item
                for item in value
            ]
        if key == "input_directories":
            return [Path(str(item)).name for item in value]
        return [normalize_value(item) for item in value]
    if isinstance(value, str):
        if key == "input_file":
            value = Path(value).name
        return VERSION_RE.sub("<VERSION>", value)
    return value


def _json(path: Path) -> Any:
    return normalize_value(json.loads(path.read_text(encoding="utf-8")))


def _csv(path: Path) -> List[List[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [[VERSION_RE.sub("<VERSION>", cell) for cell in row]
                for row in csv.reader(handle)]


def _text(path: Path) -> str:
    return VERSION_RE.sub("<VERSION>", path.read_text(encoding="utf-8"))


def _xlsx(path: Path) -> Dict[str, List[List[Any]]]:
    try:
        import openpyxl
    except ImportError as exc:  # pragma: no cover - dependency is mandatory in CI
        raise RuntimeError("openpyxl is required for compatibility comparison") from exc
    workbook = openpyxl.load_workbook(path, read_only=True, data_only=False)
    try:
        result = {}
        for sheet in workbook.worksheets:
            rows = [
                [normalize_value(cell.value) for cell in row]
                for row in sheet.iter_rows()
            ]
            for row in rows:
                if row and row[0] in {"Generated", "Run ID"} and len(row) > 1:
                    row[1] = f"<{str(row[0]).upper().replace(' ', '_')}>"
            result[sheet.title] = rows
        return result
    finally:
        workbook.close()


def compare_scenario(name: str, baseline: Path, candidate: Path) -> Dict[str, Any]:
    comparisons: List[Dict[str, Any]] = []
    required_suffixes = {".csv", ".json", ".dot", ".mmd", ".xlsx"}
    baseline_files = {
        path.name: path for path in baseline.iterdir()
        if path.is_file() and path.suffix.lower() in required_suffixes
    }
    candidate_files = {
        path.name: path for path in candidate.iterdir()
        if path.is_file() and path.suffix.lower() in required_suffixes
    }
    all_names = sorted(set(baseline_files) | set(candidate_files))
    for filename in all_names:
        left = baseline_files.get(filename)
        right = candidate_files.get(filename)
        if left is None or right is None:
            comparisons.append({
                "artifact": filename,
                "equal": False,
                "detail": "missing from baseline" if left is None else "missing from candidate",
            })
            continue
        suffix = left.suffix.lower()
        loader = _json if suffix == ".json" else _csv if suffix == ".csv" else _xlsx if suffix == ".xlsx" else _text
        try:
            equal = loader(left) == loader(right)
            detail = "equivalent after approved metadata normalization" if equal else "substantive content differs"
        except Exception as exc:
            equal = False
            detail = f"comparison error: {exc}"
        comparisons.append({"artifact": filename, "equal": equal, "detail": detail})

    manifest_left = json.loads((baseline / "run_manifest.json").read_text("utf-8"))
    manifest_right = json.loads((candidate / "run_manifest.json").read_text("utf-8"))
    generation_left = {
        "graphviz": manifest_left.get("graphviz"),
        "excel_requested": manifest_left.get("excel_requested"),
        "excel_generated": manifest_left.get("excel_generated"),
    }
    generation_right = {
        "graphviz": manifest_right.get("graphviz"),
        "excel_requested": manifest_right.get("excel_requested"),
        "excel_generated": manifest_right.get("excel_generated"),
    }
    generation_equal = normalize_value(generation_left) == normalize_value(generation_right)
    comparisons.append({
        "artifact": "diagram and Excel generation state",
        "equal": generation_equal,
        "detail": "equivalent" if generation_equal else "generation state differs",
    })
    return {
        "name": name,
        "baseline": str(baseline),
        "candidate": str(candidate),
        "passed": all(item["equal"] for item in comparisons),
        "comparisons": comparisons,
    }


def _write_markdown(path: Path, scenarios: Iterable[Dict[str, Any]]) -> None:
    scenarios = list(scenarios)
    passed = all(item["passed"] for item in scenarios)
    lines = [
        "# v1.2.4 vs v1.2.5 compatibility report",
        "",
        f"Overall result: **{'PASS' if passed else 'FAIL'}**",
        "",
        "Approved normalization is restricted to application version, run IDs,",
        "run timestamps, environment input paths, and generated-file hashes/sizes.",
        "Firewall, direction, endpoints, ports, protocols, services, evidence,",
        "confidence, findings, dependencies, and review classifications are not",
        "removed or normalized.",
        "",
    ]
    for scenario in scenarios:
        lines.extend([
            f"## {scenario['name']}",
            "",
            f"Result: **{'PASS' if scenario['passed'] else 'FAIL'}**",
            "",
            "| Artifact | Equivalent | Detail |",
            "| --- | --- | --- |",
        ])
        for item in scenario["comparisons"]:
            lines.append(
                f"| `{item['artifact']}` | {str(item['equal']).lower()} | "
                f"{item['detail']} |"
            )
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario", action="append", nargs=3, required=True,
        metavar=("NAME", "V124_DIR", "V125_DIR"),
    )
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args(argv)

    scenarios = [
        compare_scenario(name, Path(left), Path(right))
        for name, left, right in args.scenario
    ]
    payload = {
        "schema_version": "1.0",
        "baseline_version": "1.2.4",
        "candidate_version": "1.2.5",
        "passed": all(item["passed"] for item in scenarios),
        "scenarios": scenarios,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    _write_markdown(args.markdown, scenarios)
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
