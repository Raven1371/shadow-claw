#!/usr/bin/env python3
"""Run pytest and classify every skip for release-gate enforcement."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform as platform_module
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest


SECURITY_NODE_PATTERNS = (
    "test_output_security.py",
    "test_symlinked_files_and_directories_skipped",
    "test_symlinked_zeek_artifact_destination_rejected",
    "test_symlinked_current_svg_not_referenced",
)


def classify_skip(nodeid: str, reason: str, platform_name: str) -> Tuple[str, bool]:
    """Return ``(classification, acceptable)`` for a pytest skip."""
    lowered = reason.lower()
    is_linux = "linux" in platform_name.lower()
    security_test = any(pattern in nodeid for pattern in SECURITY_NODE_PATTERNS)

    if security_test:
        return "security-gate skip", not is_linux
    if "graphviz" in lowered:
        return "security-gate skip", not is_linux
    if "os.mkfifo" in lowered or "symlink" in lowered:
        return "expected platform limitation", not is_linux
    if "openpyxl" in lowered:
        return "expected optional dependency limitation", True
    if "tomllib" in lowered and sys.version_info < (3, 11):
        return "expected platform limitation", True
    return "unexpected skip", False


class SkipCollector:
    def __init__(self, platform_name: str) -> None:
        self.platform_name = platform_name
        self.skips: List[Dict[str, object]] = []

    def pytest_runtest_logreport(self, report) -> None:
        if not report.skipped:
            return
        reason = str(report.longrepr)
        if isinstance(report.longrepr, tuple) and len(report.longrepr) == 3:
            reason = str(report.longrepr[2])
            if reason.lower().startswith("skipped: "):
                reason = reason[9:]
        classification, acceptable = classify_skip(
            report.nodeid, reason, self.platform_name
        )
        self.skips.append(
            {
                "test_name": report.nodeid,
                "reason": reason,
                "classification": classification,
                "platform": self.platform_name,
                "acceptable": acceptable,
                "blocks_release": not acceptable,
            }
        )


def _write_reports(
    json_path: Path,
    markdown_path: Path,
    platform_name: str,
    pytest_exit_code: int,
    skips: List[Dict[str, object]],
) -> None:
    blockers = sum(bool(item["blocks_release"]) for item in skips)
    payload = {
        "schema_version": "1.0",
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "platform": platform_name,
        "pytest_exit_code": pytest_exit_code,
        "skip_count": len(skips),
        "blocking_skip_count": blockers,
        "release_gate_passed": pytest_exit_code == 0 and blockers == 0,
        "skips": skips,
    }
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Pytest skip classification",
        "",
        f"- Platform: `{platform_name}`",
        f"- Pytest exit code: `{pytest_exit_code}`",
        f"- Skips: `{len(skips)}`",
        f"- Release-blocking skips: `{blockers}`",
        "",
        "| Test | Classification | Acceptable | Blocks release | Reason |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in skips:
        reason = str(item["reason"]).replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| `{item['test_name']}` | {item['classification']} | "
            f"{str(item['acceptable']).lower()} | "
            f"{str(item['blocks_release']).lower()} | {reason} |"
        )
    if not skips:
        lines.append("| _None_ | - | true | false | No tests skipped. |")
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    parser.add_argument("--platform", default=platform_module.platform())
    parser.add_argument("--test-root", type=Path, default=Path.cwd())
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)

    pytest_args = list(args.pytest_args)
    if pytest_args and pytest_args[0] == "--":
        pytest_args.pop(0)
    collector = SkipCollector(args.platform)
    original = Path.cwd()
    json_path = args.json.resolve()
    markdown_path = args.markdown.resolve()
    test_root = args.test_root.resolve()
    try:
        os.chdir(test_root)
        sys.path.insert(0, str(test_root))
        exit_code = int(pytest.main(pytest_args or ["-q"], plugins=[collector]))
    finally:
        if sys.path and sys.path[0] == str(test_root):
            sys.path.pop(0)
        os.chdir(original)

    _write_reports(
        json_path,
        markdown_path,
        args.platform,
        exit_code,
        collector.skips,
    )
    if exit_code != 0 or any(item["blocks_release"] for item in collector.skips):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
