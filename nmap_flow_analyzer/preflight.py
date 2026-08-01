"""Offline startup diagnostics for source and packaged installations."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from . import TOOL_NAME, __version__


UPDATE_REMINDER = (
    "No automatic update checks are performed.\n"
    "Use the update command to check GitHub for a newer release."
)


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    critical: bool = False


def _module_check(import_name: str, display_name: str, critical: bool) -> Check:
    available = importlib.util.find_spec(import_name) is not None
    return Check(
        display_name,
        "pass" if available else "fail" if critical else "warning",
        "available" if available else "not installed",
        critical,
    )


def _packaging_mode() -> str:
    if getattr(sys, "frozen", False):
        return "standalone"
    try:
        from importlib.metadata import distribution

        distribution("nmap-flow-analyzer")
        return "python-package"
    except Exception:
        return "source-checkout"


def _graphviz_candidates(configured: Optional[Path]) -> Sequence[tuple]:
    executable = "dot.exe" if os.name == "nt" else "dot"
    candidates = []
    if configured:
        path = configured / executable if configured.is_dir() else configured
        candidates.append(("configured external", path))
    executable_dir = Path(sys.executable).resolve().parent
    bundle_roots = [
        Path(getattr(sys, "_MEIPASS", executable_dir)) / "graphviz" / "bin" / executable,
        executable_dir / "graphviz" / "bin" / executable,
        executable_dir.parent / "graphviz" / "bin" / executable,
    ]
    candidates.extend(("bundled", path) for path in bundle_roots)
    system = shutil.which("dot")
    if system:
        candidates.append(("system PATH", Path(system)))
    standards = (
        [Path("C:/Program Files/Graphviz/bin/dot.exe")]
        if os.name == "nt"
        else [Path("/usr/bin/dot"), Path("/usr/local/bin/dot")]
    )
    candidates.extend(("standard installation", path) for path in standards)
    return candidates


def discover_graphviz(configured: Optional[Path] = None) -> tuple:
    seen = set()
    for source, path in _graphviz_candidates(configured):
        try:
            resolved = path.expanduser().resolve()
        except OSError:
            continue
        key = os.path.normcase(str(resolved))
        if key in seen:
            continue
        seen.add(key)
        if resolved.is_file():
            return source, resolved
    return "unavailable", None


def _graphviz_checks(configured: Optional[Path], timeout: int) -> List[Check]:
    source, executable = discover_graphviz(configured)
    if executable is None:
        return [Check("Graphviz", "warning", "unavailable; DOT and Mermaid remain available")]
    checks = [Check("Graphviz location", "pass", f"{source}: {executable}")]
    try:
        version = subprocess.run(
            [str(executable), "-V"], capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        version_text = (version.stderr or version.stdout).strip()
        checks.append(Check(
            "Graphviz version",
            "pass" if version.returncode == 0 else "warning",
            version_text or f"exit code {version.returncode}",
        ))
        with tempfile.TemporaryDirectory(prefix="nfa-preflight-") as tmp:
            root = Path(tmp)
            dot = root / "smoke.dot"
            dot.write_text("digraph G { preflight -> ok }\n", encoding="utf-8")
            for fmt in ("svg", "png"):
                target = root / f"smoke.{fmt}"
                result = subprocess.run(
                    [str(executable), f"-T{fmt}", str(dot), "-o", str(target)],
                    capture_output=True, text=True, timeout=timeout, check=False,
                )
                valid = result.returncode == 0 and target.is_file() and target.stat().st_size > 0
                detail = "rendered successfully" if valid else (
                    (result.stderr or result.stdout).strip() or f"exit code {result.returncode}"
                )
                checks.append(Check(f"Graphviz {fmt.upper()} render", "pass" if valid else "warning", detail))
    except (OSError, subprocess.TimeoutExpired) as exc:
        checks.append(Check("Graphviz execution", "warning", str(exc)))
    return checks


def _writability_check(name: str, directory: Path, critical: bool) -> Check:
    target = directory
    while not target.exists() and target != target.parent:
        target = target.parent
    if not target.is_dir():
        return Check(name, "fail" if critical else "warning", f"no existing parent for {directory}", critical)
    try:
        with tempfile.NamedTemporaryFile(prefix=".nfa-write-", dir=target, delete=True):
            pass
        return Check(name, "pass", f"writable: {target}", critical)
    except OSError as exc:
        return Check(name, "fail" if critical else "warning", f"not writable: {target}: {exc}", critical)


def run_checks(
    configured_graphviz: Optional[Path] = None,
    output_directory: Optional[Path] = None,
    graphviz_timeout: int = 10,
) -> List[Check]:
    checks = [
        Check("Application", "pass", f"{TOOL_NAME} {__version__}"),
        Check("Operating system", "pass", platform.platform()),
        Check("Architecture", "pass", platform.machine() or "unknown"),
        Check("Packaging mode", "pass", _packaging_mode()),
        Check("Python runtime", "pass", sys.version.split()[0]),
        _module_check("defusedxml", "Secure XML support", True),
        _module_check("yaml", "YAML configuration support", True),
        _module_check("openpyxl", "Excel support", False),
        _writability_check("Temporary directory", Path(tempfile.gettempdir()), True),
    ]
    if output_directory is not None:
        checks.append(_writability_check("Output directory", output_directory, True))
    checks.extend(_graphviz_checks(configured_graphviz, graphviz_timeout))
    checks.extend([
        Check("Package integrity", "warning", "no installed checksum manifest configured"),
        Check("Update configuration", "pass", "manual update commands only; network not contacted"),
    ])
    return checks


def build_parser(command: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"nmap-flow-analyzer {command}")
    parser.add_argument("--graphviz-path", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--graphviz-timeout", type=int, default=10)
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    parser.add_argument("--non-interactive", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None, command: str = "preflight") -> int:
    args = build_parser(command).parse_args(argv)
    checks = run_checks(args.graphviz_path, args.output_dir, args.graphviz_timeout)
    failed = [check for check in checks if check.critical and check.status == "fail"]
    payload = {
        "application": TOOL_NAME,
        "version": __version__,
        "command": command,
        "network_access_performed": False,
        "status": "failed" if failed else "ready",
        "checks": [asdict(check) for check in checks],
        "update_reminder": UPDATE_REMINDER,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"{TOOL_NAME} {__version__} {command}")
        for check in checks:
            print(f"[{check.status.upper():7}] {check.name}: {check.detail}")
        print()
        print(UPDATE_REMINDER)
    return 1 if failed else 0
