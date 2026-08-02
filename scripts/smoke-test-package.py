#!/usr/bin/env python3
"""Exercise an installed/packaged command outside the source import path."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def run(command: list[str], cwd: Path, timeout: int = 90) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", type=Path, required=True)
    parser.add_argument("--examples", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--expected-version", default="1.3.0")
    parser.add_argument("--require-graphviz", action="store_true")
    args = parser.parse_args()
    command = str(args.command.resolve())
    examples = args.examples.resolve()
    config = args.config.resolve()
    with tempfile.TemporaryDirectory(prefix="nfa-package-smoke-") as tmp:
        root = Path(tmp)
        run([command, "--help"], root)
        version = run([command, "--version"], root).stdout.strip()
        if args.expected_version not in version:
            raise RuntimeError(f"unexpected package version: {version}")
        doctor = run([command, "doctor", "--non-interactive"], root)
        if "No automatic update checks are performed." not in doctor.stdout:
            raise RuntimeError("doctor omitted the offline update notice")
        preflight = run([command, "preflight", "--json", "--non-interactive"], root)
        payload = json.loads(preflight.stdout)
        if payload["network_access_performed"] is not False:
            raise RuntimeError("preflight reported network access")
        if args.require_graphviz:
            checks = {item["name"]: item["status"] for item in payload["checks"]}
            for name in ("Graphviz SVG render", "Graphviz PNG render"):
                if checks.get(name) != "pass":
                    raise RuntimeError(f"required package check did not pass: {name}")
        output = root / "analysis"
        base = [
            command, "--input", str(examples / "sample-scan.xml"),
            "--config", str(config), "--scanner-ip", "192.168.1.50",
            "--output-dir", str(output),
        ]
        run(base, root)
        if args.require_graphviz:
            for name in ("data_flow_diagram.svg", "data_flow_diagram.png"):
                if not (output / name).is_file() or not (output / name).stat().st_size:
                    raise RuntimeError(f"missing packaged Graphviz output: {name}")
        renamed = root / "renamed-analysis"
        output.rename(renamed)
        shutil.rmtree(renamed)
        run(base, root)
        shutil.rmtree(output)
        run(base + ["--zeek-dir", str(examples / "zeek-sample")], root)
        shutil.rmtree(output)
    print("Package smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
