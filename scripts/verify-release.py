#!/usr/bin/env python3
"""Verify release inventory completeness, metadata, sizes, and SHA-256."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    payload = json.loads(args.manifest.read_text("utf-8"))
    errors = []
    if payload.get("release_version") != args.version:
        errors.append("manifest release version mismatch")
    expected = {item["filename"]: item for item in payload.get("artifacts", [])}
    actual = {
        path.name: path for path in args.directory.iterdir()
        if path.is_file() and path.name not in {"SHA256SUMS.txt", "release-artifacts.json"}
    }
    for name in sorted(expected.keys() - actual.keys()):
        errors.append(f"missing artifact: {name}")
    for name in sorted(actual.keys() - expected.keys()):
        errors.append(f"unexpected artifact: {name}")
    for name in sorted(expected.keys() & actual.keys()):
        path = actual[name]
        item = expected[name]
        if path.is_symlink():
            errors.append(f"artifact is a symlink: {name}")
            continue
        if path.stat().st_size != item.get("size"):
            errors.append(f"size mismatch: {name}")
        if digest(path) != item.get("sha256"):
            errors.append(f"hash mismatch: {name}")
        if item.get("version") != args.version:
            errors.append(f"artifact version mismatch: {name}")
        if item.get("platform") not in {"ubuntu", "rhel", "windows", "source"}:
            errors.append(f"invalid platform metadata: {name}")
        if item.get("architecture") not in {"x64", "arm64", "source"}:
            errors.append(f"invalid architecture metadata: {name}")
    checksums = args.directory / "SHA256SUMS.txt"
    if not checksums.is_file():
        errors.append("missing SHA256SUMS.txt")
    else:
        expected_lines = {
            f"{item['sha256']}  {item['filename']}" for item in expected.values()
        }
        actual_lines = {line.strip() for line in checksums.read_text("utf-8").splitlines() if line.strip()}
        if actual_lines != expected_lines:
            errors.append("SHA256SUMS.txt does not match manifest")
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"Verified {len(expected)} release artifacts for {args.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
