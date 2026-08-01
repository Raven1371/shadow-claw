#!/usr/bin/env python3
"""Create a SHA-256 inventory and typed release artifact manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


PLATFORM_RE = re.compile(
    r"^nmap-flow-analyzer-(?P<version>\d+\.\d+\.\d+-rc\d+)-"
    r"(?P<platform>ubuntu|rhel|windows)-(?P<arch>x64|arm64)"
    r"(?P<tail>-portable\.tar\.gz|-portable\.zip|\.deb|\.rpm|\.AppImage|)$"
)
SOURCE_RE = re.compile(
    r"^nmap-flow-analyzer-(?P<version>\d+\.\d+\.\d+-rc\d+)-"
    r"source\.(?P<format>zip|tar\.gz)$"
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def describe(path: Path, version: str) -> dict:
    source = SOURCE_RE.fullmatch(path.name)
    match = PLATFORM_RE.fullmatch(path.name)
    selected_version = (source or match).group("version") if source or match else None
    if selected_version != version:
        raise ValueError(f"artifact filename does not match release {version}: {path.name}")
    if source:
        artifact_platform = architecture = "source"
        package_type = f"source.{source.group('format')}"
    else:
        artifact_platform = match.group("platform")
        architecture = match.group("arch")
        package_type = {
            "": "onefile",
            "-portable.tar.gz": "portable.tar.gz",
            "-portable.zip": "portable.zip",
            ".deb": "deb",
            ".rpm": "rpm",
            ".AppImage": "AppImage",
        }[match.group("tail")]
    return {
        "filename": path.name,
        "sha256": digest(path),
        "size": path.stat().st_size,
        "version": selected_version,
        "platform": artifact_platform,
        "architecture": architecture,
        "package_type": package_type,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args()
    entries = []
    seen = set()
    for path in args.artifacts:
        resolved = path.resolve()
        if path.name in seen:
            raise SystemExit(f"duplicate artifact filename: {path.name}")
        seen.add(path.name)
        if path.is_symlink() or not path.is_file():
            raise SystemExit(f"artifact is not a regular file: {path}")
        entries.append(describe(resolved, args.version))
    entries.sort(key=lambda item: item["filename"])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    checksums = "".join(f"{item['sha256']}  {item['filename']}\n" for item in entries)
    (args.output_dir / "SHA256SUMS.txt").write_text(checksums, encoding="utf-8")
    manifest = {"schema_version": "1.0", "release_version": args.version, "artifacts": entries}
    (args.output_dir / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
