#!/usr/bin/env python3
"""Fail unless a staged distribution has a complete, resolved license payload."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

REQUIRED = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "licenses/README.md",
            "licenses/DEPENDENCY_LICENSE_INVENTORY.json",
            "licenses/NATIVE_DEPENDENCY_INVENTORY.json")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    missing = [name for name in REQUIRED if not (root / name).is_file()]
    if missing:
        raise SystemExit("missing license payload: " + ", ".join(missing))
    declared = json.loads((root / REQUIRED[-1]).read_text(encoding="utf-8"))
    if declared.get("release_blocked") or declared.get("unattributed"):
        raise SystemExit("native dependency inventory contains release blockers")
    by_path = {item["path"]: item for item in declared["files"]}
    for rel, item in by_path.items():
        path = root / rel
        if not path.is_file():
            raise SystemExit(f"inventoried file absent: {rel}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != item["sha256"]:
            raise SystemExit(f"inventory checksum mismatch: {rel}")
        if not item.get("license_evidence"):
            raise SystemExit(f"missing license evidence: {rel}")
    print(f"Validated license payload and {len(by_path)} attributed native files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
