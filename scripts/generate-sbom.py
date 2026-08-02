"""Generate a deterministic CycloneDX 1.5 SBOM from a pinned requirement lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^ ;]+)")


def component(name: str, version: str) -> dict[str, object]:
    normalized = name.lower().replace("_", "-")
    return {
        "type": "library",
        "name": normalized,
        "version": version,
        "bom-ref": f"pkg:pypi/{normalized}@{version}",
        "purl": f"pkg:pypi/{normalized}@{version}",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--component", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    requirements: dict[str, str] = {}
    for raw in args.lock.read_text(encoding="utf-8").splitlines():
        match = PIN.match(raw.strip())
        if match:
            name, version = match.groups()
            key = name.lower().replace("_", "-")
            if key in requirements and requirements[key] != version:
                raise ValueError(f"conflicting lock entries for {key}")
            requirements[key] = version
    root = component(args.component, args.version)
    components = [component(name, requirements[name]) for name in sorted(requirements)]
    serial_input = json.dumps([root, components], sort_keys=True, separators=(",", ":")).encode()
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{hashlib.sha256(serial_input).hexdigest()[:32]}",
        "version": 1,
        "metadata": {"component": root},
        "components": components,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {args.output} with {len(components)} locked components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

