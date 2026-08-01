#!/usr/bin/env python3
"""Attribute every redistributed ELF file using host package metadata."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path


def run(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()


def is_elf(path: Path) -> bool:
    try:
        return path.is_file() and path.open("rb").read(4) == b"\x7fELF"
    except OSError:
        return False


def owner(path: Path, platform: str) -> tuple[str, str, str, str, list[Path]]:
    if platform == "ubuntu":
        package = run("dpkg-query", "-S", str(path.resolve())).split(":", 1)[0]
        version, arch = run("dpkg-query", "-W", "-f=${Version}\t${Architecture}", package).split("\t")
        docs = [Path("/usr/share/doc") / package / "copyright"]
        license_id = "See Debian copyright file"
    else:
        package = run("rpm", "-qf", str(path.resolve()), "--qf", "%{NAME}")
        version, arch, license_id = run("rpm", "-q", package, "--qf", "%{VERSION}-%{RELEASE}\t%{ARCH}\t%{LICENSE}").split("\t")
        docs = [Path(p) for p in run("rpm", "-ql", package).splitlines()
                if "/license" in p.lower() or p.lower().endswith(("/copying", "/copyright", "/license"))]
    return package, version, arch, license_id, [p for p in docs if p.is_file()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=("ubuntu", "rhel"), required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    entries, failures = [], []
    native_licenses = bundle / "licenses" / "native-libraries"
    native_licenses.mkdir(parents=True, exist_ok=True)
    package_license_root = bundle / "licenses" / "python-packages"
    package_license_root.mkdir(parents=True, exist_ok=True)
    python_evidence: dict[str, list[str]] = {}
    for dist_name in ("defusedxml", "PyYAML", "openpyxl", "et_xmlfile", "pyinstaller"):
        dist = importlib.metadata.distribution(dist_name)
        copied = []
        for item in dist.files or ():
            name = Path(str(item)).name.lower()
            if name.startswith(("license", "licence", "copying", "copyright")):
                source = Path(dist.locate_file(item))
                if source.is_file():
                    target = package_license_root / dist_name / Path(str(item)).name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
                    copied.append(target.relative_to(bundle).as_posix())
        if not copied:
            raise SystemExit(f"installed distribution has no license evidence: {dist_name}")
        python_evidence[dist_name.lower()] = copied
    pyinstaller_target = bundle / "licenses" / "pyinstaller"
    pyinstaller_target.mkdir(parents=True, exist_ok=True)
    for rel in python_evidence["pyinstaller"]:
        source = bundle / rel
        shutil.copy2(source, pyinstaller_target / source.name)

    python_docs = [p for p in (Path(sys.base_prefix) / "LICENSE", Path(sys.base_prefix) / "LICENSE.txt") if p.is_file()]
    python_docs += list(Path("/usr/share/doc").glob("python3*/copyright"))
    if not python_docs and args.platform == "rhel":
        python_library = Path(sysconfig.get_config_var("LIBDIR")) / sysconfig.get_config_var("LDLIBRARY")
        python_package = run("rpm", "-qf", str(python_library), "--qf", "%{NAME}")
        python_docs = [Path(p) for p in run("rpm", "-ql", python_package).splitlines()
                       if "/license" in p.lower() or p.lower().endswith(("/copying", "/copyright", "/license"))]
        python_docs = [p for p in python_docs if p.is_file()]
    python_target = bundle / "licenses" / "python"
    python_target.mkdir(parents=True, exist_ok=True)
    python_license_paths = []
    for source in python_docs:
        target = python_target / (source.parent.name + "-copyright")
        shutil.copy2(source, target)
        python_license_paths.append(target.relative_to(bundle).as_posix())
    if not python_license_paths:
        raise SystemExit("CPython package license evidence not found")
    for shipped in sorted(p for p in bundle.rglob("*") if is_elf(p)):
        # Resolve the original by basename. Files copied with -L cannot be queried by package managers.
        candidates = [shipped]
        candidates += list(Path("/usr/bin").glob(shipped.name))
        candidates += list(Path("/usr/lib").rglob(shipped.name))
        candidates += list(Path("/usr/lib64").rglob(shipped.name))
        attribution = None
        for candidate in candidates:
            try:
                package, version, arch, license_id, evidence = owner(candidate, args.platform)
                attribution = (candidate, package, version, arch, license_id, evidence)
                break
            except (subprocess.CalledProcessError, ValueError, OSError):
                continue
        rel = shipped.relative_to(bundle).as_posix()
        special = None
        lower = rel.lower()
        if shipped.name in ("nmap-flow-analyzer.bin", "nmap-flow-analyzer"):
            special = ("pyinstaller", "6.21.0", "x86_64", "GPL-2.0-or-later WITH Bootloader-exception", python_evidence["pyinstaller"])
        elif "_yaml" in lower:
            special = ("PyYAML", "6.0.2", "x86_64", "MIT", python_evidence["pyyaml"])
        elif "libpython" in lower or "lib-dynload" in lower:
            special = ("CPython", run("python3", "--version").split()[-1], "x86_64", "PSF-2.0", python_license_paths)
        if not attribution and special:
            package, version, arch, license_id, license_paths = special
            entries.append({"path": rel, "sha256": hashlib.sha256(shipped.read_bytes()).hexdigest(),
                            "source_path": "PyInstaller collected runtime", "package": package,
                            "version": version, "architecture": arch, "license": license_id,
                            "license_evidence": license_paths, "classification": "runtime"})
            continue
        if not attribution:
            failures.append(rel)
            continue
        candidate, package, version, arch, license_id, evidence = attribution
        license_paths = []
        if not evidence:
            failures.append(rel + " (package has no installed license evidence)")
            continue
        for source in evidence:
            target = native_licenses / package / source.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            license_paths.append(target.relative_to(bundle).as_posix())
        entries.append({
            "path": rel, "sha256": hashlib.sha256(shipped.read_bytes()).hexdigest(),
            "source_path": str(candidate), "package": package, "version": version,
            "architecture": arch, "license": license_id,
            "license_evidence": license_paths, "classification": "runtime"
        })
    payload = {"schema_version": 1, "platform": args.platform, "files": entries,
               "unattributed": failures, "release_blocked": bool(failures)}
    output = bundle / "licenses" / "NATIVE_DEPENDENCY_INVENTORY.json"
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if failures:
        raise SystemExit("unattributed redistributed ELF files: " + ", ".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
