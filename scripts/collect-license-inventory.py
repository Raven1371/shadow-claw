#!/usr/bin/env python3
"""Attribute every redistributed ELF file using host package metadata."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import re
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen


def run(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()


def is_elf(path: Path) -> bool:
    try:
        return path.is_file() and path.open("rb").read(4) == b"\x7fELF"
    except OSError:
        return False


LICENSE_NAME = re.compile(r"^(copying|copyright|licen[cs]e|notice)([._-].*)?$", re.I)
ROCKY_SOURCE_RPM_VAULT = {
    # Rocky 9's current repositories no longer expose the source matching the
    # libstdc++ preinstalled in the rockylinux:9 container. This immutable
    # official Rocky 9.3 vault object is selected only after SOURCERPM matches.
    "gcc-11.4.1-2.1.el9.src.rpm":
        "https://dl.rockylinux.org/vault/rocky/9.3/BaseOS/source/tree/Packages/g/"
        "gcc-11.4.1-2.1.el9.src.rpm",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def symlink_chain(path: Path) -> list[str]:
    chain, current = [], path
    for _ in range(40):
        chain.append(str(current))
        if not current.is_symlink():
            return chain
        target = Path(current.readlink())
        current = target if target.is_absolute() else current.parent / target
    raise RuntimeError(f"symlink chain is cyclic or too deep: {path}")


def parse_ldconfig(output: str, soname: str) -> list[Path]:
    paths = []
    for line in output.splitlines():
        match = re.match(r"\s*(\S+)\s+\([^)]*\)\s+=>\s+(\S+)\s*$", line)
        if match and match.group(1) == soname:
            paths.append(Path(match.group(2)))
    return paths


def require_exact_file(paths: list[Path], expected: str) -> Path:
    matches = [path for path in paths if path.name == expected]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one {expected}, got {len(matches)}")
    return matches[0]


def verify_rpm_signature(output: str) -> None:
    if "signatures ok" not in output.lower():
        raise RuntimeError(f"RPM signature was not verified: {output}")


def verify_same_file(source: Path, bundled: Path) -> None:
    if sha256(source.resolve()) != sha256(bundled):
        raise RuntimeError("bundled-file hash mismatch with canonical package file")


def exact_source_rpm_evidence(package: str, bundle: Path) -> tuple[list[Path], dict[str, str]]:
    """Recover license texts from the exact signed source RPM, without executing it."""
    source_rpm = run("rpm", "-q", package, "--qf", "%{SOURCERPM}")
    if not source_rpm or source_rpm == "(none)":
        raise RuntimeError(f"{package}: missing source RPM metadata")
    with tempfile.TemporaryDirectory(prefix="license-source-rpm-") as raw_tmp:
        tmp = Path(raw_tmp)
        download = subprocess.run(
            ("dnf", "download", "--source", "--destdir", str(tmp), package),
            check=True, text=True, capture_output=True,
        )
        matches = list(tmp.glob("*.src.rpm"))
        exact = [p for p in matches if p.name == source_rpm]
        repository = "Rocky Linux configured DNF source repository: " + download.stdout.strip()
        if len(exact) != 1 and source_rpm in ROCKY_SOURCE_RPM_VAULT:
            url = ROCKY_SOURCE_RPM_VAULT[source_rpm]
            destination = tmp / source_rpm
            with urlopen(url, timeout=120) as response, destination.open("wb") as output:
                shutil.copyfileobj(response, output)
            exact = [destination]
            repository = url
        if len(exact) != 1:
            raise RuntimeError(
                f"{package}: expected exact source RPM {source_rpm}, got "
                + ", ".join(p.name for p in matches)
            )
        srpm = require_exact_file(exact, source_rpm)
        signature = subprocess.run(
            ("rpmkeys", "--checksig", str(srpm)), check=True, text=True, capture_output=True
        ).stdout.strip()
        try:
            verify_rpm_signature(signature)
        except RuntimeError as exc:
            raise RuntimeError(f"{source_rpm}: {exc}") from exc
        extracted = tmp / "extracted"
        extracted.mkdir()
        rpm2cpio = subprocess.Popen(("rpm2cpio", str(srpm)), stdout=subprocess.PIPE)
        unpack = subprocess.run(
            ("cpio", "-idm", "--quiet"), cwd=extracted, stdin=rpm2cpio.stdout,
            text=False, capture_output=True,
        )
        assert rpm2cpio.stdout is not None
        rpm2cpio.stdout.close()
        rpm_status = rpm2cpio.wait()
        if rpm_status or unpack.returncode:
            raise RuntimeError(f"{source_rpm}: source RPM extraction failed")

        found: list[tuple[str, bytes]] = []
        for item in sorted(p for p in extracted.rglob("*") if p.is_file()):
            if LICENSE_NAME.match(item.name):
                found.append((item.relative_to(extracted).as_posix(), item.read_bytes()))
                continue
            try:
                if tarfile.is_tarfile(item):
                    with tarfile.open(item) as archive:
                        for member in archive.getmembers():
                            member_path = Path(member.name)
                            if (member.isfile() and LICENSE_NAME.match(member_path.name)
                                    and len(member_path.parts) <= 4):
                                stream = archive.extractfile(member)
                                if stream is not None:
                                    found.append((item.name + "!" + member.name, stream.read()))
                elif zipfile.is_zipfile(item):
                    with zipfile.ZipFile(item) as archive:
                        for member in archive.infolist():
                            member_path = Path(member.filename)
                            if (not member.is_dir() and LICENSE_NAME.match(member_path.name)
                                    and len(member_path.parts) <= 4):
                                found.append((item.name + "!" + member.filename, archive.read(member)))
            except (OSError, tarfile.TarError, zipfile.BadZipFile):
                continue
        if not found:
            raise RuntimeError(f"{source_rpm}: no license or notice material found")
        target_root = bundle / "licenses" / "native-libraries" / package / "source-rpm"
        target_root.mkdir(parents=True, exist_ok=True)
        copied: list[Path] = []
        origins: dict[str, str] = {}
        for index, (origin, data) in enumerate(found):
            safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(origin).name)
            target = target_root / f"{index:03d}-{safe_name}"
            target.write_bytes(data)
            copied.append(target)
            origins[target.relative_to(bundle).as_posix()] = origin
        return copied, {
            "source_rpm": source_rpm,
            "source_rpm_sha256": sha256(srpm),
            "repository": repository,
            "rpm_signature_verification": signature,
            "license_source_type": "exact-signed-source-rpm",
            "retrieval_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "license_origins": json.dumps(origins, sort_keys=True),
        }


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
        # Minimal RPM installations often split license files into a sibling
        # package built from the same source RPM (for example a *-common
        # package). Attribute that installed evidence to the shared source,
        # without guessing a package name or downloading anything.
        if not any(p.is_file() for p in docs):
            source_rpm = run("rpm", "-q", package, "--qf", "%{SOURCERPM}")
            installed = run("rpm", "-qa", "--qf", "%{NAME}\t%{SOURCERPM}\n")
            siblings = [line.split("\t", 1)[0] for line in installed.splitlines()
                        if "\t" in line and line.split("\t", 1)[1] == source_rpm]
            for sibling in siblings:
                docs.extend(Path(p) for p in run("rpm", "-ql", sibling).splitlines()
                            if "/license" in p.lower()
                            or p.lower().endswith(("/copying", "/copyright", "/license")))
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
    source_fallback_cache: dict[str, tuple[list[Path], dict[str, str]]] = {}
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
        names = {sysconfig.get_config_var("LDLIBRARY"), sysconfig.get_config_var("INSTSONAME")}
        candidates = [Path(directory) / name for directory in (sysconfig.get_config_var("LIBDIR"), "/lib64", "/usr/lib64")
                      for name in names if directory and name]
        python_package = None
        for python_library in candidates:
            if not python_library.exists():
                continue
            try:
                python_package = run("rpm", "-qf", str(python_library.resolve()), "--qf", "%{NAME}")
                break
            except subprocess.CalledProcessError:
                continue
        if not python_package:
            raise SystemExit("CPython shared-library package ownership not found")
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
            if args.platform != "rhel":
                failures.append(rel + " (package has no installed license evidence)")
                continue
            try:
                if package not in source_fallback_cache:
                    source_fallback_cache[package] = exact_source_rpm_evidence(package, bundle)
                evidence, source_provenance = source_fallback_cache[package]
            except (RuntimeError, subprocess.CalledProcessError, OSError) as exc:
                failures.append(rel + f" (exact source-RPM license fallback failed: {exc})")
                continue
        else:
            source_provenance = {
                "source_rpm": run("rpm", "-q", package, "--qf", "%{SOURCERPM}") if args.platform == "rhel" else "",
                "source_rpm_sha256": "not-required-installed-license-evidence",
                "repository": "installed package database",
                "rpm_signature_verification": "installed-package-manager-trust",
                "license_source_type": "installed-binary-rpm",
                "retrieval_timestamp_utc": "",
                "license_origins": "{}",
            }
        for source in evidence:
            target = native_licenses / package / source.name
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.resolve() != target.resolve():
                shutil.copy2(source, target)
            license_paths.append(target.relative_to(bundle).as_posix())
        entry = {
            "path": rel, "sha256": hashlib.sha256(shipped.read_bytes()).hexdigest(),
            "source_path": str(candidate), "package": package, "version": version,
            "architecture": arch, "license": license_id,
            "license_evidence": license_paths, "classification": "runtime",
            **source_provenance,
        }
        try:
            verify_same_file(candidate, shipped)
        except RuntimeError as exc:
            failures.append(rel + f" ({exc})")
            continue
        provenance_dir = native_licenses / package / "provenance"
        provenance_dir.mkdir(parents=True, exist_ok=True)
        provenance = provenance_dir / (re.sub(r"[^A-Za-z0-9._-]+", "_", rel) + ".json")
        provenance.write_text(json.dumps({
            "library_soname": shipped.name,
            "canonical_source_path": str(candidate.resolve()),
            "symbolic_link_chain": symlink_chain(candidate),
            "source_file_sha256": sha256(candidate.resolve()),
            "bundled_file_path": rel,
            "bundled_file_sha256": sha256(shipped),
            "package_name": package,
            "package_nevra": f"{package}-{version}.{arch}",
            "package_license_tag": license_id,
            "license_original_path": source_provenance["license_origins"],
            "license_packaged_path": license_paths,
            "license_sha256": {p: sha256(bundle / p) for p in license_paths},
            "verification_status": "verified",
            **{k: v for k, v in source_provenance.items() if k != "license_origins"},
        }, indent=2) + "\n", encoding="utf-8")
        entry["provenance_record"] = provenance.relative_to(bundle).as_posix()
        entries.append(entry)
    payload = {"schema_version": 1, "platform": args.platform, "files": entries,
               "unattributed": failures, "release_blocked": bool(failures)}
    output = bundle / "licenses" / "NATIVE_DEPENDENCY_INVENTORY.json"
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if failures:
        raise SystemExit("unattributed redistributed ELF files: " + ", ".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
