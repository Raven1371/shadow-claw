"""Explicit, user-initiated application update operations.

No function in this module is called during normal analysis or preflight.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import urllib.parse
import webbrowser
import zipfile
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, Optional

from . import TOOL_NAME, __version__


REPOSITORY = "Raven1371/Nmap-scan-and-reports"
RELEASES_URL = f"https://github.com/{REPOSITORY}/releases"
API_ROOT = f"https://api.github.com/repos/{REPOSITORY}/releases"
MAX_DOWNLOAD = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_FILES = 20_000
MAX_EXTRACTED_SIZE = 4 * 1024 * 1024 * 1024
PACKAGE_RE = re.compile(
    r"^nmap-flow-analyzer-(?P<version>\d+\.\d+\.\d+(?:-rc\d+)?)"
    r"-(?P<platform>ubuntu|rhel|windows)-(?P<arch>x64|arm64)"
    r"(?P<kind>-portable)?(?P<suffix>\.tar\.gz|\.zip|\.deb|\.rpm|\.AppImage|)$"
)


class UpdateError(RuntimeError):
    """A safe update operation could not be completed."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_checksums(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            raise UpdateError(f"invalid SHA256SUMS entry: {line!r}")
        name = parts[1].lstrip("*").strip()
        if not name or Path(name).name != name or name in result:
            raise UpdateError(f"unsafe or duplicate checksum filename: {name!r}")
        result[name] = parts[0].lower()
    return result


def current_target() -> tuple[str, str]:
    system = platform.system().lower()
    if system == "windows":
        target_platform = "windows"
    elif system == "linux":
        marker = ""
        try:
            marker = Path("/etc/os-release").read_text("utf-8").lower()
        except OSError:
            pass
        target_platform = "rhel" if any(
            value in marker for value in ("rhel", "rocky", "almalinux", "fedora")
        ) else "ubuntu"
    else:
        raise UpdateError(f"unsupported update platform: {system or 'unknown'}")
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64"}:
        arch = "x64"
    elif machine in {"arm64", "aarch64"}:
        arch = "arm64"
    else:
        raise UpdateError(f"unsupported update architecture: {machine or 'unknown'}")
    return target_platform, arch


def validate_package_name(path: Path, expected_platform: Optional[str] = None,
                          expected_arch: Optional[str] = None) -> Dict[str, str]:
    match = PACKAGE_RE.fullmatch(path.name)
    if not match:
        raise UpdateError(f"unrecognized complete application package: {path.name}")
    metadata = match.groupdict(default="")
    target_platform, target_arch = current_target()
    wanted_platform = expected_platform or target_platform
    wanted_arch = expected_arch or target_arch
    if metadata["platform"] != wanted_platform:
        raise UpdateError(
            f"package platform {metadata['platform']} does not match {wanted_platform}"
        )
    if metadata["arch"] != wanted_arch:
        raise UpdateError(
            f"package architecture {metadata['arch']} does not match {wanted_arch}"
        )
    return metadata


def verify_package(path: Path, expected_sha256: Optional[str] = None,
                   checksum_file: Optional[Path] = None) -> Dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise UpdateError(f"package is not a regular file: {path}")
    metadata = validate_package_name(path)
    expected = expected_sha256.lower() if expected_sha256 else None
    inventory = checksum_file or path.with_name("SHA256SUMS.txt")
    if expected is None and inventory.is_file() and not inventory.is_symlink():
        expected = parse_checksums(inventory.read_text("utf-8")).get(path.name)
    if expected is None:
        raise UpdateError("no trusted SHA-256 supplied and package is absent from SHA256SUMS.txt")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise UpdateError("expected SHA-256 must contain exactly 64 hexadecimal characters")
    actual = sha256_file(path)
    if actual != expected:
        raise UpdateError(f"SHA-256 mismatch for {path.name}: expected {expected}, got {actual}")
    metadata["sha256"] = actual
    return metadata


def _safe_member(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or normalized.startswith("/") or path.is_absolute():
        raise UpdateError(f"unsafe absolute archive path: {name!r}")
    if any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        raise UpdateError(f"unsafe archive path: {name!r}")
    return path


def _extract_zip(package: Path, destination: Path) -> None:
    with zipfile.ZipFile(package) as archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_FILES:
            raise UpdateError("portable archive contains too many entries")
        total = sum(item.file_size for item in members)
        if total > MAX_EXTRACTED_SIZE:
            raise UpdateError("portable archive exceeds extracted-size limit")
        lowered = set()
        for item in members:
            safe = _safe_member(item.filename)
            collision = str(safe).casefold()
            if collision in lowered:
                raise UpdateError(f"duplicate or case-colliding archive path: {item.filename}")
            lowered.add(collision)
            mode = (item.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise UpdateError(f"symbolic links are not accepted in update archives: {item.filename}")
        archive.extractall(destination)


def _extract_tar(package: Path, destination: Path) -> None:
    with tarfile.open(package, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > MAX_ARCHIVE_FILES:
            raise UpdateError("portable archive contains too many entries")
        if sum(item.size for item in members) > MAX_EXTRACTED_SIZE:
            raise UpdateError("portable archive exceeds extracted-size limit")
        lowered = set()
        for item in members:
            safe = _safe_member(item.name)
            collision = str(safe).casefold()
            if collision in lowered:
                raise UpdateError(f"duplicate or case-colliding archive path: {item.name}")
            lowered.add(collision)
            if item.issym() or item.islnk() or not (item.isfile() or item.isdir()):
                raise UpdateError(f"unsupported archive entry type: {item.name}")
        archive.extractall(destination, members=members)


def install_portable(package: Path, target: Path, expected_sha256: Optional[str],
                     checksum_file: Optional[Path]) -> Dict[str, str]:
    metadata = verify_package(package, expected_sha256, checksum_file)
    if metadata["kind"] != "-portable" or metadata["suffix"] not in {".zip", ".tar.gz"}:
        raise UpdateError(
            "automatic local installation is limited to verified portable archives; "
            "use the operating-system package manager for DEB/RPM/AppImage/onefile packages"
        )
    target = target.resolve()
    if target.exists():
        raise UpdateError(f"installation target already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}-", dir=target.parent))
    try:
        if metadata["suffix"] == ".zip":
            _extract_zip(package, staging)
        else:
            _extract_tar(package, staging)
        os.replace(staging, target)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    metadata["installed_to"] = str(target)
    return metadata


def _request_json(url: str) -> dict:
    request = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": TOOL_NAME}
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.geturl().split(":", 1)[0].lower() != "https":
            raise UpdateError("release lookup was redirected away from HTTPS")
        return json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))


def _download_file(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": TOOL_NAME})
    partial = destination.with_name(destination.name + ".part")
    written = 0
    try:
        with urllib.request.urlopen(request, timeout=30) as response, partial.open("xb") as output:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in {
                "github.com", "objects.githubusercontent.com",
                "release-assets.githubusercontent.com",
            }:
                raise UpdateError("release asset was redirected to an untrusted location")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_DOWNLOAD:
                    raise UpdateError("release asset exceeds download-size limit")
                output.write(chunk)
        os.replace(partial, destination)
    except Exception:
        partial.unlink(missing_ok=True)
        raise


def download_release(tag: str, package_type: str, output_dir: Path) -> Dict[str, str]:
    release = _request_json(f"{API_ROOT}/tags/{tag}")
    assets = {item.get("name"): item for item in release.get("assets", [])}
    checksum_asset = assets.get("SHA256SUMS.txt")
    if not checksum_asset:
        raise UpdateError("release does not contain SHA256SUMS.txt")
    target_platform, target_arch = current_target()
    version = tag.removeprefix("v")
    suffixes = {
        "portable": ["-portable.tar.gz", "-portable.zip"],
        "onefile": [""],
        "deb": [".deb"],
        "rpm": [".rpm"],
        "appimage": [".AppImage"],
    }[package_type]
    prefix = f"nmap-flow-analyzer-{version}-{target_platform}-{target_arch}"
    candidates = [name for name in assets if name and any(
        name == prefix + suffix for suffix in suffixes
    )]
    if len(candidates) != 1:
        raise UpdateError(
            f"release has {len(candidates)} matching {package_type} packages for "
            f"{target_platform}-{target_arch}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    package = output_dir / candidates[0]
    checksums = output_dir / "SHA256SUMS.txt"
    if package.exists() or checksums.exists():
        raise UpdateError("download destination already contains release files")
    try:
        _download_file(checksum_asset["browser_download_url"], checksums)
        inventory = parse_checksums(checksums.read_text("utf-8"))
        expected = inventory.get(package.name)
        if expected is None:
            raise UpdateError(f"release checksum inventory omits {package.name}")
        _download_file(assets[package.name]["browser_download_url"], package)
        metadata = verify_package(package, expected, checksums)
        metadata.update({"downloaded_to": str(package), "tag": tag})
        return metadata
    except Exception:
        package.unlink(missing_ok=True)
        checksums.unlink(missing_ok=True)
        raise


def check_release(tag: Optional[str] = None) -> dict:
    release = _request_json(f"{API_ROOT}/tags/{tag}" if tag else f"{API_ROOT}/latest")
    return {
        "current_version": __version__,
        "tag": release.get("tag_name", ""),
        "name": release.get("name", ""),
        "prerelease": bool(release.get("prerelease")),
        "published_at": release.get("published_at"),
        "release_url": release.get("html_url"),
        "notes": release.get("body", ""),
        "network_access_performed": True,
    }


def _print_payload(payload: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        for key, value in payload.items():
            print(f"{key.replace('_', ' ').title()}: {value}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nmap-flow-analyzer update")
    sub = parser.add_subparsers(dest="operation", required=True)
    check = sub.add_parser("check", help="explicitly query GitHub Releases")
    check.add_argument("--tag")
    check.add_argument("--json", action="store_true")
    opened = sub.add_parser("open-releases", help="open the releases page")
    opened.add_argument("--print-only", action="store_true")
    download = sub.add_parser("download", help="download and verify a release package")
    download.add_argument("--tag", required=True)
    download.add_argument(
        "--package-type", choices=["portable", "onefile", "deb", "rpm", "appimage"],
        default="portable",
    )
    download.add_argument("--output-dir", type=Path, required=True)
    download.add_argument("--json", action="store_true")
    verify = sub.add_parser("verify", help="verify a complete local package")
    verify.add_argument("package", type=Path)
    verify.add_argument("--sha256")
    verify.add_argument("--checksums", type=Path)
    verify.add_argument("--json", action="store_true")
    install = sub.add_parser("install", help="install a verified portable archive")
    install.add_argument("package", type=Path)
    install.add_argument("--target", type=Path, required=True)
    install.add_argument("--sha256")
    install.add_argument("--checksums", type=Path)
    install.add_argument("--json", action="store_true")
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        if args.operation == "check":
            _print_payload(check_release(args.tag), args.json)
        elif args.operation == "open-releases":
            print(RELEASES_URL)
            if not args.print_only and not webbrowser.open(RELEASES_URL):
                raise UpdateError("the releases page could not be opened")
        elif args.operation == "download":
            payload = download_release(args.tag, args.package_type, args.output_dir)
            payload["verified"] = True
            _print_payload(payload, args.json)
        elif args.operation == "verify":
            payload = verify_package(args.package, args.sha256, args.checksums)
            payload["verified"] = True
            _print_payload(payload, args.json)
        elif args.operation == "install":
            payload = install_portable(
                args.package, args.target, args.sha256, args.checksums
            )
            payload["installed"] = True
            _print_payload(payload, args.json)
        return 0
    except (OSError, ValueError, UpdateError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f"update error: {exc}", file=sys.stderr)
        return 2
