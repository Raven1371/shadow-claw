"""Security and offline behavior tests for explicit update commands."""

import hashlib
import io
import json
import tarfile
import tempfile
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import pytest

from nmap_flow_analyzer.cli import main
from nmap_flow_analyzer.update import (
    UpdateError,
    install_portable,
    parse_checksums,
    validate_package_name,
    verify_package,
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_checksum_inventory_rejects_traversal_and_duplicates():
    digest = "a" * 64
    with pytest.raises(UpdateError):
        parse_checksums(f"{digest}  ../package.tar.gz\n")
    with pytest.raises(UpdateError):
        parse_checksums(f"{digest}  package.tar.gz\n{digest}  package.tar.gz\n")


def test_package_validation_rejects_wrong_platform_and_architecture():
    package = Path("nmap-flow-analyzer-1.3.0-rc1-rhel-arm64-portable.tar.gz")
    with mock.patch(
        "nmap_flow_analyzer.update.current_target", return_value=("ubuntu", "x64")
    ), pytest.raises(UpdateError, match="platform"):
        validate_package_name(package)


def test_verify_package_requires_and_checks_sha256():
    with tempfile.TemporaryDirectory() as tmp:
        package = Path(tmp) / "nmap-flow-analyzer-1.3.0-rc1-ubuntu-x64-portable.tar.gz"
        package.write_bytes(b"release")
        with mock.patch(
            "nmap_flow_analyzer.update.current_target", return_value=("ubuntu", "x64")
        ):
            with pytest.raises(UpdateError, match="no trusted SHA-256"):
                verify_package(package)
            with pytest.raises(UpdateError, match="mismatch"):
                verify_package(package, "0" * 64)
            assert verify_package(package, _digest(b"release"))["sha256"] == _digest(
                b"release"
            )


def test_install_portable_zip_is_atomic_and_rejects_traversal():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "nmap-flow-analyzer-1.3.0-rc1-ubuntu-x64-portable.zip"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("nmap-flow-analyzer/bin/app", b"ok")
        target = root / "installed"
        with mock.patch(
            "nmap_flow_analyzer.update.current_target", return_value=("ubuntu", "x64")
        ):
            result = install_portable(package, target, _digest(package.read_bytes()), None)
        assert result["installed_to"] == str(target.resolve())
        assert (target / "nmap-flow-analyzer" / "bin" / "app").read_bytes() == b"ok"

        hostile = root / "nmap-flow-analyzer-1.3.0-rc2-ubuntu-x64-portable.zip"
        with zipfile.ZipFile(hostile, "w") as archive:
            archive.writestr("../escape", b"bad")
        escaped_target = root / "bad-install"
        with mock.patch(
            "nmap_flow_analyzer.update.current_target", return_value=("ubuntu", "x64")
        ), pytest.raises(UpdateError, match="unsafe archive path"):
            install_portable(hostile, escaped_target, _digest(hostile.read_bytes()), None)
        assert not escaped_target.exists()
        assert not (root / "escape").exists()


def test_install_portable_tar_rejects_links():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        package = root / "nmap-flow-analyzer-1.3.0-rc1-rhel-x64-portable.tar.gz"
        with tarfile.open(package, "w:gz") as archive:
            link = tarfile.TarInfo("app/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            archive.addfile(link)
        with mock.patch(
            "nmap_flow_analyzer.update.current_target", return_value=("rhel", "x64")
        ), pytest.raises(UpdateError, match="unsupported archive entry"):
            install_portable(package, root / "installed", _digest(package.read_bytes()), None)


def test_update_help_and_local_verify_do_not_use_network():
    stdout = io.StringIO()
    with mock.patch(
        "urllib.request.urlopen", side_effect=AssertionError("network used")
    ), redirect_stdout(stdout), pytest.raises(SystemExit) as raised:
        main(["update", "--help"])
    assert raised.value.code == 0
    assert "download" in stdout.getvalue()

    with tempfile.TemporaryDirectory() as tmp:
        package = Path(tmp) / "nmap-flow-analyzer-1.3.0-rc1-windows-x64-portable.zip"
        package.write_bytes(b"package")
        output = io.StringIO()
        errors = io.StringIO()
        with mock.patch(
            "nmap_flow_analyzer.update.current_target", return_value=("windows", "x64")
        ), mock.patch(
            "urllib.request.urlopen", side_effect=AssertionError("network used")
        ), redirect_stdout(output), redirect_stderr(errors):
            code = main(["update", "verify", str(package), "--sha256", _digest(b"package"), "--json"])
        assert code == 0
        assert errors.getvalue() == ""
        assert json.loads(output.getvalue())["verified"] is True
