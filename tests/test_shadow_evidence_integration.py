from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from nmap_flow_analyzer.cli import main
from nmap_flow_analyzer.shadow_evidence import (
    export_shadow_evidence,
    import_shadow_evidence,
    verify_shadow_evidence,
)
from shadow_core.evidence import inspect_package
from shadow_core.hashing import sha256_bytes

ROOT = Path(__file__).resolve().parents[1]


def _staging(root: Path) -> Path:
    staging = root / "staging"
    staging.mkdir()
    source = ROOT / "examples" / "sample-output-combined" / "normalized_data.json"
    shutil.copyfile(source, staging / "normalized_data.json")
    return staging


def test_export_validate_and_import_round_trip() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        staging = _staging(root)
        source_xml = ROOT / "examples" / "sample-scan.xml"
        package = export_shadow_evidence(
            staging,
            source_xml,
            [ROOT / "examples" / "zeek-sample"],
            "case-integration",
            "Integration case",
        )
        validation = verify_shadow_evidence(package)
        assert validation["valid"]
        inspection = inspect_package(package)
        manifest = inspection["manifest"]
        assert manifest["producer"] == "shadow-claw"
        assert manifest["event_count"] > 0
        assert manifest["asset_count"] > 0
        assert manifest["service_count"] > 0
        assert manifest["flow_count"] > 0
        destination = import_shadow_evidence(package, root / "imported")
        assert (destination / "case.json").is_file()
        assert (destination / "normalized" / "events.jsonl").is_file()


def test_original_evidence_and_hashes_are_preserved() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        staging = _staging(root)
        source_xml = ROOT / "examples" / "sample-scan.xml"
        package = export_shadow_evidence(staging, source_xml, [], "case-hash", "Hash case")
        with zipfile.ZipFile(package) as archive:
            raw = archive.read("evidence/other/nmap.xml")
            assert raw == source_xml.read_bytes()
            manifest = json.loads(archive.read("manifest.json"))
            record = next(item for item in manifest["files"] if item["path"] == "evidence/other/nmap.xml")
            assert record["sha256"] == sha256_bytes(source_xml.read_bytes())


def test_cli_verify_and_import_modes() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        package = export_shadow_evidence(
            _staging(root), ROOT / "examples" / "sample-scan.xml", [], "case-cli", "CLI case"
        )
        assert main(["--verify-shadow-evidence", str(package)]) == 0
        destination = root / "cli-import"
        assert main(["--import-shadow-evidence", str(package), "--output-dir", str(destination)]) == 0
        assert (destination / "manifest.json").is_file()


def test_import_and_verify_modes_do_not_require_nmap_input() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        package = export_shadow_evidence(
            _staging(root), ROOT / "examples" / "sample-scan.xml", [], "case-no-input", "No input"
        )
        assert main(["--verify-shadow-evidence", str(package)]) == 0


def test_both_console_commands_share_entry_point() -> None:
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["scripts"]["shadow-claw"] == project["scripts"]["nmap-flow-analyzer"]
    assert project["dependencies"][-1] == "shadow-core>=0.3.0.dev0,<0.4"
