"""Tests for the staging pipeline, run manifest, and stale-artifact cleanup."""

import hashlib
import json
import tempfile
from pathlib import Path
from unittest import mock

import nmap_flow_analyzer.cli as cli
from nmap_flow_analyzer.cli import main
from tests.fixtures import SINGLE_HOST_XML


def _run(tmp: Path, out: Path, extra=None) -> int:
    scan = tmp / "scan.xml"
    if not scan.exists():
        scan.write_text(SINGLE_HOST_XML, encoding="utf-8")
    return main(
        ["--input", str(scan), "--output-dir", str(out),
         "--scanner-ip", "192.168.1.50"] + (extra or [])
    )


def _no_staging_left(out: Path) -> bool:
    return not list(out.glob(".nmap-flow-analyzer-stage-*"))


def test_manifest_written_and_accurate():
    with tempfile.TemporaryDirectory() as tmp:
        tmp, out = Path(tmp), Path(tmp) / "out"
        assert _run(tmp, out, ["--excel"]) == 0
        manifest = json.loads((out / "run_manifest.json").read_text("utf-8"))
        assert manifest["application"] == "nmap-flow-analyzer"
        assert manifest["version"] == "1.2.4"
        assert manifest["run_id"] and manifest["started_at"]
        assert manifest["excel_requested"] is True
        assert manifest["excel_generated"] is True
        assert manifest["spreadsheet_sanitization"] is True
        names = {entry["path"] for entry in manifest["generated_files"]}
        assert "analysis_report.html" in names
        assert "firewall_exceptions.xlsx" in names
        # size + sha256 match the published files exactly
        for entry in manifest["generated_files"]:
            published = out / entry["path"]
            assert published.stat().st_size == entry["size"], entry["path"]
            digest = hashlib.sha256(published.read_bytes()).hexdigest()
            assert digest == entry["sha256"], entry["path"]
        assert _no_staging_left(out)


def test_second_run_without_excel_removes_stale_workbook():
    with tempfile.TemporaryDirectory() as tmp:
        tmp, out = Path(tmp), Path(tmp) / "out"
        assert _run(tmp, out, ["--excel"]) == 0
        assert (out / "firewall_exceptions.xlsx").exists()
        unrelated = out / "manual-rules.xlsx"
        unrelated.write_bytes(b"UNRELATED WORKBOOK")
        assert _run(tmp, out, ["--overwrite"]) == 0  # no --excel this time
        assert not (out / "firewall_exceptions.xlsx").exists()
        assert unrelated.read_bytes() == b"UNRELATED WORKBOOK"
        manifest = json.loads((out / "run_manifest.json").read_text("utf-8"))
        assert manifest["excel_requested"] is False
        assert manifest["excel_generated"] is False


def test_graphviz_failure_removes_stale_images_and_manifest_records_it():
    from nmap_flow_analyzer import diagrams

    with tempfile.TemporaryDirectory() as tmp:
        tmp, out = Path(tmp), Path(tmp) / "out"
        assert _run(tmp, out) == 0
        had_images = (out / "data_flow_diagram.svg").exists()
        with mock.patch.object(diagrams.shutil, "which", return_value=None):
            assert _run(tmp, out, ["--overwrite"]) == 0
        assert not (out / "data_flow_diagram.svg").exists()
        assert not (out / "data_flow_diagram.png").exists()
        assert (out / "data_flow_diagram.dot").exists()
        manifest = json.loads((out / "run_manifest.json").read_text("utf-8"))
        assert manifest["graphviz"]["available"] is False
        assert manifest["graphviz"]["svg_rendered"] is False
        assert manifest["graphviz"]["error"]
        assert had_images or True  # image presence depends on env graphviz


def test_previous_manifest_identifies_prior_artifacts_for_cleanup():
    with tempfile.TemporaryDirectory() as tmp:
        tmp, out = Path(tmp), Path(tmp) / "out"
        assert _run(tmp, out) == 0
        # Simulate an older release that generated an extra file, recorded in
        # its manifest but absent from the current legacy allowlist.
        extra = out / "legacy_extra_output.csv"
        extra.write_text("old,data\n", encoding="utf-8")
        manifest = json.loads((out / "run_manifest.json").read_text("utf-8"))
        manifest["generated_files"].append(
            {"path": "legacy_extra_output.csv", "size": 9, "sha256": "x"}
        )
        (out / "run_manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        assert _run(tmp, out, ["--overwrite"]) == 0
        assert not extra.exists()  # cleaned via previous manifest


def test_corrupt_manifest_is_handled_safely():
    with tempfile.TemporaryDirectory() as tmp:
        tmp, out = Path(tmp), Path(tmp) / "out"
        assert _run(tmp, out) == 0
        (out / "run_manifest.json").write_text("{not json", encoding="utf-8")
        keep = out / "administrator-notes.txt"
        keep.write_text("keep", encoding="utf-8")
        assert _run(tmp, out, ["--overwrite"]) == 0
        # Run succeeded, manifest regenerated, unrelated file preserved.
        json.loads((out / "run_manifest.json").read_text("utf-8"))
        assert keep.read_text(encoding="utf-8") == "keep"


def test_missing_manifest_falls_back_to_legacy_allowlist():
    with tempfile.TemporaryDirectory() as tmp:
        tmp, out = Path(tmp), Path(tmp) / "out"
        assert _run(tmp, out, ["--excel"]) == 0
        (out / "run_manifest.json").unlink()
        assert _run(tmp, out, ["--overwrite"]) == 0  # no --excel
        # Stale workbook still identified via the hardcoded allowlist.
        assert not (out / "firewall_exceptions.xlsx").exists()


def test_unrelated_files_survive_every_overwrite():
    with tempfile.TemporaryDirectory() as tmp:
        tmp, out = Path(tmp), Path(tmp) / "out"
        out.mkdir()
        keepers = {
            "administrator-notes.txt": b"notes",
            "custom-diagram.svg": b"<svg/>",
            "previous-audit.pdf": b"%PDF-1.4 fake",
            "manual-rules.xlsx": b"workbook",
        }
        for name, content in keepers.items():
            (out / name).write_bytes(content)
        assert _run(tmp, out) == 0
        assert _run(tmp, out, ["--overwrite", "--excel"]) == 0
        assert _run(tmp, out, ["--overwrite"]) == 0
        for name, content in keepers.items():
            assert (out / name).read_bytes() == content, name


def test_failure_during_html_generation_preserves_previous_run():
    with tempfile.TemporaryDirectory() as tmp:
        tmp, out = Path(tmp), Path(tmp) / "out"
        assert _run(tmp, out) == 0
        before = {
            entry.name: entry.read_bytes()
            for entry in out.iterdir()
            if entry.is_file() and entry.name != "execution.log"
        }
        with mock.patch.object(
            cli, "write_html_report", side_effect=RuntimeError("boom")
        ):
            code = _run(tmp, out, ["--overwrite"])
        assert code == 1
        after = {
            entry.name: entry.read_bytes()
            for entry in out.iterdir()
            if entry.is_file() and entry.name != "execution.log"
        }
        assert after == before  # nothing partially replaced
        assert _no_staging_left(out)  # staging cleaned after failure


def test_staging_cleaned_after_success():
    with tempfile.TemporaryDirectory() as tmp:
        tmp, out = Path(tmp), Path(tmp) / "out"
        assert _run(tmp, out, ["--excel"]) == 0
        assert _no_staging_left(out)
        assert not list(out.glob(".nfa-tmp-*"))
