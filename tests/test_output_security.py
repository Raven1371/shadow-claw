"""Output-security regression tests: symlinks, special files, atomic writes."""

import os
import tempfile
from pathlib import Path
from unittest import mock

from nmap_flow_analyzer.cli import main
from nmap_flow_analyzer.output_safety import (
    OutputSafetyError,
    atomic_write_text,
    validate_output_destination,
    validate_output_directory,
)
from tests.fixtures import SINGLE_HOST_XML

EXTERNAL_CONTENT = "EXTERNAL FILE - MUST NOT CHANGE\n"


def _symlink_unsupported() -> str:
    try:
        with tempfile.TemporaryDirectory() as tmp:
            os.symlink(Path(tmp) / "a", Path(tmp) / "b")
        return ""
    except (OSError, NotImplementedError, AttributeError) as exc:
        return f"platform cannot create symbolic links: {exc}"


SKIP_REASON = _symlink_unsupported()


def _skip(reason: str) -> None:
    try:
        import pytest
        pytest.skip(reason)
    except (ImportError, AttributeError, TypeError):
        print(f"SKIP: {reason}")


def _first_run(tmp: Path, out: Path, extra=None) -> int:
    scan = tmp / "scan.xml"
    if not scan.exists():
        scan.write_text(SINGLE_HOST_XML, encoding="utf-8")
    return main(
        ["--input", str(scan), "--output-dir", str(out),
         "--scanner-ip", "192.168.1.50"] + (extra or [])
    )


def _symlink_attack(name: str, extra=None) -> None:
    """Symlink one generated output to an external file; run; verify safety."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        external = tmp / "external.txt"
        external.write_text(EXTERNAL_CONTENT, encoding="utf-8")
        out = tmp / "out"
        out.mkdir()
        os.symlink(external, out / name)
        code = _first_run(tmp, out, ["--overwrite"] + (extra or []))
        # The run must fail safely (or reject the artifact) and the external
        # target must be byte-identical afterwards.
        assert code == 2, f"{name}: expected safe refusal, got rc={code}"
        assert external.read_text(encoding="utf-8") == EXTERNAL_CONTENT, name
        assert (out / name).is_symlink(), f"{name}: symlink was replaced"


def test_symlinked_html_report_rejected():
    if SKIP_REASON:
        return _skip(SKIP_REASON)
    _symlink_attack("analysis_report.html")


def test_symlinked_findings_summary_rejected():
    if SKIP_REASON:
        return _skip(SKIP_REASON)
    _symlink_attack("findings_summary.md")


def test_symlinked_normalized_json_rejected():
    if SKIP_REASON:
        return _skip(SKIP_REASON)
    _symlink_attack("normalized_data.json")


def test_symlinked_csv_rejected():
    if SKIP_REASON:
        return _skip(SKIP_REASON)
    _symlink_attack("inbound_exceptions.csv")


def test_symlinked_dot_and_mermaid_rejected():
    if SKIP_REASON:
        return _skip(SKIP_REASON)
    _symlink_attack("data_flow_diagram.dot")
    _symlink_attack("data_flow_diagram.mmd")


def test_symlinked_svg_and_png_rejected():
    if SKIP_REASON:
        return _skip(SKIP_REASON)
    _symlink_attack("data_flow_diagram.svg")
    _symlink_attack("data_flow_diagram.png")


def test_symlinked_excel_rejected():
    if SKIP_REASON:
        return _skip(SKIP_REASON)
    _symlink_attack("firewall_exceptions.xlsx", extra=["--excel"])


def test_symlinked_execution_log_rejected():
    if SKIP_REASON:
        return _skip(SKIP_REASON)
    _symlink_attack("execution.log")


def test_symlinked_run_manifest_rejected():
    if SKIP_REASON:
        return _skip(SKIP_REASON)
    _symlink_attack("run_manifest.json")


def test_symlinked_output_directory_rejected():
    if SKIP_REASON:
        return _skip(SKIP_REASON)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        real = tmp / "real-target"
        real.mkdir()
        link = tmp / "out-link"
        os.symlink(real, link, target_is_directory=True)
        code = _first_run(tmp, link)
        assert code == 2
        assert list(real.iterdir()) == []  # nothing written through the link


def test_destination_resolving_outside_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        root = validate_output_directory(Path(tmp))
        try:
            validate_output_destination(root, root / ".." / "evil.txt")
        except OutputSafetyError:
            pass
        else:  # pragma: no cover
            raise AssertionError("traversal accepted")


def test_directory_in_place_of_report_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        out = tmp / "out"
        out.mkdir()
        (out / "analysis_report.html").mkdir()
        code = _first_run(tmp, out, ["--overwrite"])
        assert code == 2
        assert (out / "analysis_report.html").is_dir()  # untouched


def test_fifo_in_place_of_report_rejected():
    if not hasattr(os, "mkfifo"):
        return _skip("platform has no os.mkfifo")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        out = tmp / "out"
        out.mkdir()
        os.mkfifo(out / "findings_summary.md")
        code = _first_run(tmp, out, ["--overwrite"])
        assert code == 2


def test_normal_regular_file_with_overwrite_is_replaced():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        out = tmp / "out"
        assert _first_run(tmp, out) == 0
        first = (out / "analysis_report.html").read_bytes()
        assert _first_run(tmp, out, ["--overwrite"]) == 0
        assert (out / "analysis_report.html").exists()
        assert not (out / "analysis_report.html").is_symlink()
        assert len(first) > 0


# ---------------------------------------------------------------------------
# Atomic-write guarantees
# ---------------------------------------------------------------------------

def test_atomic_text_write_rejects_symlink_destination():
    if SKIP_REASON:
        return _skip(SKIP_REASON)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        external = tmp / "external.txt"
        external.write_text(EXTERNAL_CONTENT, encoding="utf-8")
        link = tmp / "report.md"
        os.symlink(external, link)
        try:
            atomic_write_text(link, "new content")
        except OutputSafetyError:
            pass
        else:  # pragma: no cover
            raise AssertionError("symlink destination accepted")
        assert external.read_text(encoding="utf-8") == EXTERNAL_CONTENT
        assert not list(tmp.glob(".nfa-tmp-*"))  # temp cleaned


def test_existing_file_intact_until_replacement_succeeds():
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "data_flow_diagram.dot"
        target.write_text("ORIGINAL", encoding="utf-8")
        with mock.patch("os.replace", side_effect=OSError("boom")):
            try:
                atomic_write_text(target, "NEW")
            except OSError:
                pass
        assert target.read_text(encoding="utf-8") == "ORIGINAL"
        assert not list(Path(tmp).glob(".nfa-tmp-*"))


def test_excel_failure_does_not_corrupt_previous_workbook():
    try:
        import openpyxl
    except ImportError:  # pragma: no cover
        return _skip("openpyxl not installed")
    from nmap_flow_analyzer.excel_export import export_excel
    from nmap_flow_analyzer.flow_analysis import AnalysisOptions
    from tests.fixtures import base_config, run_pipeline

    data = run_pipeline(SINGLE_HOST_XML, base_config(), AnalysisOptions())
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "firewall_exceptions.xlsx"
        assert export_excel(
            path, data["metadata"], data["hosts"], data["records"],
            data["flows"], data["inbound"], data["outbound"], [], [], [],
        ) is None
        original = path.read_bytes()
        with mock.patch.object(
            openpyxl.workbook.workbook.Workbook, "save",
            side_effect=OSError("disk full"),
        ):
            message = export_excel(
                path, data["metadata"], data["hosts"], data["records"],
                data["flows"], data["inbound"], data["outbound"], [], [], [],
            )
        assert message is not None
        assert path.read_bytes() == original  # byte-identical, not truncated
        assert not list(Path(tmp).glob(".nfa-tmp-*"))


def test_graphviz_partial_output_not_published():
    import shutil as real_shutil

    if not real_shutil.which("dot"):  # pragma: no cover
        return _skip("Graphviz not installed")
    import subprocess

    from nmap_flow_analyzer import diagrams
    from nmap_flow_analyzer.flow_analysis import AnalysisOptions
    from tests.fixtures import base_config, run_pipeline

    data = run_pipeline(SINGLE_HOST_XML, base_config(), AnalysisOptions())
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        with mock.patch.object(
            diagrams.subprocess, "run",
            side_effect=subprocess.TimeoutExpired(cmd="dot", timeout=1),
        ):
            result = diagrams.write_diagrams(
                data["hosts"], data["flows"], data["metadata"],
                base_config(), out, graphviz_timeout=1,
            )
        assert not result.svg_rendered
        assert not (out / "data_flow_diagram.svg").exists()
        assert not list(out.glob(".nfa-tmp-*"))  # partial render removed
        assert (out / "data_flow_diagram.dot").exists()  # sources kept
        assert (out / "data_flow_diagram.mmd").exists()
