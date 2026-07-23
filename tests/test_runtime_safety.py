"""Tests for large-XML parsing, output-directory policy, and Graphviz safety."""

import subprocess
import tempfile
from pathlib import Path
from unittest import mock

from nmap_flow_analyzer import diagrams
from nmap_flow_analyzer.cli import GENERATED_FILES, check_output_dir, main
from nmap_flow_analyzer.parser import parse_nmap_xml
from nmap_flow_analyzer.reports import atomic_write_text
from tests.fixtures import SINGLE_HOST_XML, XML_FOOTER, XML_HEADER, base_config


# ---------------------------------------------------------------------------
# Large XML
# ---------------------------------------------------------------------------

def _large_xml(count: int) -> str:
    hosts = []
    for i in range(count):
        third, fourth = divmod(i, 250)
        hosts.append(
            f'<host><status state="up" reason="arp-response"/>'
            f'<address addr="10.{third}.{fourth // 250}.{fourth + 1}" addrtype="ipv4"/>'
            f'<hostnames><hostname name="bulk{i}.example.local" type="PTR"/></hostnames>'
            f'<ports><port protocol="tcp" portid="443">'
            f'<state state="open" reason="syn-ack"/>'
            f'<service name="https" method="table"/></port></ports></host>'
        )
    return XML_HEADER + "\n".join(hosts) + XML_FOOTER


def test_large_report_parses_incrementally():
    xml = _large_xml(600)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "large.xml"
        path.write_text(xml, encoding="utf-8")
        metadata, hosts = parse_nmap_xml(path)
    assert len(hosts) == 600
    assert all(h.ports for h in hosts)
    assert metadata.nmap_version == "7.95"


def test_parser_uses_streaming_iterparse():
    import inspect

    from nmap_flow_analyzer import parser as parser_module

    source = inspect.getsource(parser_module)
    assert "iterparse" in source
    assert ".clear()" in source


# ---------------------------------------------------------------------------
# Output directory policy
# ---------------------------------------------------------------------------

def _run_main(tmp: Path, out: Path, extra=None) -> int:
    scan = tmp / "scan.xml"
    if not scan.exists():
        scan.write_text(SINGLE_HOST_XML, encoding="utf-8")
    argv = ["--input", str(scan), "--output-dir", str(out)]
    return main(argv + (extra or []))


def test_new_directory_is_created_and_used():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "fresh"
        assert _run_main(Path(tmp), out) == 0
        assert (out / "analysis_report.html").exists()


def test_existing_empty_directory_is_fine():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "empty"
        out.mkdir()
        assert _run_main(Path(tmp), out) == 0


def test_existing_generated_files_block_without_overwrite():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out"
        assert _run_main(Path(tmp), out) == 0
        assert _run_main(Path(tmp), out) == 2  # refused
        assert _run_main(Path(tmp), out, ["--overwrite"]) == 0


def test_unrelated_files_never_block_and_are_never_touched():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out"
        out.mkdir()
        keep = out / "keep-me.txt"
        keep.write_text("precious", encoding="utf-8")
        assert _run_main(Path(tmp), out) == 0
        assert keep.read_text(encoding="utf-8") == "precious"


def test_check_output_dir_reports_which_files_block():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        (out / "analysis_report.html").write_text("x", encoding="utf-8")
        message = check_output_dir(out, overwrite=False)
        assert message and "analysis_report.html" in message
        assert check_output_dir(out, overwrite=True) is None


def test_atomic_write_cleans_up_after_failure():
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "report.csv"
        with mock.patch("os.replace", side_effect=OSError("disk full")):
            try:
                atomic_write_text(target, "data")
            except OSError:
                pass
            else:  # pragma: no cover
                raise AssertionError("expected OSError")
        leftovers = list(Path(tmp).iterdir())
        assert leftovers == []  # no temp files, no partial report


# ---------------------------------------------------------------------------
# Graphviz safeguards
# ---------------------------------------------------------------------------

def _diagram_inputs():
    import tempfile as _tf

    from nmap_flow_analyzer.flow_analysis import AnalysisOptions
    from tests.fixtures import run_pipeline

    data = run_pipeline(SINGLE_HOST_XML, base_config(), AnalysisOptions())
    return data["hosts"], data["flows"], data["metadata"]


def test_graphviz_unavailable_keeps_sources():
    hosts, flows, metadata = _diagram_inputs()
    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch.object(diagrams.shutil, "which", return_value=None):
            result = diagrams.write_diagrams(
                hosts, flows, metadata, base_config(), Path(tmp)
            )
        assert not result.rendered
        assert "Graphviz" in result.message
        assert (Path(tmp) / "data_flow_diagram.dot").exists()
        assert (Path(tmp) / "data_flow_diagram.mmd").exists()


def test_graphviz_timeout_is_handled():
    hosts, flows, metadata = _diagram_inputs()
    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch.object(diagrams.shutil, "which", return_value="/usr/bin/dot"), \
             mock.patch.object(
                 diagrams.subprocess, "run",
                 side_effect=subprocess.TimeoutExpired(cmd="dot", timeout=1),
             ):
            result = diagrams.write_diagrams(
                hosts, flows, metadata, base_config(), Path(tmp),
                graphviz_timeout=1,
            )
        assert not result.rendered
        assert "timed out" in result.message
        assert (Path(tmp) / "data_flow_diagram.dot").exists()


def test_graphviz_nonzero_exit_is_handled():
    hosts, flows, metadata = _diagram_inputs()
    fake = subprocess.CompletedProcess(args=["dot"], returncode=1, stdout="", stderr="boom")
    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch.object(diagrams.shutil, "which", return_value="/usr/bin/dot"), \
             mock.patch.object(diagrams.subprocess, "run", return_value=fake):
            result = diagrams.write_diagrams(
                hosts, flows, metadata, base_config(), Path(tmp)
            )
        assert not result.rendered
        assert "status 1" in result.message and "boom" in result.message


def test_graphviz_success_renders_images():
    import shutil as real_shutil

    if not real_shutil.which("dot"):  # pragma: no cover - no Graphviz present
        return
    hosts, flows, metadata = _diagram_inputs()
    with tempfile.TemporaryDirectory() as tmp:
        result = diagrams.write_diagrams(
            hosts, flows, metadata, base_config(), Path(tmp)
        )
        assert result.rendered
        assert (Path(tmp) / "data_flow_diagram.svg").exists()
        assert (Path(tmp) / "data_flow_diagram.png").exists()


# ---------------------------------------------------------------------------
# Backward-compatible CLI execution
# ---------------------------------------------------------------------------

def test_minimal_cli_invocation_still_works():
    with tempfile.TemporaryDirectory() as tmp:
        scan = Path(tmp) / "full-scan.xml"
        scan.write_text(SINGLE_HOST_XML, encoding="utf-8")
        out = Path(tmp) / "out"
        assert main(["--input", str(scan), "--output-dir", str(out)]) == 0
        for name in (
            "service_inventory.csv", "inbound_exceptions.csv",
            "outbound_exceptions.csv", "manual_review.csv",
            "findings_summary.md", "analysis_report.html",
            "normalized_data.json",
        ):
            assert (out / name).exists(), name


def test_documented_full_invocation_still_works():
    with tempfile.TemporaryDirectory() as tmp:
        scan = Path(tmp) / "full-scan.xml"
        scan.write_text(SINGLE_HOST_XML, encoding="utf-8")
        out = Path(tmp) / "out"
        code = main([
            "--input", str(scan),
            "--output-dir", str(out),
            "--scanner-ip", "192.168.1.50",
            "--scanner-zone", "Management",
            "--excel",
        ])
        assert code == 0
        assert (out / "firewall_exceptions.xlsx").exists()
