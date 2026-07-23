"""Stale-diagram regression tests: a preexisting SVG must never be reused."""

import subprocess
import tempfile
from pathlib import Path
from unittest import mock

from nmap_flow_analyzer import diagrams
from nmap_flow_analyzer.cli import main
from nmap_flow_analyzer.diagrams import DiagramResult
from nmap_flow_analyzer.flow_analysis import AnalysisOptions
from nmap_flow_analyzer.reports import write_html_report
from tests.fixtures import SINGLE_HOST_XML, base_config, run_pipeline

MALICIOUS_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg">\n'
    "  <script>alert(1)</script>\n"
    "</svg>\n"
)


def _seed_run(tmp: Path, out: Path) -> None:
    scan = tmp / "scan.xml"
    scan.write_text(SINGLE_HOST_XML, encoding="utf-8")
    assert main(
        ["--input", str(scan), "--output-dir", str(out),
         "--scanner-ip", "192.168.1.50"]
    ) == 0


def _rerun(tmp: Path, out: Path) -> int:
    return main(
        ["--input", str(tmp / "scan.xml"), "--output-dir", str(out),
         "--scanner-ip", "192.168.1.50", "--overwrite"]
    )


def _plant_malicious_svg(out: Path) -> None:
    (out / "data_flow_diagram.svg").write_text(MALICIOUS_SVG, encoding="utf-8")


def _assert_clean_report(out: Path) -> None:
    html = (out / "analysis_report.html").read_text(encoding="utf-8")
    assert "alert(1)" not in html
    assert MALICIOUS_SVG.strip() not in html
    assert 'src="data_flow_diagram.svg"' not in html  # no stale reference
    assert "Diagram image rendering was unavailable for this run" in html


def test_old_svg_replaced_when_render_succeeds():
    import shutil as real_shutil

    if not real_shutil.which("dot"):  # pragma: no cover
        return
    with tempfile.TemporaryDirectory() as tmp:
        tmp, out = Path(tmp), Path(tmp) / "out"
        _seed_run(tmp, out)
        _plant_malicious_svg(out)
        assert _rerun(tmp, out) == 0
        svg = (out / "data_flow_diagram.svg").read_text(encoding="utf-8")
        assert "alert(1)" not in svg  # freshly rendered, old content gone
        html = (out / "analysis_report.html").read_text(encoding="utf-8")
        assert 'src="data_flow_diagram.svg"' in html  # current-run image
        assert "alert(1)" not in html


def test_old_malicious_svg_with_graphviz_unavailable():
    with tempfile.TemporaryDirectory() as tmp:
        tmp, out = Path(tmp), Path(tmp) / "out"
        _seed_run(tmp, out)
        _plant_malicious_svg(out)
        with mock.patch.object(diagrams.shutil, "which", return_value=None):
            assert _rerun(tmp, out) == 0
        assert not (out / "data_flow_diagram.svg").exists()  # stale removed
        assert not (out / "data_flow_diagram.png").exists()
        _assert_clean_report(out)
        # Current DOT/Mermaid sources were still generated.
        assert (out / "data_flow_diagram.dot").exists()
        assert (out / "data_flow_diagram.mmd").exists()


def test_old_svg_with_graphviz_timeout():
    with tempfile.TemporaryDirectory() as tmp:
        tmp, out = Path(tmp), Path(tmp) / "out"
        _seed_run(tmp, out)
        _plant_malicious_svg(out)
        with mock.patch.object(diagrams.shutil, "which", return_value="/usr/bin/dot"), \
             mock.patch.object(
                 diagrams.subprocess, "run",
                 side_effect=subprocess.TimeoutExpired(cmd="dot", timeout=1),
             ):
            assert _rerun(tmp, out) == 0
        assert not (out / "data_flow_diagram.svg").exists()
        _assert_clean_report(out)


def test_old_svg_with_graphviz_nonzero_exit():
    fake = subprocess.CompletedProcess(args=["dot"], returncode=1,
                                       stdout="", stderr="boom")
    with tempfile.TemporaryDirectory() as tmp:
        tmp, out = Path(tmp), Path(tmp) / "out"
        _seed_run(tmp, out)
        _plant_malicious_svg(out)
        with mock.patch.object(diagrams.shutil, "which", return_value="/usr/bin/dot"), \
             mock.patch.object(diagrams.subprocess, "run", return_value=fake):
            assert _rerun(tmp, out) == 0
        assert not (out / "data_flow_diagram.svg").exists()
        _assert_clean_report(out)


def _write_report(tmp: Path, diagram) -> str:
    data = run_pipeline(SINGLE_HOST_XML, base_config(), AnalysisOptions())
    path = tmp / "analysis_report.html"
    write_html_report(
        path, data["metadata"], data["hosts"], data["records"],
        data["flows"], data["inbound"], data["outbound"], [], [], [],
        diagram=diagram,
    )
    return path.read_text(encoding="utf-8")


def test_diagram_result_flag_controls_report_inclusion():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        svg = tmp / "data_flow_diagram.svg"
        svg.write_text("<svg xmlns='http://www.w3.org/2000/svg'/>",
                       encoding="utf-8")
        # svg_rendered=True from THIS run -> referenced via <img>.
        ok = DiagramResult(svg_path=svg, svg_rendered=True)
        html = _write_report(tmp, ok)
        assert '<img src="data_flow_diagram.svg"' in html
        # Same file on disk but svg_rendered=False -> NOT referenced.
        stale = DiagramResult(svg_path=svg, svg_rendered=False,
                              render_error="Graphviz unavailable")
        html = _write_report(tmp, stale)
        assert 'src="data_flow_diagram.svg"' not in html
        assert "Diagram image rendering was unavailable" in html
        assert "Graphviz unavailable" in html


def test_preexisting_file_alone_is_never_accepted():
    # A file merely existing on disk (e.g. older mtime, prior run) does not
    # get referenced: only the current-run result object grants inclusion.
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "data_flow_diagram.svg").write_text(MALICIOUS_SVG,
                                                   encoding="utf-8")
        html = _write_report(tmp, None)  # no DiagramResult at all
        assert "alert(1)" not in html
        assert 'src="data_flow_diagram.svg"' not in html


def test_symlinked_current_svg_not_referenced():
    import os

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        external = tmp / "external.svg"
        external.write_text(MALICIOUS_SVG, encoding="utf-8")
        link = tmp / "data_flow_diagram.svg"
        try:
            os.symlink(external, link)
        except (OSError, NotImplementedError):
            return  # platform cannot create symlinks
        sneaky = DiagramResult(svg_path=link, svg_rendered=True)
        html = _write_report(tmp, sneaky)
        assert 'src="data_flow_diagram.svg"' not in html
