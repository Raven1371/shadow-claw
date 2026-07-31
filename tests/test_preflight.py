"""Offline doctor/preflight command coverage."""

import json
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

from nmap_flow_analyzer.cli import main
from nmap_flow_analyzer.preflight import Check, discover_graphviz, run_checks


def test_preflight_json_is_machine_readable_and_offline(capsys):
    with mock.patch(
        "nmap_flow_analyzer.preflight.run_checks",
        return_value=[Check("Application", "pass", "ok")],
    ), mock.patch("socket.create_connection", side_effect=AssertionError("network used")):
        assert main(["preflight", "--json", "--non-interactive"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["network_access_performed"] is False
    assert payload["status"] == "ready"


def test_doctor_and_preflight_are_aliases(capsys):
    with mock.patch(
        "nmap_flow_analyzer.preflight.run_checks",
        return_value=[Check("Application", "pass", "ok")],
    ):
        assert main(["doctor", "--non-interactive"]) == 0
    output = capsys.readouterr().out
    assert "No automatic update checks are performed." in output
    assert "Use the update command" in output


def test_critical_failure_returns_nonzero(capsys):
    with mock.patch(
        "nmap_flow_analyzer.preflight.run_checks",
        return_value=[Check("Temporary directory", "fail", "blocked", True)],
    ):
        assert main(["preflight", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "failed"


def test_graphviz_resolution_prefers_explicit_path():
    with tempfile.TemporaryDirectory() as tmp:
        executable = Path(tmp) / ("dot.exe" if __import__("os").name == "nt" else "dot")
        executable.write_bytes(b"placeholder")
        source, found = discover_graphviz(executable)
        assert source == "configured external"
        assert found == executable.resolve()


def test_missing_graphviz_is_noncritical():
    with mock.patch("nmap_flow_analyzer.preflight.discover_graphviz", return_value=("unavailable", None)):
        checks = run_checks()
    graphviz = next(check for check in checks if check.name == "Graphviz")
    assert graphviz.status == "warning"
    assert graphviz.critical is False


def test_graphviz_render_test_is_bounded_and_checks_both_formats():
    completed = subprocess.CompletedProcess(["dot"], 0, "", "dot version test")
    with mock.patch(
        "nmap_flow_analyzer.preflight.discover_graphviz",
        return_value=("system PATH", Path("dot")),
    ), mock.patch("nmap_flow_analyzer.preflight.subprocess.run", return_value=completed) as run:
        checks = run_checks(graphviz_timeout=3)
    assert any(check.name == "Graphviz SVG render" for check in checks)
    assert any(check.name == "Graphviz PNG render" for check in checks)
    assert all(call.kwargs.get("timeout") == 3 for call in run.call_args_list)
