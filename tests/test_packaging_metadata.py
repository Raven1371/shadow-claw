"""Regression tests for authoritative Python package metadata."""

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on supported Python 3.9/3.10 CI
    tomllib = None

from nmap_flow_analyzer import __version__


ROOT = Path(__file__).resolve().parents[1]


def _metadata():
    if tomllib is None:
        import pytest

        pytest.skip("tomllib metadata validation requires Python 3.11+")
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def test_pyproject_is_authoritative_for_version_and_entry_point():
    project = _metadata()["project"]
    assert project["version"] == __version__ == "1.6.0.dev0"
    assert project["scripts"]["nmap-flow-analyzer"] == (
        "nmap_flow_analyzer.cli:main"
    )


def test_legacy_runtime_requirements_match_pyproject_dependencies():
    project_dependencies = {
        requirement.split(">=")[0].lower()
        for requirement in _metadata()["project"]["dependencies"]
    }
    legacy_dependencies = {
        line.split(">=")[0].strip().lower()
        for line in (ROOT / "requirements.txt").read_text("utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert legacy_dependencies == project_dependencies


def test_pytest_is_development_only_dependency():
    metadata = _metadata()
    runtime = "\n".join(metadata["project"]["dependencies"]).lower()
    development = "\n".join(
        metadata["project"]["optional-dependencies"]["dev"]
    ).lower()
    assert "pytest" not in runtime
    assert "pytest" in development

