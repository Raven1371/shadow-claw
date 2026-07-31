"""Tests for release-gate skip classification."""

from scripts.run_pytest_with_skip_report import classify_skip


def test_linux_security_skip_blocks_release():
    classification, acceptable = classify_skip(
        "tests/test_output_security.py::test_fifo_destination_rejected",
        "platform has no os.mkfifo",
        "Linux-6.8",
    )
    assert classification == "security-gate skip"
    assert acceptable is False


def test_windows_symlink_limitation_is_explicitly_classified():
    classification, acceptable = classify_skip(
        "tests/test_zeek_parser.py::test_symlinked_files_and_directories_skipped",
        "symlink creation requires Windows developer mode or privilege",
        "Windows-11",
    )
    assert classification == "security-gate skip"
    assert acceptable is True


def test_linux_graphviz_skip_blocks_release():
    classification, acceptable = classify_skip(
        "tests/test_output_security.py::test_graphviz_partial_output_not_published",
        "Graphviz not installed",
        "rocky-linux-9",
    )
    assert classification == "security-gate skip"
    assert acceptable is False


def test_optional_dependency_skip_is_identified():
    classification, acceptable = classify_skip(
        "tests/test_excel_export.py::test_excel_output",
        "openpyxl not installed",
        "Windows-11",
    )
    assert classification == "expected optional dependency limitation"
    assert acceptable is True


def test_unknown_skip_blocks_release():
    classification, acceptable = classify_skip(
        "tests/test_parser.py::test_unknown",
        "some unexplained condition",
        "Linux-6.8",
    )
    assert classification == "unexpected skip"
    assert acceptable is False
