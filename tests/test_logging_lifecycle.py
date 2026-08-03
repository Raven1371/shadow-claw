"""Cross-platform regression coverage for invocation-owned logging."""

import logging
import shutil
import tempfile
from pathlib import Path
from unittest import mock

from nmap_flow_analyzer.cli import main
from nmap_flow_analyzer.logging_config import LOGGER_NAME
from nmap_flow_analyzer.reports import write_csv, write_json
from nmap_flow_analyzer.models import ServiceRecord
from tests.fixtures import SINGLE_HOST_XML


def _run(base: Path, name: str = "out", extra=None):
    scan = base / "scan.xml"
    scan.write_text(SINGLE_HOST_XML, encoding="utf-8")
    out = base / name
    code = main([
        "--input", str(scan), "--output-dir", str(out),
        "--scanner-ip", "192.168.1.50", *(extra or []),
    ])
    return code, out


def _analyzer_file_handlers():
    return [
        handler for handler in logging.getLogger(LOGGER_NAME).handlers
        if isinstance(handler, logging.FileHandler)
    ]


def test_success_releases_log_and_allows_immediate_rename_delete():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        code, out = _run(base)
        assert code == 0
        assert (out / "execution.log").is_file()
        assert not _analyzer_file_handlers()
        renamed = base / "renamed"
        out.rename(renamed)
        shutil.rmtree(renamed)
        assert not renamed.exists()


def test_repeated_runs_do_not_accumulate_handlers_or_duplicate_lines():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        first_code, first = _run(base, "first")
        second_code, second = _run(base, "second")
        assert first_code == second_code == 0
        assert not _analyzer_file_handlers()
        for output in (first, second):
            text = (output / "execution.log").read_text(encoding="utf-8")
            assert text.count("nmap-flow-analyzer 1.6.0.dev0 starting") == 1
            shutil.rmtree(output)


def test_failure_after_logging_releases_file_and_reuses_output_path():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        broken = base / "broken.xml"
        broken.write_text("<not-nmap>", encoding="utf-8")
        out = base / "out"
        code = main(["--input", str(broken), "--output-dir", str(out)])
        assert code == 2
        assert not _analyzer_file_handlers()
        shutil.rmtree(out)
        assert not out.exists()
        good = base / "scan.xml"
        good.write_text(SINGLE_HOST_XML, encoding="utf-8")
        assert main([
            "--input", str(good), "--output-dir", str(out),
            "--scanner-ip", "192.168.1.50",
        ]) == 0
        shutil.rmtree(out)


def test_cleanup_preserves_parent_and_unrelated_handlers():
    app_logger = logging.getLogger(LOGGER_NAME)
    parent_handler = logging.StreamHandler()
    unrelated = logging.getLogger("unrelated.application")
    unrelated_handler = logging.StreamHandler()
    app_logger.addHandler(parent_handler)
    unrelated.addHandler(unrelated_handler)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            code, out = _run(Path(tmp))
            assert code == 0
            assert parent_handler in app_logger.handlers
            assert unrelated_handler in unrelated.handlers
            assert parent_handler.stream is not None
            assert unrelated_handler.stream is not None
            shutil.rmtree(out)
    finally:
        app_logger.removeHandler(parent_handler)
        unrelated.removeHandler(unrelated_handler)
        parent_handler.close()
        unrelated_handler.close()


def test_validation_failure_before_logging_does_not_touch_parent_handler():
    app_logger = logging.getLogger(LOGGER_NAME)
    parent_handler = logging.StreamHandler()
    app_logger.addHandler(parent_handler)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            missing = base / "missing.xml"
            out = base / "out"
            assert main(["--input", str(missing), "--output-dir", str(out)]) == 2
            assert parent_handler in app_logger.handlers
            assert parent_handler.stream is not None
            if out.exists():
                shutil.rmtree(out)
    finally:
        app_logger.removeHandler(parent_handler)
        parent_handler.close()


def test_report_generation_failure_releases_log_and_preserves_parent():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        out = base / "out"
        with mock.patch(
            "nmap_flow_analyzer.cli.write_html_report",
            side_effect=RuntimeError("injected report failure"),
        ):
            code, _ = _run(base, "out")
        assert code == 1
        assert not _analyzer_file_handlers()
        shutil.rmtree(out)


def test_zeek_required_failure_releases_log():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        empty_zeek = base / "zeek"
        empty_zeek.mkdir()
        code, out = _run(
            base, "out",
            ["--zeek-dir", str(empty_zeek), "--zeek-required"],
        )
        assert code == 2
        assert not _analyzer_file_handlers()
        shutil.rmtree(out)


def test_approved_singular_row_and_record_wording():
    records = []

    class RecordingHandler(logging.Handler):
        def emit(self, record):
            records.append(record)

    logger = logging.getLogger(LOGGER_NAME)
    handler = RecordingHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            row = ServiceRecord()
            write_csv(base / "one.csv", [row], ServiceRecord)
            write_json(base / "one.json", [row])
    finally:
        logger.removeHandler(handler)
        handler.close()
    messages = [record.getMessage() for record in records]
    assert any("one.csv (1 row)" in message for message in messages)
    assert any("one.json (1 record)" in message for message in messages)
    assert all("1 rows" not in message for message in messages)
    assert all("1 records" not in message for message in messages)
