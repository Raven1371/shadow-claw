#!/usr/bin/env python3
"""Offline test runner for nmap-flow-analyzer.

The test suite is written as plain pytest-compatible tests (module-level
``test_*`` functions, ``unittest.mock``, ``tempfile``), so the standard
command works wherever pytest is installed::

    python -m pytest -q

This script exists so the suite can also be run with **no third-party
dependencies at all** (air-gapped build hosts, minimal containers,
pip-restricted environments)::

    python run_tests.py                 # whole suite
    python run_tests.py tests/test_zeek_parser.py
    python run_tests.py -k certificate  # substring filter
    python run_tests.py -v              # list every test

It discovers ``tests/test_*.py``, runs every module-level ``test_*``
function, and reports pass/fail/skip counts with the same semantics as
pytest for this suite. ``pytest.skip()`` calls are honored when pytest is
importable; otherwise the suite's own skip helpers degrade to a printed
SKIP line, which this runner counts.
"""

from __future__ import annotations

import argparse
import importlib
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TESTS_DIR = ROOT / "tests"


class _Skipped(Exception):
    """Raised by the shim when a test calls pytest.skip() without pytest."""


def _install_pytest_shim() -> bool:
    """Provide a minimal 'pytest' module when the real one is absent.

    Returns True when the real pytest is available.
    """
    try:
        import pytest  # noqa: F401
        return True
    except ImportError:
        pass

    import types

    shim = types.ModuleType("pytest")

    def skip(reason: str = "", **_kwargs):
        raise _Skipped(reason)

    class _Raises:
        """Minimal pytest.raises context manager."""

        def __init__(self, expected, match=None):
            self.expected = expected
            self.match = match
            self.value = None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, _tb):
            if exc_type is None:
                raise AssertionError(
                    f"DID NOT RAISE {self.expected}"
                )
            if not issubclass(exc_type, self.expected):
                return False  # propagate the unexpected exception
            self.value = exc
            if self.match is not None:
                import re

                if not re.search(self.match, str(exc)):
                    raise AssertionError(
                        f"exception message did not match {self.match!r}: {exc}"
                    )
            return True

    shim.skip = skip
    shim.raises = _Raises
    shim.fail = lambda reason="": (_ for _ in ()).throw(AssertionError(reason))
    shim.mark = types.SimpleNamespace(
        skipif=lambda *a, **k: (lambda fn: fn),
        parametrize=lambda *a, **k: (lambda fn: fn),
    )
    sys.modules["pytest"] = shim
    return False


def discover(selected) -> list:
    """Return sorted test module names, optionally filtered by path."""
    if selected:
        paths = [Path(item) for item in selected]
    else:
        paths = sorted(TESTS_DIR.glob("test_*.py"))
    modules = []
    for path in paths:
        path = Path(path)
        if not path.is_absolute():
            path = ROOT / path
        if not path.exists():
            print(f"error: no such test file: {path}", file=sys.stderr)
            raise SystemExit(2)
        modules.append(f"tests.{path.stem}")
    return modules


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the nmap-flow-analyzer test suite without pytest."
    )
    parser.add_argument("paths", nargs="*", help="specific tests/test_*.py files")
    parser.add_argument("-k", dest="keyword", default="",
                        help="only run tests whose name contains this substring")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print each test name as it runs")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(ROOT))
    real_pytest = _install_pytest_shim()

    passed = failed = skipped = 0
    failures = []
    for name in discover(args.paths):
        module = importlib.import_module(name)
        for attr in sorted(dir(module)):
            if not attr.startswith("test_"):
                continue
            if args.keyword and args.keyword not in attr:
                continue
            func = getattr(module, attr)
            if not callable(func):
                continue
            label = f"{name}.{attr}"
            try:
                func()
            except _Skipped as exc:
                skipped += 1
                if args.verbose:
                    print(f"SKIP {label}: {exc}")
                continue
            except BaseException as exc:  # noqa: BLE001 - report everything
                if real_pytest and type(exc).__name__ == "Skipped":
                    skipped += 1
                    if args.verbose:
                        print(f"SKIP {label}")
                    continue
                failed += 1
                failures.append(label)
                print(f"FAIL {label}")
                traceback.print_exc(limit=6)
                continue
            passed += 1
            if args.verbose:
                print(f"PASS {label}")

    print()
    if failures:
        print("Failed tests:")
        for label in failures:
            print(f"  - {label}")
    total = passed + failed + skipped
    print(f"{total} collected, {passed} passed, {failed} failed, "
          f"{skipped} skipped")
    if not real_pytest:
        print("(pytest was not installed; ran with the built-in offline "
              "runner. 'python -m pytest -q' gives identical results where "
              "pytest is available.)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
