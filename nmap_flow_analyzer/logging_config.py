"""Structured logging configuration.

Console logging is INFO (or DEBUG with ``--verbose``); a UTF-8 file handler
always writes DEBUG detail to ``execution.log`` inside the output directory.
"""

from __future__ import annotations

import logging
from pathlib import Path

LOGGER_NAME = "nmap_flow_analyzer"


def setup_logging(output_dir: Path, verbose: bool = False) -> logging.Logger:
    """Configure and return the application logger (idempotent)."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for handler in list(logger.handlers):  # re-runs in the same process
        logger.removeHandler(handler)
        handler.close()

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
    logger.addHandler(console)

    try:
        file_handler = logging.FileHandler(
            output_dir / "execution.log", mode="w", encoding="utf-8"
        )
    except OSError as exc:  # keep running even if the log file can't be opened
        logger.warning("Could not open execution.log: %s", exc)
    else:
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
        )
        logger.addHandler(file_handler)
    return logger
