"""Structured logging configuration.

Console logging is INFO (or DEBUG with ``--verbose``); a UTF-8 file handler
always writes DEBUG detail to ``execution.log`` inside the output directory.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

LOGGER_NAME = "nmap_flow_analyzer"
_OWNED_ATTRIBUTE = "_nmap_flow_analyzer_owned"


def _owned_handlers(logger: logging.Logger) -> Iterable[logging.Handler]:
    """Return handlers created by this analyzer, never host-owned handlers."""
    return (
        handler for handler in list(logger.handlers)
        if getattr(handler, _OWNED_ATTRIBUTE, False)
    )


def close_invocation_logging(logger: logging.Logger) -> None:
    """Flush, detach, and close only analyzer-owned invocation handlers."""
    for handler in _owned_handlers(logger):
        try:
            handler.flush()
        finally:
            logger.removeHandler(handler)
            handler.close()


def setup_logging(output_dir: Path, verbose: bool = False) -> logging.Logger:
    """Configure one invocation while preserving host-application handlers."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    # Defensive cleanup for an interrupted or incorrectly embedded prior run.
    # Only our tagged handlers are touched; pytest, GUI, and parent handlers
    # remain owned by their creators.
    close_invocation_logging(logger)

    console = logging.StreamHandler()
    setattr(console, _OWNED_ATTRIBUTE, True)
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
        setattr(file_handler, _OWNED_ATTRIBUTE, True)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
        )
        logger.addHandler(file_handler)
    return logger
