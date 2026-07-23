"""Streaming Zeek log discovery and parsing.

Standard-library only; Zeek itself is never required to parse its logs.
Both JSON Lines and native Zeek TSV are supported (auto-detected per file),
including rotated filenames and ``.gz`` compression, with hard safety
limits on line length and record counts so a hostile compressed file
cannot exhaust memory.  Symbolic links are never followed during discovery
or reading.
"""

from __future__ import annotations

import gzip
import io
import ipaddress
import json
import logging
import os
import re
import stat
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from .zeek_models import ZeekInputMetadata, iso_utc

LOG = logging.getLogger(__name__)

#: Log types the analyzer understands.  conn is the required core log;
#: everything else is optional enrichment and never fatal when missing.
SUPPORTED_LOG_TYPES = [
    "conn", "dns", "ssl", "x509", "http", "ssh", "rdp",
    "smb_cmd", "smb_files", "smb_mapping", "dce_rpc", "kerberos", "ntlm",
    "ldap", "ldap_search", "dhcp", "ntp", "smtp", "postgresql", "quic",
    "tunnel", "known_hosts", "known_services", "known_certs", "software",
    "files", "notice", "weird", "capture_loss", "reporter",
]

#: Matches "conn.log", "conn.log.gz", rotated "conn.2026-07-21-01-00-00.log",
#: "conn.log.1", "conn-20260721.log.gz" and similar.
_LOG_NAME_RE = re.compile(
    r"^(?P<type>[a-z0-9_]+?)(?:[.\-]\d[\d\-.:T_]*)?\.log(?:\.\d+)?(?P<gz>\.gz)?$"
)


class ZeekParseError(Exception):
    """Fatal Zeek-input problem (only raised when --zeek-required)."""


def classify_filename(name: str) -> Optional[Tuple[str, bool]]:
    """Return (log type, gzipped?) for a Zeek log filename, else None."""
    match = _LOG_NAME_RE.match(name)
    if not match:
        return None
    log_type = match.group("type")
    if log_type not in SUPPORTED_LOG_TYPES:
        return None
    return log_type, bool(match.group("gz"))


def discover_logs(directories: List[Path], metadata: ZeekInputMetadata) -> Dict[str, List[Path]]:
    """Find supported Zeek logs in the given directories (no symlinks).

    Returns {log_type: [paths...]} with deterministic ordering.  Symlinked
    files and directories are skipped with a warning; multiple/rotated
    files per log type are all included.
    """
    found: Dict[str, List[Path]] = {}
    for directory in directories:
        metadata.input_directories.append(str(directory))
        if directory.is_symlink():
            metadata.warnings.append(
                f"Zeek input directory {directory} is a symbolic link; skipped"
            )
            continue
        if not directory.is_dir():
            metadata.warnings.append(f"Zeek input path {directory} is not a directory")
            continue
        for entry in sorted(directory.iterdir(), key=lambda p: p.name):
            if entry.is_symlink():
                metadata.warnings.append(
                    f"Zeek input file {entry.name} is a symbolic link; skipped"
                )
                continue
            if not entry.is_file():
                continue
            info = classify_filename(entry.name)
            if info is None:
                continue
            found.setdefault(info[0], []).append(entry)
    for paths in found.values():
        paths.sort(key=lambda p: (p.name, str(p)))
    metadata.log_types_found = sorted(found)
    return found


def _open_stream(path: Path, gzipped: bool, max_line: int) -> io.TextIOBase:
    """Open a log for streaming text reads without following symlinks."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    mode = os.fstat(fd).st_mode
    if not stat.S_ISREG(mode):
        os.close(fd)
        raise OSError(f"{path} is not a regular file")
    raw = os.fdopen(fd, "rb")
    if gzipped:
        raw = gzip.GzipFile(fileobj=raw)  # streamed; never extracted to disk
    return io.TextIOWrapper(io.BufferedReader(raw), encoding="utf-8", errors="replace")


def _iter_limited_lines(
    handle: io.TextIOBase, path: Path, max_line: int, max_records: int,
    metadata: ZeekInputMetadata,
) -> Iterator[str]:
    count = 0
    while True:
        line = handle.readline(max_line + 1)
        if not line:
            return
        if len(line) > max_line:
            metadata.warnings.append(
                f"{path.name}: line exceeds max_line_length_bytes ({max_line}); "
                "remainder of file skipped for safety"
            )
            return
        count += 1
        if count > max_records:
            metadata.warnings.append(
                f"{path.name}: exceeded max_records_per_file ({max_records}); "
                "remaining records skipped for safety"
            )
            return
        yield line.rstrip("\r\n")


# ---------------------------------------------------------------------------
# TSV support
# ---------------------------------------------------------------------------

#: Recognized native Zeek TSV log-header directives (issue 2, v1.2.4).
#: A leading '#' alone is NOT sufficient to classify a file as Zeek TSV; the
#: first whitespace-delimited token must be exactly one of these.
ZEEK_TSV_DIRECTIVES = frozenset({
    "#separator",
    "#set_separator",
    "#empty_field",
    "#unset_field",
    "#path",
    "#open",
    "#fields",
    "#types",
    "#close",
})


def detect_zeek_format(first_meaningful_line: str) -> str:
    """Classify a Zeek log from its first meaningful line.

    Returns "json", "tsv", or "indeterminate". The input should already have
    had a leading BOM and surrounding whitespace stripped by the caller.

    JSON is recognized by a leading '{'. Native Zeek TSV is recognized ONLY
    when the first whitespace-delimited token is a known Zeek directive (e.g.
    "#separator", "#fields"); an arbitrary "#" comment such as "#random" or a
    look-alike such as "#separator_fake" is NOT TSV. Anything else is
    indeterminate.
    """
    if first_meaningful_line.startswith("{"):
        return "json"
    if first_meaningful_line.startswith("#"):
        token = first_meaningful_line.split(None, 1)[0]
        if token in ZEEK_TSV_DIRECTIVES:
            return "tsv"
    return "indeterminate"


def _decode_separator(token: str) -> str:
    r"""Decode Zeek's '#separator \x09' representation."""
    if token.startswith("\\x") and len(token) >= 4:
        try:
            return chr(int(token[2:4], 16))
        except ValueError:
            return "\t"
    return token or "\t"


def _tsv_records(
    lines: Iterator[str], path: Path, metadata: ZeekInputMetadata, log_type: str
) -> Iterator[Dict[str, object]]:
    separator = "\t"
    set_sep = ","
    empty_field = "(empty)"
    unset_field = "-"
    fields: List[str] = []
    types: List[str] = []
    for lineno, line in enumerate(lines, start=1):
        if line.startswith("#"):
            parts = line.split(separator if separator in line else " ", 1)
            directive = parts[0]
            rest = parts[1] if len(parts) > 1 else ""
            if directive == "#separator":
                separator = _decode_separator(rest.strip())
            elif directive == "#set_separator":
                set_sep = rest.strip() or set_sep
            elif directive == "#empty_field":
                empty_field = rest.strip() or empty_field
            elif directive == "#unset_field":
                unset_field = rest.strip() or unset_field
            elif directive == "#fields":
                fields = rest.split(separator)
            elif directive == "#types":
                types = rest.split(separator)
            continue
        if not line:
            continue
        if not fields:
            metadata.parse_errors.append(
                f"{path.name}:{lineno}: data before #fields header"
            )
            yield lineno, None  # a data record was seen, but it is malformed
            continue
        values = line.split(separator)
        if len(values) != len(fields):
            metadata.parse_errors.append(
                f"{path.name}:{lineno}: expected {len(fields)} fields, "
                f"got {len(values)}"
            )
            yield lineno, None
            continue
        record: Dict[str, object] = {}
        for index, name in enumerate(fields):
            value = values[index]
            if value == unset_field:
                record[name] = None  # unset: field absent for this record
            elif value == empty_field:
                record[name] = ""  # present but empty
            else:
                ftype = types[index] if index < len(types) else ""
                if ftype.startswith(("set[", "vector[")):
                    record[name] = value.split(set_sep)
                else:
                    record[name] = value
        yield lineno, record


def _json_records(
    lines: Iterator[str], path: Path, metadata: ZeekInputMetadata, log_type: str
) -> Iterator[Dict[str, object]]:
    for lineno, line in enumerate(lines, start=1):
        stripped = line.lstrip("\ufeff")  # tolerate a leading UTF-8 BOM
        if not stripped.strip():
            continue
        try:
            record = json.loads(stripped)
        except ValueError as exc:
            # Bounded, sanitized reason; never echo the hostile line back.
            reason = str(exc).splitlines()[0][:120]
            metadata.parse_errors.append(f"{path.name}:{lineno}: {reason}")
            yield lineno, None  # a data record was seen, but it is malformed
            continue
        if not isinstance(record, dict):
            metadata.parse_errors.append(
                f"{path.name}:{lineno}: expected a JSON object, got "
                f"{type(record).__name__}"
            )
            yield lineno, None
            continue
        yield lineno, record


def iter_log_records(
    path: Path,
    log_type: str,
    metadata: ZeekInputMetadata,
    log_format: str = "auto",
    max_line: int = 1048576,
    max_records: int = 10_000_000,
) -> Iterator[Dict[str, object]]:
    """Stream parsed records from one log file (JSON Lines or Zeek TSV).

    Format is auto-detected per file when requested, so mixed directories
    work.  Unknown fields are preserved in the record dict and ignored by
    consumers; malformed rows are counted with file/line context and
    skipped.
    """
    gzipped = path.name.endswith(".gz")
    try:
        handle = _open_stream(path, gzipped, max_line)
    except OSError as exc:
        metadata.warnings.append(f"Cannot read {path.name}: {exc}")
        return
    entry = {"file": path.name, "log_type": log_type, "format": "",
             "size": path.stat().st_size, "records": 0, "malformed": 0,
             "data_records_seen": 0}
    with handle:
        lines = _iter_limited_lines(handle, path, max_line, max_records, metadata)
        chosen = log_format
        if chosen == "auto":
            # Detect on the first MEANINGFUL line: skip leading blank and
            # whitespace-only lines and an optional UTF-8 BOM, but BUFFER them
            # so they are re-fed to the parser and physical line numbers stay
            # correct (issue 1, v1.2.3). We never read the whole file.
            buffered: List[str] = []
            meaningful = None
            for candidate in lines:
                buffered.append(candidate)
                probe = candidate.lstrip("\ufeff").strip()
                if probe:
                    meaningful = probe
                    break
            if meaningful is None:
                # Whitespace/BOM-only or empty file: no data records at all.
                metadata.warnings.append(f"{path.name}: no data records found")
                entry["format"] = "empty"
                metadata.files_processed.append(entry)
                return
            chosen = detect_zeek_format(meaningful)
            if chosen == "indeterminate":
                # Not JSON and not a RECOGNIZED Zeek directive: never guess
                # TSV. The physical line number is the last buffered line.
                metadata.warnings.append(
                    f"{path.name}:{len(buffered)}: could not determine log "
                    "format from the first data line (expected JSON '{{' or a "
                    "recognized Zeek header directive such as #separator or "
                    "#fields); skipping"
                )
                entry["format"] = "indeterminate"
                metadata.files_processed.append(entry)
                return

            def _chain(head: List[str], rest: Iterator[str]) -> Iterator[str]:
                yield from head
                yield from rest

            lines = _chain(buffered, lines)
        entry["format"] = chosen
        parser = _json_records if chosen == "json" else _tsv_records
        for lineno, record in parser(lines, path, metadata, log_type):
            # Every yielded item is one DATA record that was seen (blank lines
            # and TSV directives are never yielded). raw_records_read therefore
            # equals data_records_seen and satisfies the invariant
            # data_records_seen == usable_records + malformed_records
            # (issue 2, v1.2.3).
            metadata.raw_records_read[log_type] = (
                metadata.raw_records_read.get(log_type, 0) + 1
            )
            entry["data_records_seen"] += 1
            problem = None
            if record is None:
                # Structurally malformed (bad JSON / wrong type / bad TSV row);
                # the parser already recorded a bounded reason.
                problem = "structurally malformed record"
            elif log_type == "conn":
                problem = validate_conn_record(record)
                if problem is not None:
                    metadata.parse_errors.append(
                        f"{path.name}:{lineno}: {problem}"
                    )
            if problem is not None:
                metadata.malformed_counts[log_type] = (
                    metadata.malformed_counts.get(log_type, 0) + 1
                )
                entry["malformed"] += 1
                continue
            entry["records"] += 1
            metadata.record_counts[log_type] = (
                metadata.record_counts.get(log_type, 0) + 1
            )
            metadata.usable_records[log_type] = (
                metadata.usable_records.get(log_type, 0) + 1
            )
            yield record
    metadata.files_processed.append(entry)


# ---------------------------------------------------------------------------
# Required-field validation for conn.log (v1.2.1)
# ---------------------------------------------------------------------------

#: conn.log fields without which a connection cannot be reconstructed.
REQUIRED_CONN_FIELDS = ("ts", "id.orig_h", "id.resp_h", "proto")


def validate_conn_record(record: Dict[str, object]) -> Optional[str]:
    """Return a short reason why a conn.log record is unusable, else None.

    Validation happens in the parser, while the filename and line number are
    still known, so an invalid record is counted as malformed rather than
    silently dropped later. The returned reason never echoes record content
    back to the report (a hostile log must not be able to inject text through
    an error message); it names only the offending field.
    """
    if record.get("ts", record.get("ts")) in (None, ""):
        return "missing required field 'ts'"
    orig = as_str(record, "id.orig_h", "id_orig_h")
    resp = as_str(record, "id.resp_h", "id_resp_h")
    proto = as_str(record, "proto").lower()
    if not orig:
        return "missing required field 'id.orig_h'"
    if not resp:
        return "missing required field 'id.resp_h'"
    if not proto:
        return "missing required field 'proto'"
    try:
        float(record.get("ts"))
    except (TypeError, ValueError):
        return "field 'ts' is not a numeric timestamp"
    for label, value in (("id.orig_h", orig), ("id.resp_h", resp)):
        try:
            ipaddress.ip_address(value.split("%")[0])
        except ValueError:
            return f"field {label!r} is not a valid IP address"
    if proto in ("tcp", "udp"):
        # ICMP is deliberately excluded: its type/code are not ports and it
        # must not be forced into the destination-port model.
        port = record.get("id.resp_p", record.get("id_resp_p"))
        if port in (None, ""):
            return f"missing required field 'id.resp_p' for {proto}"
        try:
            port_value = int(float(port))
        except (TypeError, ValueError):
            return "field 'id.resp_p' is not a valid port number"
        if not 0 <= port_value <= 65535:
            return "field 'id.resp_p' is outside the valid port range"
    return None


# ---------------------------------------------------------------------------
# Field coercion helpers (shared by aggregation)
# ---------------------------------------------------------------------------

def as_str(record: Dict[str, object], *names: str) -> str:
    for name in names:
        value = record.get(name)
        if value is None:
            continue
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)
    return ""


def as_int(record: Dict[str, object], *names: str) -> int:
    for name in names:
        value = record.get(name)
        if value in (None, ""):
            continue
        try:
            return int(float(value))
        except (TypeError, ValueError):
            continue
    return 0


def as_float(record: Dict[str, object], *names: str) -> Optional[float]:
    for name in names:
        value = record.get(name)
        if value in (None, ""):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return None


def as_list(record: Dict[str, object], *names: str) -> List[str]:
    for name in names:
        value = record.get(name)
        if value in (None, ""):
            continue
        if isinstance(value, list):
            return [str(v) for v in value if v not in (None, "")]
        return [str(value)]
    return []
