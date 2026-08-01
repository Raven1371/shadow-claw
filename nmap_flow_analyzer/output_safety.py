"""Centralized output-path safety.

Every generated artifact passes through this module before it is created,
replaced, or deleted.  The rules:

1. The output directory is resolved once and used as the containment root.
2. A destination must be lexically and logically inside that root.
3. Existing symlink destinations are rejected (never followed, never
   overwritten through, and their targets are never touched).
4. Parent components between the root and the destination must not be
   symlinks.
5. Existing non-regular files (directories, FIFOs, sockets, devices) are
   rejected.
6. Temporary files are created only inside the validated root and are
   published with ``os.replace`` after ``fsync``.
7. Nothing is ever recursively deleted except the run's own staging
   directory, which this module created itself.

Validation is layered rather than relying on any single platform flag;
``os.open(..., O_NOFOLLOW)`` is used additionally where available.
"""

from __future__ import annotations

import logging
import os
import stat
import tempfile
from pathlib import Path
from typing import Optional

LOG = logging.getLogger(__name__)


class OutputSafetyError(Exception):
    """A generated-output destination failed safety validation."""


def validate_output_directory(path: Path) -> Path:
    """Validate the output directory and return its resolved real path.

    The directory (or the location where it will be created) must not itself
    be a symlink: for a security-reporting tool, writing through a symlinked
    output directory silently redirects every artifact, so it is rejected
    with a clear error instead.  Pass the real path explicitly if a link is
    intended.
    """
    if path.is_symlink():
        raise OutputSafetyError(
            f"Output directory {path} is a symbolic link; refusing to write "
            "through it. Pass the link target directly instead."
        )
    if path.exists() and not path.is_dir():
        raise OutputSafetyError(f"Output path {path} exists and is not a directory")
    return path.resolve()


def _is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def reject_symlink_components(output_dir: Path, destination: Path) -> None:
    """Reject symlinked parent components between root and destination."""
    parent = destination.parent
    root = Path(output_dir)
    while True:
        if parent.is_symlink():
            raise OutputSafetyError(
                f"Refusing {destination.name}: parent directory {parent} is a "
                "symbolic link"
            )
        if parent == root or parent == parent.parent:
            break
        parent = parent.parent


def validate_output_destination(output_dir: Path, destination: Path) -> Path:
    """Validate one artifact destination inside the resolved output dir.

    Returns the destination path.  Raises OutputSafetyError when the
    destination is a symlink, has symlinked parents, resolves outside the
    output directory, or exists as a non-regular file.  The destination is
    never followed or modified by validation.
    """
    root = Path(output_dir)
    destination = Path(destination)
    if not destination.is_absolute():
        destination = root / destination

    # Lexical containment first (no resolution of the final component).
    if not _is_within(root, destination):
        raise OutputSafetyError(
            f"Refusing {destination}: outside the output directory {root}"
        )
    reject_symlink_components(root, destination)

    # Logical containment: the fully resolved parent must stay inside root.
    resolved_parent = destination.parent.resolve()
    if not _is_within(root, resolved_parent) and resolved_parent != root:
        raise OutputSafetyError(
            f"Refusing {destination}: resolves outside the output directory"
        )

    if destination.is_symlink():
        raise OutputSafetyError(
            f"Refusing {destination.name}: destination exists as a symbolic "
            "link; it will not be followed or replaced through. Remove the "
            "link manually if this is intended."
        )
    if destination.exists():
        mode = os.lstat(destination).st_mode
        if not stat.S_ISREG(mode):
            kind = (
                "directory" if stat.S_ISDIR(mode)
                else "FIFO" if stat.S_ISFIFO(mode)
                else "socket" if stat.S_ISSOCK(mode)
                else "device" if stat.S_ISBLK(mode) or stat.S_ISCHR(mode)
                else "special file"
            )
            raise OutputSafetyError(
                f"Refusing {destination.name}: destination exists as a {kind}, "
                "not a regular file"
            )
    return destination


def create_secure_temp_file(output_dir: Path, suffix: str = "") -> Path:
    """Create a temp file inside the validated output directory (0600)."""
    fd, name = tempfile.mkstemp(dir=str(output_dir), prefix=".nfa-tmp-", suffix=suffix)
    os.close(fd)
    return Path(name)


def _fsync_path(path: Path) -> None:
    flags = os.O_RDONLY
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags | nofollow)
    except OSError:
        return  # fsync is best-effort; the atomic rename still holds
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_replace_file(temp_path: Path, destination: Path) -> None:
    """Atomically publish ``temp_path`` to ``destination``.

    The destination is re-validated immediately before replacement (symlink
    and file-type checks), buffers are flushed to disk, permissions are made
    world-readable like a normal report, and ``os.replace`` performs the
    swap.  The temp file is removed if anything fails.
    """
    try:
        validate_output_destination(destination.parent, destination)
        _fsync_path(temp_path)
        try:
            os.chmod(temp_path, 0o644)
        except OSError:
            pass
        os.replace(temp_path, destination)
    except BaseException:
        Path(temp_path).unlink(missing_ok=True)
        raise


def atomic_write_text(
    destination: Path,
    content: str,
    *,
    encoding: str = "utf-8",
) -> None:
    """Validated, fsynced, atomic text write."""
    destination = Path(destination)
    validate_output_destination(destination.parent, destination)
    tmp = create_secure_temp_file(destination.parent, suffix=".tmp")
    try:
        with open(tmp, "w", encoding=encoding, newline="") as handle:
            handle.write(content)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        atomic_replace_file(tmp, destination)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def atomic_write_bytes(destination: Path, content: bytes) -> None:
    """Validated, fsynced, atomic binary write."""
    destination = Path(destination)
    validate_output_destination(destination.parent, destination)
    tmp = create_secure_temp_file(destination.parent, suffix=".tmp")
    try:
        with open(tmp, "wb") as handle:
            handle.write(content)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        atomic_replace_file(tmp, destination)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def safe_remove_stale(output_dir: Path, name: str) -> Optional[str]:
    """Remove one stale generated artifact by name.

    Only a direct child of the output directory that is a regular file is
    removed.  Symlinks and special files are left in place (a warning string
    is returned instead) so an attacker-supplied entry is never followed and
    its target is never deleted.  Returns None on success or if the file is
    absent; otherwise a human-readable reason why it was skipped.
    """
    entry = Path(output_dir) / Path(name).name  # direct child only
    if not entry.exists() and not entry.is_symlink():
        return None
    if entry.is_symlink():
        return f"stale entry {entry.name} is a symbolic link; left untouched"
    if not stat.S_ISREG(os.lstat(entry).st_mode):
        return f"stale entry {entry.name} is not a regular file; left untouched"
    try:
        entry.unlink()
    except OSError as exc:
        return f"could not remove stale {entry.name}: {exc}"
    return None
