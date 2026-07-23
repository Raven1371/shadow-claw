#!/usr/bin/env python3
"""Process an EXISTING, authorized PCAP file with Zeek into JSON logs.

This helper does NOT capture live traffic and never will: it only runs
``zeek -r`` against a capture file you already have. Live packet capture
requires explicit authorization and appropriate tooling outside this
project's scope (see docs/ZEEK_COLLECTION.md).

Safety properties:
- The Zeek process is invoked with a list of arguments; no shell is ever
  involved and no string interpolation reaches a command line.
- An explicit input PCAP and output directory are required.
- Existing Zeek logs in the output directory are never overwritten unless
  --force is given.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Process an existing authorized PCAP with Zeek "
                    "(offline only; never captures live traffic)."
    )
    parser.add_argument("--pcap", required=True, type=Path,
                        help="Existing capture file to process")
    parser.add_argument("--output-dir", required=True, type=Path,
                        help="Directory that will receive the JSON Zeek logs")
    parser.add_argument("--force", action="store_true",
                        help="Allow writing into a directory that already "
                             "contains Zeek logs")
    args = parser.parse_args(argv)

    pcap = args.pcap
    if pcap.is_symlink() or not pcap.is_file():
        print(f"error: --pcap must be an existing regular file: {pcap}",
              file=sys.stderr)
        return 2
    out = args.output_dir
    if out.is_symlink():
        print(f"error: --output-dir must not be a symbolic link: {out}",
              file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    existing = sorted(p.name for p in out.iterdir() if p.name.endswith(".log"))
    if existing and not args.force:
        print("error: output directory already contains Zeek logs "
              f"({', '.join(existing[:5])}); refusing to overwrite without "
              "--force", file=sys.stderr)
        return 2

    zeek = shutil.which("zeek")
    if not zeek:
        print("error: the 'zeek' binary was not found on PATH. Install Zeek "
              "(https://zeek.org) to process PCAPs; the analyzer itself does "
              "not require Zeek to parse already-generated logs.",
              file=sys.stderr)
        return 2

    print(f"Processing existing capture {pcap} (offline; no live capture).")
    # List-argument invocation only: no shell, no interpolation.
    result = subprocess.run(
        [zeek, "-r", str(pcap), "LogAscii::use_json=T"],
        cwd=out,
        check=False,
    )
    if result.returncode != 0:
        print(f"error: zeek exited with status {result.returncode}",
              file=sys.stderr)
        return result.returncode
    produced = sorted(p.name for p in out.iterdir() if p.name.endswith(".log"))
    print(f"Wrote {len(produced)} JSON log(s) to {out}: "
          f"{', '.join(produced[:8])}{'...' if len(produced) > 8 else ''}")
    print("Point the analyzer at this directory with --zeek-dir.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
