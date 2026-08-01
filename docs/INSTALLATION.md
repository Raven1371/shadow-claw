# Installation

Choose one supported path:

- **Standalone:** use the portable archive, onefile executable, DEB, or RPM for
  the matching Linux platform and architecture. Python dependencies and the
  required Graphviz runtime are bundled.
- **Python:** install with `pipx install .` (preferred) or `pip install .`.
- **Developer:** create a virtual environment and run
  `pip install -e ".[dev]"`.

After installation, run `nmap-flow-analyzer doctor`. No automatic update or
telemetry request is made.

The Linux v1.3.0-rc1 artifacts are release-candidate builds. Windows 11
self-hosted validation remains pending.
