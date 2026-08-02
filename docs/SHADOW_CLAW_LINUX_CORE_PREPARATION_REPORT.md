# Shadow Claw Linux/Core Preparation Report

## Scope

This report records repository preparation only. It is not evidence that
Shadow Core, Shadow Fang, the complete Shadow Evidence format, or Windows
integration has been implemented.

## Starting state

- Workspace: `C:\Users\kache\Documents\Shadow-Ecosystem`
- Repository: `C:\Users\kache\Documents\Shadow-Ecosystem\shadow-claw`
- Origin: `https://github.com/Raven1371/shadow-claw.git`
- Starting branch and commit: `main` at
  `59b4f8423311eeb6eb5e28e9c9d86b10c4f37f47`
- Starting tree: clean and synchronized with `origin/main`
- Published prerelease: `v1.3.0-rc1`, preserved unchanged
- Development branch: `develop/shadow-claw-linux-core-integration`

## Preparation changes

- Product identity is Shadow Claw™; active repository metadata now points to
  `Raven1371/shadow-claw`.
- Historical validation links and dependency-inventory provenance referencing
  the former repository are preserved as historically accurate records.
- `nmap-flow-analyzer`, `nmap_flow_analyzer`, existing arguments, imports,
  configuration, inputs, reports, and release artifacts remain compatible.
- The authoritative development version is `1.4.0.dev0`.
- Linux-first development targets Ubuntu 24.04 x64 and Rocky Linux 9 /
  RHEL-compatible x64. Windows 11 validation, packaging, and application
  integration are deferred.
- The future Shadow Core/Shadow Claw ownership boundary, Shadow Evidence
  boundary, and lineage requirements are documented separately.

## Validation record

Validation results on the development branch:

- Full pytest suite: **438 passed, 15 skipped** in 19.89 seconds.
- Offline test runner: **440 collected, 426 passed, 0 failed, 14
  skipped**.
- Python compilation: passed using an external bytecode-cache directory.
- Package metadata, release-integrity, and update tests: **11 passed**.
- Dependency-lock, project license-payload, and native-attribution tests:
  **19 passed, 1 environment-dependent skip**.
- Workflow YAML validation: all **7** workflow files parsed successfully.
- Deterministic-output, staging/manifest, logging lifecycle, stale diagram,
  bundled Graphviz, and Zeek output tests: **44 passed**.
- Representative Nmap and Nmap-plus-Zeek analysis: passed as exercised by the
  complete and targeted suites. A redundant manual CLI rerun was not performed
  because its external temporary-output write was not approved.
- CLI compatibility: `nmap-flow-analyzer --help` behavior passed and version
  output is `nmap-flow-analyzer 1.4.0.dev0`.
- Native Graphviz SVG/PNG rendering: not run because `dot` is unavailable in
  this Windows environment. Timeout, bundled-path, stale-output, and fallback
  behavior remain covered by passing tests.
- Output-directory atomic publication, cleanup, rename/reuse, and file-handle
  lifecycle behavior: covered by the passing full and targeted suites.

The standalone distributable-payload validator expects a built bundle with
`licenses/NATIVE_DEPENDENCY_INVENTORY.json`; invoking it on the source tree is
not applicable. Source-tree licensing and attribution tests passed. No release
bundle was created by this preparation task.

## Known limitations and remaining work

The future `shadow-claw` CLI alias is documented but not yet implemented.
Shadow Core integration, Core-owned evidence schemas and package handling,
PCAP/PCAPNG parsing, Suricata ingestion, confidence changes, Shadow Fang, and
Windows integration remain separate future work. Platform-specific packaging
and Graphviz artifact validation require their applicable Linux build hosts and
tools. No automatic security enforcement is introduced.
