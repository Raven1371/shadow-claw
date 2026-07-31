# Manual updates

Shadow Claw / nmap-flow-analyzer never polls for updates, sends telemetry, or
contacts GitHub during analysis, startup, `doctor`, or `preflight`.

Network operations happen only after an explicit command:

```text
nmap-flow-analyzer update check
nmap-flow-analyzer update check --tag v1.3.0-rc1 --json
nmap-flow-analyzer update open-releases
nmap-flow-analyzer update download --tag v1.3.0-rc1 --package-type portable --output-dir ./update
```

`download` retrieves the complete platform package and `SHA256SUMS.txt` from
the selected GitHub release. It rejects a missing inventory, hash mismatch,
wrong platform, wrong architecture, unexpected filename, non-HTTPS redirect,
or oversized download. It never downloads individual Python or Graphviz
dependencies as an application-update mechanism.

## Offline verification and installation

Transfer both the complete package and `SHA256SUMS.txt` into the closed
network, then run:

```text
nmap-flow-analyzer update verify ./nmap-flow-analyzer-1.3.0-rc1-ubuntu-x64-portable.tar.gz
nmap-flow-analyzer update install ./nmap-flow-analyzer-1.3.0-rc1-ubuntu-x64-portable.tar.gz --target ./nmap-flow-analyzer-1.3.0-rc1
```

Portable ZIP and tar.gz archives can be installed to a new target directory.
Extraction is staged and renamed only after complete validation. Existing
targets are never overwritten. Traversal paths, absolute paths, links,
duplicate/case-colliding names, excessive file counts, and excessive expanded
sizes are rejected.

DEB, RPM, AppImage, and onefile packages can be verified with `update verify`,
but installation remains an explicit operating-system administrator action.
The application does not silently invoke a privileged package manager.

An exact digest can be supplied instead of a checksum inventory:

```text
nmap-flow-analyzer update verify PACKAGE --sha256 HEX_DIGEST
```

Signing is not claimed or required until signing keys and release policy are
configured. An unsigned package is never described as signed.
