# nmap-flow-analyzer v1.3.0-rc1

This prerelease adds modern Python packaging, offline doctor/preflight checks,
explicit verified application updates, and Linux standalone/native packaging.
It preserves the Linux-verified v1.2.5 analyzer behavior.

Ubuntu 24.04 and Rocky Linux 9 packages must pass their current-source build
and artifact smoke gates before assembly. Windows 11 remains pending, so this
is not the final cross-platform v1.3.0 release.

The software recommends firewall candidates for human review; it does not
implement security policy changes.
