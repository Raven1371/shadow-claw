# Distribution options

| Format | Best fit | Runtime behavior |
|---|---|---|
| Portable archive | Closed networks and removable media | Extract once; bundled runtime and Graphviz |
| Onefile | Simple transfer | Extracts its runtime to a temporary directory at startup |
| DEB | Managed Ubuntu hosts | Native install/uninstall under `/opt/nmap-flow-analyzer` |
| RPM | Managed Rocky/RHEL-compatible hosts | Native install/uninstall under `/opt/nmap-flow-analyzer` |
| AppImage | Portable desktop-style Linux use | Published only when its CI smoke test succeeds |
| pipx | Python users | Isolated Python environment; system Graphviz may be used |

Select the artifact whose filename matches the operating system and `x64`
architecture. Verify it against `SHA256SUMS.txt` before use.
