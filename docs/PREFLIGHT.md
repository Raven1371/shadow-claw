# Doctor and preflight

Use either command to inspect a source, Python-package, or standalone runtime:

```text
nmap-flow-analyzer doctor
nmap-flow-analyzer preflight
```

Both commands are aliases. They report application and Python versions,
operating system and architecture, packaging mode, required modules, YAML and
Excel support, temporary/output-directory writability, Graphviz discovery and
bounded SVG/PNG rendering, package-integrity configuration, and update mode.

For automation, use JSON-only output:

```text
nmap-flow-analyzer preflight --json --non-interactive
```

An output destination can be checked without running an analysis:

```text
nmap-flow-analyzer preflight --output-dir /srv/shadow-claw/reports
```

An explicit Graphviz executable or installation directory can be supplied
with `--graphviz-path`. Discovery order is explicit configuration, bundled
Graphviz, system `PATH`, and standard platform locations. Every discovered
binary is exercised using controlled SVG and PNG renders in an isolated
temporary directory.

Missing Graphviz is a warning because DOT and Mermaid sources remain
available. Missing secure XML/YAML support or an unusable temporary/output
directory is a critical failure.

Preflight never contacts the network and never checks for updates. Normal
analysis remains prompt-free. `--no-preflight` is accepted for explicit
automation policy, although v1.3.0 does not run dedicated preflight commands
implicitly.

