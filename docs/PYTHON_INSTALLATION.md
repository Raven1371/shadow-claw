# Python installation

Python 3.9 or newer is required for this distribution path.

Install from a checked-out release source tree:

```text
python -m pip install .
nmap-flow-analyzer --version
nmap-flow-analyzer preflight --non-interactive
```

For an isolated command installation:

```text
pipx install .
```

The authoritative metadata and console entry point are defined in
`pyproject.toml`. Runtime dependencies are installed with the package. Neither
installation mode performs application update polling or telemetry.

Ordinary users should prefer a verified standalone platform package once the
v1.3.0 release candidate publishes those artifacts; that path does not require
a separately managed Python installation.
