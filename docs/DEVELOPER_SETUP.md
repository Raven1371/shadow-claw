# Developer setup

Create and activate a virtual environment using Python 3.9 or newer, then:

```text
python -m pip install -e ".[dev]"
python -m pytest -q
python run_tests.py
```

The editable development extra contains build and test tooling. It is not
included in runtime or standalone distributions.

Before submitting packaging changes, validate all three Python paths in clean
environments:

```text
python -m pip install .
python -m pip install -e ".[dev]"
pipx install .
```

Run the installed `nmap-flow-analyzer` command rather than relying on imports
from the repository root. Keep generated environments, caches, and artifacts
under ignored build directories.
