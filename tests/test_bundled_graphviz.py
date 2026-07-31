"""Bundled Graphviz discovery and environment precedence."""

import os
import tempfile
from pathlib import Path
from unittest import mock

from nmap_flow_analyzer.runtime import configure_bundled_graphviz


def test_bundled_graphviz_is_preferred_for_frozen_runtime():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        executable = "dot.exe" if os.name == "nt" else "dot"
        dot = root / "graphviz" / "bin" / executable
        plugins = root / "graphviz" / "lib" / "graphviz"
        plugins.mkdir(parents=True)
        dot.parent.mkdir(parents=True, exist_ok=True)
        dot.write_bytes(b"placeholder")
        with mock.patch("nmap_flow_analyzer.runtime.sys._MEIPASS", str(root), create=True), \
                mock.patch.dict(os.environ, {"PATH": "system-path"}, clear=False):
            selected = configure_bundled_graphviz()
            assert selected == root / "graphviz"
            assert os.environ["PATH"].split(os.pathsep)[0] == str(dot.parent)
            assert os.environ["GVBINDIR"] == str(plugins)
