"""Runtime configuration shared by source and frozen distributions."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional


def bundled_graphviz_root() -> Optional[Path]:
    roots = []
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        roots.append(Path(frozen_root))
    roots.extend([Path(sys.executable).resolve().parent,
                  Path(sys.executable).resolve().parent.parent])
    executable = "dot.exe" if os.name == "nt" else "dot"
    for root in roots:
        if (root / "graphviz" / "bin" / executable).is_file():
            return root / "graphviz"
    return None


def configure_bundled_graphviz() -> Optional[Path]:
    """Prefer a packaged Graphviz runtime without affecting source installs."""
    root = bundled_graphviz_root()
    if root is None:
        return None
    bin_dir = root / "bin"
    lib_dir = root / "lib"
    os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ.get("PATH", "")
    if (lib_dir / "graphviz").is_dir():
        os.environ["GVBINDIR"] = str(lib_dir / "graphviz")
    if os.name != "nt" and lib_dir.is_dir():
        current = os.environ.get("LD_LIBRARY_PATH", "")
        os.environ["LD_LIBRARY_PATH"] = str(lib_dir) + (os.pathsep + current if current else "")
    return root
