#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PATH="$root/graphviz/bin:$PATH"
export LD_LIBRARY_PATH="$root/graphviz/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
if [ -d "$root/graphviz/lib/graphviz" ]; then
  export GVBINDIR="$root/graphviz/lib/graphviz"
fi
exec "$root/nmap-flow-analyzer.bin" "$@"
