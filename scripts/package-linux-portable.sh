#!/usr/bin/env bash
set -euo pipefail

platform=${1:?usage: package-linux-portable.sh ubuntu|rhel}
case "$platform" in ubuntu|rhel) ;; *) echo "unsupported platform: $platform" >&2; exit 2;; esac
release_version=${RELEASE_VERSION:-1.3.0-rc1}
root=$(cd "$(dirname "$0")/.." && pwd)
work="$root/build/linux-$platform"
out="$root/dist-linux-$platform"
rm -rf "$work" "$out"
mkdir -p "$work" "$out"

python3 -m PyInstaller --clean --noconfirm --onedir --name nmap-flow-analyzer \
  --distpath "$work/onedir" --workpath "$work/pyinstaller-work" \
  --specpath "$work" "$root/nmap_flow_analyzer.py"
graphviz_lib=$(pkg-config --variable=libdir libgvc 2>/dev/null || true)
if [[ -z "$graphviz_lib" || ! -d "$graphviz_lib/graphviz" ]]; then
  graphviz_plugin_dir=$(find /usr/lib /usr/lib64 -type d -path '*/graphviz' -print -quit 2>/dev/null || true)
  [[ -n "$graphviz_plugin_dir" ]] && graphviz_lib=$(dirname "$graphviz_plugin_dir")
fi
onefile_args=(--clean --noconfirm --onefile --name nmap-flow-analyzer
  --distpath "$work/onefile" --workpath "$work/pyinstaller-onefile"
  --specpath "$work" --add-binary "$(command -v dot):graphviz/bin")
if [[ -n "$graphviz_lib" && -d "$graphviz_lib/graphviz" ]]; then
  onefile_args+=(--add-data "$graphviz_lib/graphviz:graphviz/lib/graphviz")
fi
mapfile -t system_graphviz_dependencies < <(
  { printf '%s\0' "$(command -v dot)"; find "$graphviz_lib/graphviz" -type f -name '*.so*' -print0 2>/dev/null; } |
    xargs -0 -r ldd 2>/dev/null |
    awk '{path=""} /=> \/[^ ]+/ {path=$3} /^\/[^ ]+/ {path=$1} path && path !~ /\/(ld-linux|libc\.so|libpthread|libdl|librt|libm\.so|libresolv|libutil)/ {print path}' |
    sort -u
)
for dependency in "${system_graphviz_dependencies[@]}"; do
  [[ -f "$dependency" ]] && onefile_args+=(--add-binary "$dependency:graphviz/lib")
done
python3 -m PyInstaller "${onefile_args[@]}" "$root/nmap_flow_analyzer.py"

bundle="$work/bundle/nmap-flow-analyzer-$release_version-$platform-x64"
mkdir -p "$bundle/graphviz/bin" "$bundle/graphviz/lib" "$bundle/docs"
cp -a "$work/onedir/nmap-flow-analyzer/." "$bundle/"
mv "$bundle/nmap-flow-analyzer" "$bundle/nmap-flow-analyzer.bin"
cp "$root/packaging/common/linux-launcher.sh" "$bundle/nmap-flow-analyzer"
chmod 0755 "$bundle/nmap-flow-analyzer" "$bundle/nmap-flow-analyzer.bin"
cp "$(command -v dot)" "$bundle/graphviz/bin/dot"
if [[ -n "$graphviz_lib" && -d "$graphviz_lib/graphviz" ]]; then
  cp -a "$graphviz_lib/graphviz" "$bundle/graphviz/lib/"
fi
mapfile -t graphviz_dependencies < <(
  find "$bundle/graphviz" -type f \( -name dot -o -name '*.so*' \) -print0 |
    xargs -0 -r ldd 2>/dev/null |
    awk '{path=""} /=> \/[^ ]+/ {path=$3} /^\/[^ ]+/ {path=$1} path && path !~ /\/(ld-linux|libc\.so|libpthread|libdl|librt|libm\.so|libresolv|libutil)/ {print path}' |
    sort -u
)
for dependency in "${graphviz_dependencies[@]}"; do
  [[ -f "$dependency" ]] && cp -L "$dependency" "$bundle/graphviz/lib/"
done
cp -a "$root/examples" "$bundle/"
cp "$root/network_config.example.yaml" "$root/README.md" "$root/CHANGELOG.md" "$bundle/"
cp -a "$root/docs/." "$bundle/docs/"

tar -C "$work/bundle" -czf \
  "$out/nmap-flow-analyzer-$release_version-$platform-x64-portable.tar.gz" \
  "$(basename "$bundle")"
cp "$work/onefile/nmap-flow-analyzer" \
  "$out/nmap-flow-analyzer-$release_version-$platform-x64"
chmod 0755 "$out/nmap-flow-analyzer-$release_version-$platform-x64"
printf '%s\n' "$bundle"
