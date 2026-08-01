#!/usr/bin/env bash
set -euo pipefail
platform=${1:?usage: try-build-appimage.sh ubuntu|rhel}
release_version=${RELEASE_VERSION:-1.3.0-rc1}
root=$(cd "$(dirname "$0")/.." && pwd)
work="$root/build/linux-$platform"
out="$root/dist-linux-$platform"
bundle="$work/bundle/nmap-flow-analyzer-$release_version-$platform-x64"
appdir="$work/AppDir"
rm -rf "$appdir"
mkdir -p "$appdir/opt/nmap-flow-analyzer" "$appdir/usr/bin" "$appdir/usr/share/applications"
cp -a "$bundle/." "$appdir/opt/nmap-flow-analyzer/"
ln -s /opt/nmap-flow-analyzer/nmap-flow-analyzer "$appdir/usr/bin/nmap-flow-analyzer"
cat > "$appdir/AppRun" <<'EOF'
#!/bin/sh
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$HERE/opt/nmap-flow-analyzer/nmap-flow-analyzer" "$@"
EOF
chmod 0755 "$appdir/AppRun"
cat > "$appdir/nmap-flow-analyzer.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=nmap-flow-analyzer
Exec=nmap-flow-analyzer
Icon=nmap-flow-analyzer
Categories=System;Security;
Terminal=true
EOF
cat > "$appdir/nmap-flow-analyzer.svg" <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128"><rect width="128" height="128" rx="20" fill="#18212f"/><path d="M24 92V36h15l25 33 25-33h15v56H87V62L64 91 41 62v30z" fill="#d7e3f4"/></svg>
EOF
tool="$work/appimagetool"
curl --fail --location --retry 3 \
  https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage \
  --output "$tool"
chmod 0755 "$tool"
ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$tool" "$appdir" \
  "$out/nmap-flow-analyzer-$release_version-$platform-x64.AppImage"
chmod 0755 "$out/nmap-flow-analyzer-$release_version-$platform-x64.AppImage"
