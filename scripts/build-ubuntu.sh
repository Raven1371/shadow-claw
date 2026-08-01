#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
bash "$root/scripts/package-linux-portable.sh" ubuntu
release_version=${RELEASE_VERSION:-1.3.0-rc1}
work="$root/build/linux-ubuntu"
out="$root/dist-linux-ubuntu"
package="$work/deb"
mkdir -p "$package/DEBIAN" "$package/opt/nmap-flow-analyzer" "$package/usr/bin"
cp "$root/packaging/ubuntu/control" "$package/DEBIAN/control"
cp -a "$work/bundle/nmap-flow-analyzer-$release_version-ubuntu-x64/." \
  "$package/opt/nmap-flow-analyzer/"
ln -s /opt/nmap-flow-analyzer/nmap-flow-analyzer "$package/usr/bin/nmap-flow-analyzer"
mkdir -p "$package/usr/share/doc/nmap-flow-analyzer"
cp "$root/LICENSE" "$root/NOTICE" "$root/THIRD_PARTY_NOTICES.md" \
  "$package/usr/share/doc/nmap-flow-analyzer/"
cp -a "$root/licenses" "$package/usr/share/doc/nmap-flow-analyzer/"
dpkg-deb --build --root-owner-group "$package" \
  "$out/nmap-flow-analyzer-$release_version-ubuntu-x64.deb"
