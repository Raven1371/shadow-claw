#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
bash "$root/scripts/package-linux-portable.sh" rhel
release_version=${RELEASE_VERSION:-1.3.0-rc1}
work="$root/build/linux-rhel"
out="$root/dist-linux-rhel"
top="$work/rpmbuild"
mkdir -p "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
ln -s "$work/bundle/nmap-flow-analyzer-$release_version-rhel-x64" "$top/SOURCES/bundle"
cp "$root/packaging/rhel/nmap-flow-analyzer.spec" "$top/SPECS/"
rpmbuild --define "_topdir $top" -bb "$top/SPECS/nmap-flow-analyzer.spec"
cp "$top"/RPMS/x86_64/*.rpm "$out/nmap-flow-analyzer-$release_version-rhel-x64.rpm"
