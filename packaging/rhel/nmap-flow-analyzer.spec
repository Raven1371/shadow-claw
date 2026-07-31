Name: nmap-flow-analyzer
Version: 1.3.0
Release: 0.rc1%{?dist}
Summary: Offline network analysis and security investigation
License: Unspecified
BuildArch: x86_64

%description
Offline Nmap and Zeek evidence analysis with human-reviewed recommendations.

%install
mkdir -p %{buildroot}/opt/nmap-flow-analyzer %{buildroot}/usr/bin
cp -a %{_sourcedir}/bundle/. %{buildroot}/opt/nmap-flow-analyzer/
ln -s /opt/nmap-flow-analyzer/nmap-flow-analyzer %{buildroot}/usr/bin/nmap-flow-analyzer

%files
/opt/nmap-flow-analyzer
/usr/bin/nmap-flow-analyzer
