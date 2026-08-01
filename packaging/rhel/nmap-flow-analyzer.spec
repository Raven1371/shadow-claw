%global _build_id_links none

Name: nmap-flow-analyzer
Version: 1.3.0
Release: 0.rc1%{?dist}
Summary: Offline network analysis and security investigation
License: PolyForm-Noncommercial-1.0.0
BuildArch: x86_64

%description
Offline Nmap and Zeek evidence analysis with human-reviewed recommendations.

%install
mkdir -p %{buildroot}/opt/nmap-flow-analyzer %{buildroot}/usr/bin %{buildroot}%{_licensedir}/%{name}
cp -a %{_sourcedir}/bundle/. %{buildroot}/opt/nmap-flow-analyzer/
ln -s /opt/nmap-flow-analyzer/nmap-flow-analyzer %{buildroot}/usr/bin/nmap-flow-analyzer
cp %{_sourcedir}/bundle/LICENSE %{_sourcedir}/bundle/NOTICE %{_sourcedir}/bundle/COPYRIGHT.md %{_sourcedir}/bundle/COMMERCIAL_USE.md %{_sourcedir}/bundle/TRADEMARKS.md %{_sourcedir}/bundle/THIRD_PARTY_NOTICES.md %{buildroot}%{_licensedir}/%{name}/
cp -a %{_sourcedir}/bundle/licenses %{buildroot}%{_licensedir}/%{name}/

%files
/opt/nmap-flow-analyzer
/usr/bin/nmap-flow-analyzer
%license %{_licensedir}/%{name}
