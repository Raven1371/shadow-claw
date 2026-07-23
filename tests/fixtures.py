"""Shared helpers and small embedded Nmap XML fixtures for the test suite."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import List, Tuple

from nmap_flow_analyzer.config import AnalyzerConfig, default_config
from nmap_flow_analyzer.models import Host, ScanMetadata
from nmap_flow_analyzer.parser import parse_nmap_xml


def parse_xml(text: str) -> Tuple[ScanMetadata, List[Host]]:
    """Write the XML to a temp file and parse it."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "scan.xml"
        path.write_text(text, encoding="utf-8")
        return parse_nmap_xml(path)


def base_config() -> AnalyzerConfig:
    """A configuration with a scanner and two zones, used across tests."""
    cfg = default_config()
    cfg.scanner_ip = "192.168.1.50"
    cfg.scanner_hostname = "sec-scan01"
    cfg.scanner_zone = "Management"
    cfg.zones = {
        "Management": ["192.168.1.0/24"],
        "Servers": ["192.168.10.0/24"],
    }
    cfg.local_networks = ["192.168.0.0/16"]
    return cfg


XML_HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<nmaprun scanner="nmap" args="nmap -sS -sV -oX out.xml targets" '
    'start="1719800000" startstr="Mon Jul  1 10:00:00 2026" version="7.95" '
    'xmloutputversion="1.05">\n'
    '<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>\n'
)
XML_FOOTER = (
    '<runstats><finished time="1719800100" timestr="Mon Jul  1 10:01:40 2026" '
    'elapsed="100" summary="scan finished"/>'
    '<hosts up="1" down="0" total="1"/></runstats>\n</nmaprun>\n'
)

SINGLE_HOST_XML = XML_HEADER + """
<host><status state="up" reason="arp-response"/>
<address addr="192.168.10.20" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Dell Inc."/>
<hostnames><hostname name="web01.example.local" type="PTR"/>
<hostname name="intranet.example.local" type="user"/></hostnames>
<ports><port protocol="tcp" portid="443">
<state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.24.0" tunnel="ssl"
 method="probed" conf="10"><cpe>cpe:/a:nginx:nginx:1.24.0</cpe></service>
</port></ports>
<os><osmatch name="Linux 5.X" accuracy="95">
<osclass type="general purpose" vendor="Linux" osfamily="Linux"/></osmatch></os>
</host>
""" + XML_FOOTER

MULTI_HOST_XML = XML_HEADER + """
<host><status state="up" reason="syn-ack"/>
<address addr="192.168.10.20" addrtype="ipv4"/>
<hostnames><hostname name="web01.example.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="9.6" method="probed"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" method="probed" product="nginx"/></port>
<port protocol="tcp" portid="3306"><state state="closed" reason="reset"/>
<service name="mysql"/></port>
<port protocol="tcp" portid="8443"><state state="filtered" reason="no-response"/></port>
</ports></host>
<host><status state="up" reason="echo-reply"/>
<address addr="192.168.10.30" addrtype="ipv4"/>
<hostnames><hostname name="db01.example.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="5432"><state state="open" reason="syn-ack"/>
<service name="postgresql" product="PostgreSQL DB" method="probed"/></port>
<port protocol="udp" portid="161">
<state state="open|filtered" reason="no-response"/>
<service name="snmp"/></port>
<port protocol="tcp" portid="9999"><state state="open" reason="syn-ack"/></port>
</ports></host>
""" + XML_FOOTER

IPV6_HOST_XML = XML_HEADER + """
<host><status state="up" reason="nd-response"/>
<address addr="2001:db8::20" addrtype="ipv6"/>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" method="probed"/></port></ports></host>
""" + XML_FOOTER

DUPLICATE_PORT_XML = XML_HEADER + """
<host><status state="up"/>
<address addr="192.168.10.40" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" method="probed"/>
<script id="ssh-hostkey" output="2048 aa:bb (RSA)"/></port>
</ports></host>
""" + XML_FOOTER

SCRIPT_XML = XML_HEADER + """
<host><status state="up"/>
<address addr="192.168.10.50" addrtype="ipv4"/>
<hostnames><hostname name="files01" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="445">
<state state="open" reason="syn-ack"/>
<service name="microsoft-ds" method="probed"/>
<script id="smb-protocols" output="dialects: NT LM 0.12 (SMBv1) 2.02 3.11"/>
<script id="smb-vuln-ms17-010" output="State: VULNERABLE - Remote code execution"/>
</port></ports>
<hostscript><script id="smb-os-discovery"
 output="OS: Windows Server 2019; note peer 192.168.10.30"/></hostscript>
</host>
""" + XML_FOOTER

DC_HOST_XML = XML_HEADER + """
<host><status state="up"/>
<address addr="192.168.10.10" addrtype="ipv4"/>
<hostnames><hostname name="dc01.example.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="53"><state state="open" reason="syn-ack"/>
<service name="domain" method="probed"/></port>
<port protocol="tcp" portid="88"><state state="open" reason="syn-ack"/>
<service name="kerberos-sec" method="probed"/></port>
<port protocol="tcp" portid="389"><state state="open" reason="syn-ack"/>
<service name="ldap" method="probed" product="Microsoft Windows Active Directory LDAP"/></port>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/>
<service name="microsoft-ds" method="probed"/></port>
</ports>
<os><osmatch name="Microsoft Windows Server 2019" accuracy="93">
<osclass type="general purpose"/></osmatch></os>
</host>
""" + XML_FOOTER

# Special characters (escaped entities and non-ASCII text) in service info.
SPECIAL_CHARS_XML = XML_HEADER + """
<host><status state="up"/>
<address addr="192.168.10.60" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" method="probed" product="Caf&#233; &amp; Server &lt;beta&gt;"/></port>
</ports></host>
""" + XML_FOOTER

EMPTY_SCAN_XML = XML_HEADER + XML_FOOTER

MISSING_SERVICE_XML = XML_HEADER + """
<host><status state="up"/>
<address addr="192.168.10.70" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="4444">
<state state="open" reason="syn-ack"/></port></ports></host>
""" + XML_FOOTER

INVALID_XML = "<nmaprun><host><status state="

NO_IP_HOST_XML = XML_HEADER + """
<host><status state="up"/>
<hostnames><hostname name="ghost.example.local" type="PTR"/></hostnames>
</host>
""" + XML_FOOTER


HOSTILE_XML = XML_HEADER.replace(
    'args="nmap -sS -sV -oX out.xml targets"',
    'args="=2+5+cmd|&#39; /C calc&#39;!A0 targets"',
) + """
<host><status state="up" reason="arp-response"/>
<address addr="192.168.10.66" addrtype="ipv4"/>
<hostnames><hostname name="=HYPERLINK(&quot;http://evil&quot;)" type="PTR"/>
<hostname name="host&quot;; A -&gt; B; &quot;" type="user"/></hostnames>
<ports><port protocol="tcp" portid="443">
<state state="open" reason="syn-ack"/>
<service name="http" product="+SUM(A1:A2)" version="-CMD()" tunnel="ssl"
 method="probed" conf="10"/>
<script id="ssl-cert" output="@HYPERLINK(&quot;example&quot;)&#10;line1&#10;line2&#10;&lt;script&gt;alert(1)&lt;/script&gt;&#10;node] --&gt; attacker&#10;value|new-column"/>
</port></ports>
</host>
""" + XML_FOOTER

IPV6_PAIR_XML = XML_HEADER + """
<host><status state="up" reason="nd-response"/>
<address addr="2001:db8::20" addrtype="ipv6"/>
<hostnames><hostname name="v6web.example.local" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="443">
<state state="open" reason="syn-ack"/>
<service name="http" tunnel="ssl" method="probed" conf="10"/>
</port></ports>
</host>
<host><status state="up" reason="nd-response"/>
<address addr="2001:db8::30" addrtype="ipv6"/>
<hostnames><hostname name="v6db.example.local" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="5432">
<state state="open" reason="syn-ack"/>
<service name="postgresql" method="probed" conf="10"/>
</port></ports>
</host>
""" + XML_FOOTER


def run_pipeline(xml, config, options):
    """Parse -> enrich -> records -> flows -> inbound/outbound (+ reviews)."""
    from nmap_flow_analyzer.firewall_rules import build_inbound, build_outbound
    from nmap_flow_analyzer.flow_analysis import build_flows, enrich_hosts
    from nmap_flow_analyzer.risk_analysis import build_service_records

    metadata, hosts = parse_xml(xml)
    enrich_hosts(hosts, config)
    records = build_service_records(hosts, config)
    result = build_flows(hosts, records, config, options)
    inbound, in_rev = build_inbound(result.flows, config, options)
    outbound, out_rev = build_outbound(result.flows, inbound, config, options)
    return {
        "metadata": metadata,
        "hosts": hosts,
        "records": records,
        "flows": result.flows,
        "flow_reviews": result.reviews,
        "inbound": inbound,
        "outbound": outbound,
        "rule_reviews": in_rev + out_rev,
        "reviews": result.reviews + in_rev + out_rev,
    }
