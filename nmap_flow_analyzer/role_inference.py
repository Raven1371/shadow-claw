"""Weighted host-role inference.

Combines hostname patterns, OS matches, device types, open ports, service
products, NSE output, MAC vendor, and user configuration into a scored role
guess.  Weak evidence never produces a definitive role: below the assignment
threshold the host stays "Unknown" and the candidates are recorded as
evidence only.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .models import Host
from .normalization import normalize_service
from .pluralize import plural

LOG = logging.getLogger("nmap_flow_analyzer.role_inference")

#: Minimum score for a definitive role assignment.
ASSIGNMENT_THRESHOLD = 40
#: If the runner-up is within this margin, record the ambiguity.
AMBIGUITY_MARGIN = 10

KNOWN_ROLES = [
    "Domain controller",
    "DNS server",
    "DHCP server",
    "Web server",
    "Database server",
    "File server",
    "Mail server",
    "Hypervisor",
    "Virtualization management server",
    "Backup server",
    "SIEM or logging server",
    "Network switch",
    "Router",
    "Firewall",
    "Wireless access point",
    "Printer",
    "Storage appliance",
    "Workstation",
    "Linux server",
    "Windows server",
    "Security appliance",
    "Unknown",
]


@dataclass
class RoleInference:
    role: str = "Unknown"
    confidence: int = 0
    evidence: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    source: str = "none"


@dataclass
class _Facts:
    """Pre-extracted evidence for scoring rules."""

    hostname: str
    os_names: str
    device_types: Set[str]
    vendor: str
    products: str
    scripts_text: str
    services: Set[str]
    tcp_ports: Set[int]
    udp_ports: Set[int]
    open_count: int


def _facts(host: Host) -> _Facts:
    services: Set[str] = set()
    tcp: Set[int] = set()
    udp: Set[int] = set()
    products: List[str] = []
    for rec in host.ports:
        if rec.state not in {"open", "open|filtered"}:
            continue
        norm = normalize_service(rec)
        services.add(norm.final)
        if rec.protocol == "tcp" and rec.state == "open":
            tcp.add(rec.port)
        elif rec.protocol == "udp":
            udp.add(rec.port)
        if rec.product:
            products.append(f"{rec.product} {rec.version}".strip())
    scripts = [s.output for s in host.host_scripts]
    for rec in host.ports:
        scripts.extend(s.output for s in rec.scripts)
    return _Facts(
        hostname=" ".join(host.hostnames).lower(),
        os_names=" ".join(m.name for m in host.os_matches).lower(),
        device_types={t.lower() for t in host.device_types},
        vendor=host.mac_vendor.lower(),
        products=" ".join(products).lower(),
        scripts_text=" ".join(scripts).lower(),
        services=services,
        tcp_ports=tcp,
        udp_ports=udp,
        open_count=len(host.open_ports()),
    )


def _score(host: Host, f: _Facts) -> Dict[str, List[Tuple[int, str]]]:
    """Return {role: [(weight, evidence), ...]} using transparent rules."""
    s: Dict[str, List[Tuple[int, str]]] = defaultdict(list)

    def add(role: str, weight: int, why: str) -> None:
        s[role].append((weight, why))

    # --- Directory / domain services
    dc_ports = {88, 389, 445} & f.tcp_ports
    if {"Kerberos", "LDAP"} <= f.services:
        add("Domain controller", 40, "Kerberos and LDAP services open")
    if len(dc_ports) == 3 and 53 in (f.tcp_ports | f.udp_ports):
        add("Domain controller", 20, "Full AD port set (88/389/445 + DNS)")
    if "active directory" in f.products or "active directory" in f.scripts_text:
        add("Domain controller", 25, "Active Directory referenced in service/NSE data")
    for token in ("dc0", "dc1", "dc2", "-dc", "dc-", "domaincontroller"):
        if token in f.hostname:
            add("Domain controller", 20, f"Hostname contains '{token}'")
            break

    # --- DNS / DHCP
    if "DNS" in f.services:
        add("DNS server", 30, "DNS service open")
        if f.services <= {"DNS", "NTP", "SSH", "Unknown"}:
            add("DNS server", 15, "Host exposes little besides DNS")
    if 67 in f.udp_ports:
        add("DHCP server", 35, "UDP/67 (DHCP server) responding")

    # --- Web / DB / file / mail
    if f.services & {"HTTP", "HTTPS", "Alternate HTTP", "Alternate HTTPS"}:
        add("Web server", 20, "HTTP/HTTPS service open")
        for product in ("nginx", "apache", "iis", "lighttpd", "tomcat", "caddy"):
            if product in f.products:
                add("Web server", 15, f"Web server product '{product}' detected")
                break
    db = f.services & {"Microsoft SQL Server", "Oracle", "MySQL", "PostgreSQL"}
    if db:
        add("Database server", 40,
            f"Database {plural('service', len(db))} open: "
            f"{', '.join(sorted(db))}")
    if f.services & {"SMB", "NFS", "NetBIOS Session"} and not dc_ports == {88, 389, 445}:
        add("File server", 25, "SMB/NFS file service open")
    if f.services & {"SMTP", "SMTP Submission", "IMAP", "IMAPS", "POP3", "POP3S"}:
        add("Mail server", 30, "Mail protocol service open")

    # --- Virtualization / backup / logging
    if "Proxmox Management" in f.services or "proxmox" in f.products:
        add("Hypervisor", 50, "Proxmox management interface detected")
    if "esxi" in f.products or "esxi" in f.os_names or "VMware Management" in f.services:
        add("Hypervisor", 45, "VMware ESXi indicators")
    if "vcenter" in f.products or "vcenter" in f.hostname:
        add("Virtualization management server", 45, "vCenter indicators")
    for product in ("veeam", "bacula", "networker", "commvault", "bareos"):
        if product in f.products or product in f.hostname:
            add("Backup server", 40, f"Backup product indicator '{product}'")
            break
    if f.services & {"Syslog", "Syslog over TLS"}:
        add("SIEM or logging server", 35, "Syslog listener open")
    for product in ("splunk", "graylog", "elastic", "wazuh", "logstash"):
        if product in f.products or product in f.hostname:
            add("SIEM or logging server", 30, f"Logging product indicator '{product}'")
            break

    # --- Network / security devices (device type from Nmap osclass first)
    for dtype, role in (
        ("switch", "Network switch"),
        ("router", "Router"),
        ("firewall", "Firewall"),
        ("wap", "Wireless access point"),
        ("bridge", "Network switch"),
        ("printer", "Printer"),
        ("storage-misc", "Storage appliance"),
    ):
        if dtype in f.device_types:
            add(role, 45, f"Nmap device type '{dtype}'")
    for token, role in (
        ("cisco ios", "Network switch"),
        ("junos", "Router"),
        ("routeros", "Router"),
        ("fortinet", "Firewall"),
        ("fortios", "Firewall"),
        ("palo alto", "Firewall"),
        ("pfsense", "Firewall"),
        ("opnsense", "Firewall"),
    ):
        if token in f.os_names or token in f.products:
            add(role, 35, f"OS/product indicator '{token}'")
    for vendor, role in (
        ("cisco", "Network switch"),
        ("juniper", "Router"),
        ("aruba", "Wireless access point"),
        ("ubiquiti", "Wireless access point"),
        ("fortinet", "Firewall"),
        ("palo alto", "Firewall"),
    ):
        if vendor in f.vendor:
            add(role, 15, f"MAC vendor '{host.mac_vendor}'")

    # --- Printers / storage
    if f.tcp_ports & {9100, 515, 631}:
        add("Printer", 35, "Printing service ports open (9100/515/631)")
    for vendor in ("hewlett packard", "canon", "epson", "brother", "lexmark", "kyocera"):
        if vendor in f.vendor:
            add("Printer", 20, f"Printer-class MAC vendor '{host.mac_vendor}'")
            break
    for token in ("synology", "qnap", "netapp", "truenas", "freenas", "isilon"):
        if token in f.products or token in f.os_names or token in f.hostname:
            add("Storage appliance", 40, f"Storage product indicator '{token}'")
            break

    # --- Generic OS roles
    if "windows" in f.os_names or "microsoft" in f.products or "MS RPC" in f.services:
        workstation_os = any(t in f.os_names for t in ("windows 10", "windows 11", "windows 7"))
        if workstation_os and f.open_count <= 4 and not db:
            add("Workstation", 30, "Client Windows OS with few exposed services")
        add("Windows server", 15, "Windows OS/service indicators")
    if "linux" in f.os_names:
        add("Linux server", 12, "Linux OS match")
    if "general purpose" in f.device_types and f.open_count == 0:
        add("Workstation", 10, "General-purpose device with no open services")

    return s


def infer_role(host: Host, configured_role: str = "") -> RoleInference:
    """Infer the most likely role for a host.

    A user-configured role always wins (confidence 100, source recorded as
    user configuration).  Otherwise weighted XML evidence is scored, and a
    role is assigned only when the top score meets the threshold.
    """
    if configured_role:
        return RoleInference(
            role=configured_role,
            confidence=100,
            evidence=[f"Role '{configured_role}' supplied in configuration"],
            source="user configuration",
        )

    facts = _facts(host)
    scored = _score(host, facts)
    if not scored:
        return RoleInference(
            role="Unknown",
            confidence=0,
            evidence=["No role evidence available in scan data"],
            source="xml evidence",
        )

    totals = sorted(
        (
            (min(100, sum(w for w, _ in items)), role, [why for _, why in items])
            for role, items in scored.items()
        ),
        key=lambda item: (-item[0], item[1]),
    )
    best_score, best_role, best_evidence = totals[0]
    contradictions: List[str] = []
    for score, role, evidence in totals[1:]:
        if best_score - score <= AMBIGUITY_MARGIN and score > 0:
            contradictions.append(
                f"Competing evidence for '{role}' (score {score}): {evidence[0]}"
            )

    if best_score < ASSIGNMENT_THRESHOLD:
        candidates = ", ".join(f"{role} ({score})" for score, role, _ in totals[:3])
        return RoleInference(
            role="Unknown",
            confidence=best_score,
            evidence=[f"Evidence too weak for a definitive role; candidates: {candidates}"]
            + best_evidence,
            contradictions=contradictions,
            source="xml evidence",
        )
    return RoleInference(
        role=best_role,
        confidence=best_score,
        evidence=best_evidence,
        contradictions=contradictions,
        source="xml evidence",
    )