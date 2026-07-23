"""Service normalization.

Maps (protocol, port) to an expected service name, normalizes Nmap-detected
service names, and flags mismatches.  A service is never assumed correct
based only on its port number: both the detected service and the port-based
expected service are recorded, and detection wins when Nmap actively probed
the service.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

from .models import PortRecord

#: Registered / conventional service by (protocol, port).
PORT_SERVICE_MAP: Dict[Tuple[str, int], str] = {
    ("tcp", 21): "FTP",
    ("tcp", 22): "SSH",
    ("tcp", 23): "Telnet",
    ("tcp", 25): "SMTP",
    ("tcp", 53): "DNS",
    ("udp", 53): "DNS",
    ("udp", 67): "DHCP",
    ("udp", 68): "DHCP",
    ("udp", 69): "TFTP",
    ("tcp", 80): "HTTP",
    ("tcp", 88): "Kerberos",
    ("udp", 88): "Kerberos",
    ("tcp", 110): "POP3",
    ("tcp", 111): "RPCbind",
    ("udp", 111): "RPCbind",
    ("udp", 123): "NTP",
    ("tcp", 135): "MS RPC",
    ("tcp", 139): "NetBIOS Session",
    ("tcp", 143): "IMAP",
    ("udp", 161): "SNMP",
    ("udp", 162): "SNMP Trap",
    ("tcp", 389): "LDAP",
    ("tcp", 443): "HTTPS",
    ("tcp", 445): "SMB",
    ("tcp", 464): "Kerberos Password",
    ("udp", 464): "Kerberos Password",
    ("udp", 514): "Syslog",
    ("tcp", 515): "LPD Print",
    ("tcp", 587): "SMTP Submission",
    ("tcp", 631): "IPP Print",
    ("udp", 631): "IPP Print",
    ("tcp", 636): "LDAPS",
    ("tcp", 902): "VMware Management",
    ("tcp", 993): "IMAPS",
    ("tcp", 995): "POP3S",
    ("tcp", 1433): "Microsoft SQL Server",
    ("udp", 1434): "MS SQL Browser",
    ("tcp", 1521): "Oracle",
    ("udp", 1812): "RADIUS",
    ("tcp", 2049): "NFS",
    ("udp", 2049): "NFS",
    ("tcp", 3128): "HTTP Proxy",
    ("tcp", 3268): "LDAP Global Catalog",
    ("tcp", 3306): "MySQL",
    ("tcp", 3389): "RDP",
    ("tcp", 5432): "PostgreSQL",
    ("tcp", 5900): "VNC",
    ("tcp", 5985): "WinRM HTTP",
    ("tcp", 5986): "WinRM HTTPS",
    ("tcp", 6514): "Syslog over TLS",
    ("tcp", 8006): "Proxmox Management",
    ("tcp", 8080): "Alternate HTTP",
    ("tcp", 8443): "Alternate HTTPS",
    ("tcp", 9100): "Raw Print",
}

#: Nmap service-name aliases → normalized name (lower-cased keys).
SERVICE_ALIASES: Dict[str, str] = {
    "ftp": "FTP",
    "ssh": "SSH",
    "telnet": "Telnet",
    "smtp": "SMTP",
    "submission": "SMTP Submission",
    "domain": "DNS",
    "dns": "DNS",
    "dhcps": "DHCP",
    "dhcpc": "DHCP",
    "bootps": "DHCP",
    "tftp": "TFTP",
    "http": "HTTP",
    "https": "HTTPS",
    "http-alt": "Alternate HTTP",
    "https-alt": "Alternate HTTPS",
    "http-proxy": "HTTP Proxy",
    "squid-http": "HTTP Proxy",
    "kerberos-sec": "Kerberos",
    "kerberos": "Kerberos",
    "kpasswd5": "Kerberos Password",
    "pop3": "POP3",
    "pop3s": "POP3S",
    "imap": "IMAP",
    "imaps": "IMAPS",
    "rpcbind": "RPCbind",
    "sunrpc": "RPCbind",
    "ntp": "NTP",
    "msrpc": "MS RPC",
    "netbios-ssn": "NetBIOS Session",
    "snmp": "SNMP",
    "snmptrap": "SNMP Trap",
    "ldap": "LDAP",
    "ldapssl": "LDAPS",
    "ldaps": "LDAPS",
    "globalcatldap": "LDAP Global Catalog",
    "microsoft-ds": "SMB",
    "smb": "SMB",
    "syslog": "Syslog",
    "syslog-tls": "Syslog over TLS",
    "printer": "LPD Print",
    "ipp": "IPP Print",
    "jetdirect": "Raw Print",
    "ms-sql-s": "Microsoft SQL Server",
    "ms-sql-m": "MS SQL Browser",
    "oracle": "Oracle",
    "oracle-tns": "Oracle",
    "radius": "RADIUS",
    "nfs": "NFS",
    "mysql": "MySQL",
    "ms-wbt-server": "RDP",
    "rdp": "RDP",
    "postgresql": "PostgreSQL",
    "vnc": "VNC",
    "wsman": "WinRM HTTP",
    "wsmans": "WinRM HTTPS",
    "vmware-auth": "VMware Management",
}

#: Detected names that mean "not actually identified".
UNIDENTIFIED_NAMES: Set[str] = {"", "unknown", "tcpwrapped"}

#: Groups considered equivalent for mismatch purposes.
_EQUIVALENT_GROUPS: List[Set[str]] = [
    {"HTTP", "Alternate HTTP", "HTTP Proxy"},
    {"HTTPS", "Alternate HTTPS", "Proxmox Management", "WinRM HTTPS"},
    {"SMB", "NetBIOS Session"},
    {"LDAP", "LDAP Global Catalog"},
    {"Syslog", "Syslog over TLS"},
    {"SMTP", "SMTP Submission"},
]


@dataclass
class NormalizedService:
    expected: str  # from the port/protocol registry ("" if unregistered)
    detected_raw: str  # nmap's service name attribute as reported
    detected: str  # normalized detected name ("" if unidentified)
    final: str  # the name used in reports
    mismatch: bool
    note: str


def normalize_port(protocol: str, port: int) -> str:
    """Expected service for a port/protocol pair, or '' if unregistered."""
    return PORT_SERVICE_MAP.get((protocol.lower(), port), "")


def normalize_detected(name: str, tunnel: str = "") -> str:
    """Normalize an Nmap-detected service name; '' if unidentified."""
    raw = (name or "").strip().lower()
    if raw in UNIDENTIFIED_NAMES:
        return ""
    normalized = SERVICE_ALIASES.get(raw, name.strip())
    if tunnel.lower() == "ssl" and normalized == "HTTP":
        normalized = "HTTPS"
    return normalized


def services_equivalent(a: str, b: str) -> bool:
    if a == b:
        return True
    return any(a in group and b in group for group in _EQUIVALENT_GROUPS)


def normalize_service(rec: PortRecord) -> NormalizedService:
    """Normalize a port record's service, preferring active detection.

    Detection wins over the port registry only when Nmap actually probed the
    service (``method="probed"``); table-derived names are just the registry
    restated by Nmap.
    """
    expected = normalize_port(rec.protocol, rec.port)
    detected = normalize_detected(rec.service_name, rec.tunnel)
    notes: List[str] = []

    if detected and rec.detection_method == "probed":
        final = detected
    elif expected:
        final = expected
        if detected and rec.detection_method != "probed":
            notes.append("Service name from Nmap port table, not active probing")
    elif detected:
        final = detected
    else:
        final = "Unknown"
        if (rec.service_name or "").strip().lower() == "tcpwrapped":
            notes.append("Nmap reported 'tcpwrapped' (connection accepted, no banner)")
        else:
            notes.append("Service could not be identified")

    mismatch = bool(
        expected
        and detected
        and rec.detection_method == "probed"
        and not services_equivalent(expected, detected)
    )
    if mismatch:
        notes.append(
            f"Detected {detected} on {rec.protocol}/{rec.port}, which is "
            f"registered for {expected}"
        )
    return NormalizedService(
        expected=expected,
        detected_raw=rec.service_name,
        detected=detected,
        final=final,
        mismatch=mismatch,
        note="; ".join(notes),
    )
