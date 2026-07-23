"""Risk analysis for exposed services.

All rules are transparent (each risk level comes with recorded reasons) and
configurable via ``policy.risk_overrides``.  Version detection alone never
produces a "confirmed vulnerability": NSE results are preserved as reported
and categorized separately.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

from .config import AnalyzerConfig
from .models import (
    EvidenceClass,
    Host,
    PortRecord,
    RISK_ORDER,
    RiskLevel,
    ScriptResult,
    ServiceRecord,
    VulnCategory,
    VulnFinding,
)
from .normalization import NormalizedService, normalize_service

LOG = logging.getLogger("nmap_flow_analyzer.risk_analysis")

ENCRYPTED_SERVICES = {
    "SSH",
    "HTTPS",
    "Alternate HTTPS",
    "LDAPS",
    "WinRM HTTPS",
    "Syslog over TLS",
    "IMAPS",
    "POP3S",
    "Proxmox Management",
    "RDP",  # protocol-level TLS is typical, though not verified
}
CLEARTEXT_SERVICES = {
    "Telnet",
    "FTP",
    "HTTP",
    "Alternate HTTP",
    "HTTP Proxy",
    "SNMP",
    "SNMP Trap",
    "LDAP",
    "POP3",
    "IMAP",
    "SMTP",
    "Syslog",
    "TFTP",
    "LPD Print",
    "IPP Print",
    "Raw Print",
    "MS RPC",
    "RPCbind",
    "NetBIOS Session",
    "DNS",
    "NTP",
    "DHCP",
    "VNC",
}
MANAGEMENT_SERVICES = {
    "SSH",
    "Telnet",
    "RDP",
    "VNC",
    "WinRM HTTP",
    "WinRM HTTPS",
    "SNMP",
    "Proxmox Management",
    "VMware Management",
    "IPP Print",
    "LPD Print",
}
DATABASE_SERVICES = {
    "Microsoft SQL Server",
    "Oracle",
    "MySQL",
    "PostgreSQL",
    "MS SQL Browser",
}
INFRA_DEVICE_CLASSES = {"network device", "security appliance", "printer", "storage device", "hypervisor"}
INFRA_ROLES = {
    "Network switch",
    "Router",
    "Firewall",
    "Wireless access point",
    "Printer",
    "Storage appliance",
    "Hypervisor",
    "Virtualization management server",
}

#: Patterns that indicate a product/OS is likely past end of support.  This is
#: a small offline heuristic; findings are always phrased as "possible" and
#: flagged for verification, never as confirmed vulnerabilities.
EOL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"windows (xp|2000|vista|server 2003|server 2008|7\b)", re.I), "Microsoft OS past end of support"),
    (re.compile(r"\biis[ /]([456])\.", re.I), "Microsoft IIS 4/5/6 (end of life)"),
    (re.compile(r"\bphp[ /]5\.", re.I), "PHP 5.x (end of life)"),
    (re.compile(r"\bsamba[ /]3\.", re.I), "Samba 3.x (end of life)"),
    (re.compile(r"openssl[ /](0\.9|1\.0\.[01])", re.I), "OpenSSL 0.9/1.0.0/1.0.1 (end of life)"),
    (re.compile(r"\bcentos( linux)?[ /]?[56]\b", re.I), "CentOS 5/6 (end of life)"),
]

_WEAK_TLS_TOKENS = ("sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "64-bit block cipher", "rc4")


def script_vuln_category(script: ScriptResult) -> Optional[str]:
    """Categorize an NSE script result; None when not security-relevant."""
    text = script.output.upper()
    sid = script.script_id.lower()
    if "LIKELY VULNERABLE" in text:
        return VulnCategory.LIKELY.value
    if "NOT VULNERABLE" in text:
        return VulnCategory.INFORMATIONAL.value
    if "STATE: VULNERABLE" in text or "VULNERABLE" in text:
        return VulnCategory.CONFIRMED.value
    if any(token in text for token in ("COULDN'T", "COULD NOT", "ERROR", "TIMEOUT", "UNKNOWN STATE")):
        if "vuln" in sid or "cve" in sid:
            return VulnCategory.UNDETERMINED.value
    if "vuln" in sid or "cve" in sid or sid.startswith("exploit"):
        return VulnCategory.POTENTIAL.value
    if sid in {
        "ssl-cert",
        "ssl-enum-ciphers",
        "smb-security-mode",
        "smb2-security-mode",
        "smb-protocols",
        "ftp-anon",
        "snmp-info",
        "http-title",
        "http-server-header",
    }:
        return VulnCategory.INFORMATIONAL.value
    return None


def collect_vuln_findings(hosts: List[Host]) -> List[VulnFinding]:
    """Preserve NSE vulnerability-relevant results as reported."""
    findings: List[VulnFinding] = []
    for host in hosts:
        sources: List[Tuple[str, str, List[ScriptResult]]] = [("", "", host.host_scripts)]
        sources.extend(
            (rec.protocol, str(rec.port), rec.scripts) for rec in host.ports
        )
        for protocol, port, scripts in sources:
            for script in scripts:
                category = script_vuln_category(script)
                if category is None:
                    continue
                excerpt = " ".join(script.output.split())
                findings.append(
                    VulnFinding(
                        host=host.display_name,
                        ip=host.primary_ip,
                        protocol=protocol,
                        port=port,
                        script_id=script.script_id,
                        category=category,
                        excerpt=excerpt[:400] + ("..." if len(excerpt) > 400 else ""),
                    )
                )
    findings.sort(key=lambda f: (f.ip, f.port, f.script_id))
    return findings


def encryption_status(rec: PortRecord, norm: NormalizedService) -> str:
    if rec.tunnel.lower() == "ssl":
        return "Encrypted (TLS tunnel reported)"
    if norm.final in ENCRYPTED_SERVICES:
        return "Encrypted (protocol default; not independently verified)"
    if norm.final in CLEARTEXT_SERVICES:
        return "Cleartext"
    return "Unknown"


def authentication_status(rec: PortRecord, norm: NormalizedService) -> str:
    for script in rec.scripts:
        text = script.output.lower()
        if script.script_id == "ftp-anon" and "anonymous ftp login allowed" in text:
            return "Anonymous access indicated (ftp-anon)"
        if script.script_id.startswith("smb") and ("anonymous" in text or "guest" in text):
            return "Anonymous/guest access indicated by NSE"
        if script.script_id == "smb2-security-mode" and "not required" in text:
            return "SMB signing not required (per NSE)"
    if norm.final in {"SSH", "RDP", "LDAP", "LDAPS", "SMB", "WinRM HTTP", "WinRM HTTPS", "VNC"} | DATABASE_SERVICES:
        return "Protocol requires authentication (not verified)"
    return "Unknown"


def _scripts_text(rec: PortRecord) -> str:
    return " ".join(f"{s.script_id} {s.output}" for s in rec.scripts).lower()


def assess_port(
    host: Host, rec: PortRecord, norm: NormalizedService, config: AnalyzerConfig
) -> Tuple[str, List[str]]:
    """Return (risk_level, reasons) for one port using transparent rules."""
    if rec.state == "open|filtered":
        return (
            RiskLevel.INFORMATIONAL.value,
            ["Port state uncertain (open|filtered); no risk rating assigned"],
        )
    if rec.state != "open":
        return (RiskLevel.INFORMATIONAL.value, [])

    level = RiskLevel.LOW.value
    reasons: List[str] = []
    scripts = _scripts_text(rec)
    products = f"{rec.product} {rec.version} {rec.extrainfo} {host.best_os}".strip()
    final = norm.final
    infra_device = host.device_class in INFRA_DEVICE_CLASSES or host.role in INFRA_ROLES

    def bump(candidate: str, reason: str) -> None:
        nonlocal level
        reasons.append(reason)
        if RISK_ORDER[candidate] > RISK_ORDER[level]:
            level = candidate

    if final == "Telnet":
        bump(RiskLevel.HIGH.value, "Telnet: cleartext remote administration")
    if final == "FTP" and rec.tunnel.lower() != "ssl":
        bump(RiskLevel.MEDIUM.value, "FTP without encryption (cleartext credentials)")
        if "anonymous ftp login allowed" in scripts:
            bump(RiskLevel.HIGH.value, "Anonymous FTP access reported by ftp-anon")
    if final in {"HTTP", "Alternate HTTP"}:
        bump(RiskLevel.MEDIUM.value, "Unencrypted HTTP service")
        if infra_device:
            bump(RiskLevel.HIGH.value, "Cleartext HTTP management interface on infrastructure device")
    if final in {"SMB", "NetBIOS Session"}:
        bump(RiskLevel.MEDIUM.value, "SMB exposed; restrict to trusted zones")
        if "smbv1" in scripts or "nt lm 0.12" in scripts:
            bump(RiskLevel.HIGH.value, "SMBv1 dialect enabled per NSE output")
        if "anonymous" in scripts or "guest" in scripts:
            bump(RiskLevel.HIGH.value, "Anonymous/guest SMB access indicated by NSE")
    if final in {"SNMP", "SNMP Trap"}:
        bump(RiskLevel.MEDIUM.value, "SNMP v1/v2c uses cleartext community strings (version not confirmed)")
        if re.search(r"\b(public|private)\b", scripts):
            bump(RiskLevel.HIGH.value, "Default SNMP community string indicated by NSE output")
    if final == "RDP":
        bump(RiskLevel.MEDIUM.value, "RDP exposed; restrict source to management network")
    if final == "SSH":
        bump(RiskLevel.LOW.value, "SSH remote administration; restrict source to management network")
    if final in DATABASE_SERVICES:
        host_cfg = config.host_cfg(host.primary_ip)
        approved = bool(host_cfg and host_cfg.approved_entry(rec.protocol, rec.port))
        if approved:
            bump(RiskLevel.MEDIUM.value, "Database service exposed (approved in configuration; verify scope)")
        else:
            bump(RiskLevel.HIGH.value, "Database service exposed outside an approved application/management scope")
    if final == "NFS":
        bump(RiskLevel.MEDIUM.value, "NFS export service exposed; verify export restrictions")
    if final == "LDAP":
        bump(RiskLevel.MEDIUM.value, "Cleartext LDAP (credentials/queries unencrypted)")
    if final in {"MS RPC", "RPCbind"}:
        bump(RiskLevel.MEDIUM.value, "RPC endpoint mapper exposed")
    if final in {"LPD Print", "IPP Print", "Raw Print"}:
        bump(RiskLevel.MEDIUM.value, "Printer service exposed; restrict to print servers/users")
    if final in {"Proxmox Management", "VMware Management"} or (
        final in {"HTTPS", "Alternate HTTPS"}
        and re.search(r"(vmware|proxmox|idrac|ilo|ipmi|vcenter)", products, re.I)
    ):
        bump(RiskLevel.HIGH.value, "Hypervisor/out-of-band management interface exposed")
    if final == "WinRM HTTP":
        bump(RiskLevel.MEDIUM.value, "WinRM over HTTP (management channel not TLS-wrapped)")
    if final == "VNC":
        bump(RiskLevel.MEDIUM.value, "VNC remote-control service exposed")
    if norm.mismatch:
        bump(RiskLevel.MEDIUM.value, f"Service/port mismatch: {norm.note}")
    if final == "Unknown":
        bump(RiskLevel.MEDIUM.value, "Unidentified service on an open port")
    if rec.tunnel.lower() == "ssl":
        for token in _WEAK_TLS_TOKENS:
            if token in scripts:
                bump(RiskLevel.HIGH.value, f"Weak TLS configuration indicated by NSE ('{token}')")
                break
    for pattern, label in EOL_PATTERNS:
        if pattern.search(products):
            bump(
                RiskLevel.HIGH.value,
                f"Possible end-of-life software: {label} (verify manually; version detection is not proof)",
            )
            break

    # NSE vulnerability categories escalate the port risk.
    for script in rec.scripts:
        category = script_vuln_category(script)
        if category == VulnCategory.CONFIRMED.value:
            bump(RiskLevel.CRITICAL.value, f"NSE script '{script.script_id}' reports VULNERABLE state")
        elif category == VulnCategory.LIKELY.value:
            bump(RiskLevel.HIGH.value, f"NSE script '{script.script_id}' reports likely vulnerable")
        elif category == VulnCategory.POTENTIAL.value:
            bump(RiskLevel.MEDIUM.value, f"NSE script '{script.script_id}' indicates a potential issue")

    # Configuration-driven overrides are applied last and win.
    for override in config.policy.risk_overrides:
        service = override.get("service")
        port = override.get("port")
        protocol = str(override.get("protocol", rec.protocol)).lower()
        matched = False
        if service and str(service) == final:
            matched = True
        if port is not None and int(port) == rec.port and protocol == rec.protocol:
            matched = True
        if matched and str(override.get("level")) in RISK_ORDER:
            level = str(override["level"])
            reasons.append(f"Risk level set to {level} by policy.risk_overrides")

    if not reasons:
        reasons.append("No elevated-risk indicators matched; baseline exposure")
    return level, reasons


def always_manual_review(rec: PortRecord, norm: NormalizedService, config: AnalyzerConfig) -> bool:
    """True when policy requires manual review for this port/service."""
    for entry in config.policy.always_manual_review:
        if "port" in entry:
            if int(entry["port"]) == rec.port and entry.get("protocol", "tcp") == rec.protocol:
                return True
        service = entry.get("service")
        if service and str(service) in {norm.final, norm.expected, norm.detected}:
            return True
    return False


def build_service_records(hosts: List[Host], config: AnalyzerConfig) -> List[ServiceRecord]:
    """Build the flattened, risk-assessed service inventory (all port states)."""
    records: List[ServiceRecord] = []
    for host in hosts:
        host_cfg = config.host_cfg(host.primary_ip)
        for rec in sorted(host.ports, key=lambda p: (p.protocol, p.port)):
            norm = normalize_service(rec)
            level, reasons = assess_port(host, rec, norm, config)
            if rec.state == "open":
                evidence = EvidenceClass.OBSERVED.value
            elif rec.state == "open|filtered":
                evidence = EvidenceClass.MANUAL_REVIEW.value
            else:
                evidence = EvidenceClass.UNKNOWN.value
            approved = "not specified"
            if host_cfg:
                entry = host_cfg.approved_entry(rec.protocol, rec.port)
                if entry is not None:
                    approved = "yes" if entry.get("approved", True) else "no"
                elif host_cfg.approved_services:
                    approved = "no"  # an approval list exists and this port is absent
            records.append(
                ServiceRecord(
                    hostname=host.display_name,
                    ip=host.primary_ip,
                    zone=host.zone,
                    role=host.role,
                    protocol=rec.protocol,
                    port=rec.port,
                    state=rec.state,
                    reason=rec.reason,
                    detected_service=norm.detected_raw,
                    product=rec.product,
                    version=rec.version,
                    extrainfo=rec.extrainfo,
                    tunnel=rec.tunnel,
                    normalized_service=norm.final,
                    expected_service=norm.expected,
                    mismatch=norm.mismatch,
                    mismatch_note=norm.note,
                    cpes=list(rec.cpes),
                    scripts=[s.script_id for s in rec.scripts],
                    risk_level=level,
                    risk_reasons=reasons,
                    encryption=encryption_status(rec, norm),
                    authentication=authentication_status(rec, norm),
                    evidence_class=evidence,
                    approved=approved,
                )
            )
    return records
