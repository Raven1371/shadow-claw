"""Secure, memory-bounded parser for Nmap XML reports.

Uses ``defusedxml.ElementTree`` when available (strongly preferred) and falls
back to the standard library with a loud warning.  Parsing is incremental
(``iterparse``) and each processed ``<host>`` element is cleared so very large
reports do not accumulate in memory.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .pluralize import count_noun
from .models import (
    Host,
    OSMatch,
    PortRecord,
    ScanMetadata,
    ScriptResult,
    TracerouteHop,
    ip_sort_key,
)

try:  # pragma: no cover - exercised implicitly
    from defusedxml import ElementTree as ET
    from defusedxml.common import DefusedXmlException

    SECURE_PARSER = True
except ImportError:  # pragma: no cover - fallback path
    import xml.etree.ElementTree as ET  # type: ignore[no-redef]

    class DefusedXmlException(Exception):  # type: ignore[no-redef]
        """Placeholder when defusedxml is unavailable."""

    SECURE_PARSER = False

LOG = logging.getLogger("nmap_flow_analyzer.parser")

VALID_PORT_STATES = {
    "open",
    "open|filtered",
    "filtered",
    "closed",
    "closed|filtered",
    "unfiltered",
}


class ParserError(Exception):
    """Raised when the input XML cannot be parsed safely."""


def _to_int(value: Optional[str], default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _build_port(elem) -> Optional[PortRecord]:
    """Build a PortRecord from a ``<port>`` element; None if invalid."""
    portid = _to_int(elem.get("portid"), -1)
    if not 0 <= portid <= 65535:
        LOG.warning("Ignoring port element with invalid portid=%r", elem.get("portid"))
        return None
    rec = PortRecord(protocol=(elem.get("protocol") or "tcp").lower(), port=portid)

    state = elem.find("state")
    if state is not None:
        rec.state = (state.get("state") or "unknown").lower()
        rec.reason = state.get("reason") or ""
    if rec.state not in VALID_PORT_STATES and rec.state != "unknown":
        LOG.debug("Uncommon port state %r on port %s", rec.state, portid)

    service = elem.find("service")
    if service is not None:
        rec.service_name = service.get("name") or ""
        rec.product = service.get("product") or ""
        rec.version = service.get("version") or ""
        rec.extrainfo = service.get("extrainfo") or ""
        rec.tunnel = service.get("tunnel") or ""
        rec.detection_method = service.get("method") or ""
        rec.detection_confidence = service.get("conf") or ""
        for cpe in service.findall("cpe"):
            if cpe.text and cpe.text not in rec.cpes:
                rec.cpes.append(cpe.text)

    for script in elem.findall("script"):
        rec.scripts.append(
            ScriptResult(
                script_id=script.get("id") or "",
                output=script.get("output") or "",
                scope="port",
            )
        )
    return rec


def _richness(rec: PortRecord) -> int:
    """Heuristic used when merging duplicate port entries."""
    score = 0
    if rec.state == "open":
        score += 4
    if rec.service_name:
        score += 2
    score += min(len(rec.scripts), 3)
    if rec.product:
        score += 1
    return score


def _add_port(host: Host, rec: PortRecord) -> None:
    """Add a port record, merging duplicates deterministically."""
    for existing in host.ports:
        if existing.protocol == rec.protocol and existing.port == rec.port:
            LOG.debug(
                "Duplicate %s/%s on %s; merging",
                rec.protocol,
                rec.port,
                host.primary_ip or "host",
            )
            keep, drop = (rec, existing) if _richness(rec) > _richness(existing) else (existing, rec)
            for s in drop.scripts:
                if all(s.script_id != k.script_id for k in keep.scripts):
                    keep.scripts.append(s)
            for c in drop.cpes:
                if c not in keep.cpes:
                    keep.cpes.append(c)
            if keep is rec:
                host.ports[host.ports.index(existing)] = rec
            return
    host.ports.append(rec)


def _build_host(elem) -> Host:
    host = Host()

    status = elem.find("status")
    if status is not None:
        host.state = status.get("state") or "unknown"
        host.state_reason = status.get("reason") or ""

    for addr in elem.findall("address"):
        addr_type = addr.get("addrtype") or ""
        value = addr.get("addr") or ""
        if addr_type == "ipv4":
            host.ipv4 = value
        elif addr_type == "ipv6":
            host.ipv6 = value
        elif addr_type == "mac":
            host.mac = value
            host.mac_vendor = addr.get("vendor") or ""

    hostnames = elem.find("hostnames")
    if hostnames is not None:
        for hn in hostnames.findall("hostname"):
            name = hn.get("name") or ""
            if name and name not in host.hostnames:
                host.hostnames.append(name)

    ports = elem.find("ports")
    if ports is not None:
        for port_elem in ports.findall("port"):
            rec = _build_port(port_elem)
            if rec is not None:
                _add_port(host, rec)

    os_elem = elem.find("os")
    if os_elem is not None:
        for match in os_elem.findall("osmatch"):
            osm = OSMatch(
                name=match.get("name") or "",
                accuracy=_to_int(match.get("accuracy")),
            )
            for osclass in match.findall("osclass"):
                dtype = osclass.get("type") or ""
                if dtype:
                    if dtype not in osm.device_types:
                        osm.device_types.append(dtype)
                    if dtype not in host.device_types:
                        host.device_types.append(dtype)
            host.os_matches.append(osm)
        host.os_matches.sort(key=lambda m: (-m.accuracy, m.name))

    trace = elem.find("trace")
    if trace is not None:
        for hop in trace.findall("hop"):
            host.traceroute.append(
                TracerouteHop(
                    ttl=_to_int(hop.get("ttl")),
                    ip=hop.get("ipaddr") or "",
                    rtt=hop.get("rtt") or "",
                    host=hop.get("host") or "",
                )
            )

    hostscript = elem.find("hostscript")
    if hostscript is not None:
        for script in hostscript.findall("script"):
            host.host_scripts.append(
                ScriptResult(
                    script_id=script.get("id") or "",
                    output=script.get("output") or "",
                    scope="host",
                )
            )
    return host


def _merge_host(base: Host, extra: Host) -> None:
    """Merge a duplicate host record (same primary IP) into ``base``."""
    for name in extra.hostnames:
        if name not in base.hostnames:
            base.hostnames.append(name)
    for rec in extra.ports:
        _add_port(base, rec)
    if not base.os_matches:
        base.os_matches = extra.os_matches
    if not base.mac:
        base.mac, base.mac_vendor = extra.mac, extra.mac_vendor
    if base.state != "up" and extra.state == "up":
        base.state, base.state_reason = extra.state, extra.state_reason
    for script in extra.host_scripts:
        if all(script.script_id != s.script_id for s in base.host_scripts):
            base.host_scripts.append(script)


def parse_nmap_xml(path: Path) -> Tuple[ScanMetadata, List[Host]]:
    """Parse an Nmap XML file into scan metadata and host records.

    Raises :class:`ParserError` for missing files, invalid XML, non-Nmap XML,
    or XML containing forbidden entity constructs.
    """
    path = Path(path)
    if not path.is_file():
        raise ParserError(f"Input file not found: {path}")
    if not SECURE_PARSER:
        LOG.warning(
            "defusedxml is not installed; falling back to the standard XML "
            "parser. Install defusedxml for safe parsing of untrusted input."
        )

    metadata = ScanMetadata(source_file=path.name)
    hosts: Dict[str, Host] = {}
    source = None

    try:
        # Open the input ourselves so early parser exits cannot leave the
        # internally opened iterparse handle alive on Windows.
        source = path.open("rb")
        context = ET.iterparse(source, events=("start", "end"))
        try:
            event, root = next(context)
        except StopIteration as exc:
            raise ParserError(f"Empty or unreadable XML file: {path.name}") from exc
        if root.tag != "nmaprun":
            raise ParserError(
                f"Not an Nmap XML report (root element is <{root.tag}>, expected <nmaprun>)"
            )
        metadata.command_line = root.get("args") or ""
        metadata.args = metadata.command_line
        metadata.nmap_version = root.get("version") or ""
        metadata.xml_version = root.get("xmloutputversion") or ""
        metadata.scanner = root.get("scanner") or ""
        metadata.start_time = root.get("startstr") or root.get("start") or ""

        for event, elem in context:
            if event != "end":
                continue
            if elem.tag == "scaninfo":
                stype = elem.get("type") or ""
                sproto = elem.get("protocol") or ""
                if stype and stype not in metadata.scan_types:
                    metadata.scan_types.append(stype)
                if sproto and sproto not in metadata.scan_protocols:
                    metadata.scan_protocols.append(sproto)
            elif elem.tag == "host":
                host = _build_host(elem)
                key = host.primary_ip
                if not key:
                    LOG.warning(
                        "Skipping host record without an IP address (state=%s, names=%s)",
                        host.state,
                        ",".join(host.hostnames) or "-",
                    )
                elif key in hosts:
                    LOG.info("Duplicate host record for %s; merging results", key)
                    _merge_host(hosts[key], host)
                else:
                    hosts[key] = host
                elem.clear()  # bound memory on very large reports
                # Cleared <host> elements would still accumulate as empty
                # children of <nmaprun>; drop completed children so memory
                # stays bounded regardless of report size.
                while len(root):
                    del root[0]
            elif elem.tag == "finished":
                metadata.end_time = elem.get("timestr") or elem.get("time") or ""
                metadata.elapsed = elem.get("elapsed") or ""
                metadata.summary = elem.get("summary") or ""
    except ParserError:
        raise
    except DefusedXmlException as exc:
        raise ParserError(
            f"Refusing to parse {path.name}: unsafe XML construct detected ({exc})"
        ) from exc
    except ET.ParseError as exc:
        raise ParserError(f"Invalid XML in {path.name}: {exc}") from exc
    except OSError as exc:
        raise ParserError(f"Could not read {path.name}: {exc}") from exc
    finally:
        if source is not None:
            source.close()

    if not hosts:
        LOG.warning("Scan contained no host records with IP addresses (empty scan?)")

    ordered = sorted(hosts.values(), key=lambda h: ip_sort_key(h.primary_ip))
    LOG.info("Parsed %s from %s", count_noun(len(ordered), "host"), path.name)
    return metadata, ordered
