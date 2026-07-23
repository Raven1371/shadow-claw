"""Zeek conn.log classification, aggregation, enrichment, sensor health."""

from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .pluralize import count_noun, verb
from .zeek_models import (
    OUTCOME_AMBIGUOUS,
    ZeekCertificate,
    ZeekExtras,
    OUTCOME_FAILED,
    OUTCOME_ONE_WAY,
    OUTCOME_PARTIAL,
    OUTCOME_REJECTED,
    OUTCOME_SUCCESSFUL,
    ZeekConnectionRecord,
    ZeekFlowAggregate,
    ZeekInputMetadata,
    ZeekSensorHealth,
    iso_utc,
)
from .zeek_parser import as_float, as_int, as_list, as_str, iter_log_records

LOG = logging.getLogger(__name__)

#: TCP conn_state semantics (Zeek documentation), conservatively mapped.
_TCP_STATE_OUTCOME = {
    # Established / completed exchanges may support successful traffic.
    "SF": OUTCOME_SUCCESSFUL,     # normal establishment and termination
    "S1": OUTCOME_SUCCESSFUL,     # established, not terminated
    "S2": OUTCOME_SUCCESSFUL,     # established, originator closed only
    "S3": OUTCOME_SUCCESSFUL,     # established, responder closed only
    "RSTO": OUTCOME_SUCCESSFUL,   # established, originator aborted
    "RSTR": OUTCOME_SUCCESSFUL,   # established, responder aborted
    # Unsuccessful attempts.
    "S0": OUTCOME_FAILED,         # attempt seen, no reply
    "REJ": OUTCOME_REJECTED,      # attempt rejected
    "RSTOS0": OUTCOME_FAILED,     # SYN then originator RST; no responder reply seen
    # Half-open / asymmetric / midstream observations.
    "SH": OUTCOME_ONE_WAY,        # SYN then FIN, SYN-ACK never seen
    "SHR": OUTCOME_AMBIGUOUS,     # responder SYN-ACK+FIN, SYN never seen
    "RSTRH": OUTCOME_AMBIGUOUS,   # responder SYN-ACK then RST, SYN never seen
    "OTH": OUTCOME_PARTIAL,       # midstream traffic, no SYN observed
}


def classify_connection(
    proto: str,
    conn_state: str,
    orig_pkts: int = 0,
    resp_pkts: int = 0,
    orig_bytes: int = 0,
    resp_bytes: int = 0,
) -> str:
    """Classify one Zeek connection outcome (the single central function).

    TCP relies on documented conn_state semantics; UDP requires responder
    packets or bytes before an interaction counts as successful (one-way
    UDP is classified separately, never as success); ICMP is preserved as
    an observed flow but conservatively classified — its type/code are not
    ports and it never feeds ordinary rule generation.
    """
    proto = (proto or "").lower()
    state = (conn_state or "").upper()

    if proto == "tcp":
        return _TCP_STATE_OUTCOME.get(state, OUTCOME_AMBIGUOUS)

    if proto == "udp":
        if resp_pkts > 0 or resp_bytes > 0:
            return OUTCOME_SUCCESSFUL
        if state == "REJ":  # ICMP port-unreachable seen by Zeek
            return OUTCOME_REJECTED
        return OUTCOME_ONE_WAY

    if proto == "icmp":
        # Observed network activity, but never a transport-level "service
        # success": actionable ICMP policy belongs in manual review.
        if resp_pkts > 0 or resp_bytes > 0:
            return OUTCOME_PARTIAL
        return OUTCOME_ONE_WAY

    return OUTCOME_AMBIGUOUS


def _record_from_conn(raw: Dict[str, object]) -> Optional[ZeekConnectionRecord]:
    orig = as_str(raw, "id.orig_h", "id_orig_h")
    resp = as_str(raw, "id.resp_h", "id_resp_h")
    proto = as_str(raw, "proto").lower()
    if not orig or not resp or not proto:
        return None
    try:
        ipaddress.ip_address(orig.split("%")[0])
        ipaddress.ip_address(resp.split("%")[0])
    except ValueError:
        return None
    return ZeekConnectionRecord(
        uid=as_str(raw, "uid"),
        ts=as_float(raw, "ts"),
        orig_h=orig,
        orig_p=as_int(raw, "id.orig_p", "id_orig_p"),
        resp_h=resp,
        resp_p=as_int(raw, "id.resp_p", "id_resp_p"),
        proto=proto,
        service=as_str(raw, "service"),
        duration=as_float(raw, "duration") or 0.0,
        orig_bytes=as_int(raw, "orig_bytes"),
        resp_bytes=as_int(raw, "resp_bytes"),
        conn_state=as_str(raw, "conn_state"),
        missed_bytes=as_int(raw, "missed_bytes"),
        orig_pkts=as_int(raw, "orig_pkts"),
        orig_ip_bytes=as_int(raw, "orig_ip_bytes"),
        resp_pkts=as_int(raw, "resp_pkts"),
        resp_ip_bytes=as_int(raw, "resp_ip_bytes"),
        tunnel_parents=as_list(raw, "tunnel_parents"),
        vlan=as_str(raw, "vlan"),
        community_id=as_str(raw, "community_id"),
    )


def _bounded_add(values: List[str], value: str, cap: int) -> None:
    if value and value not in values and len(values) < cap:
        values.append(value)


class ZeekAggregator:
    """Streams conn.log records into per-communication aggregates."""

    def __init__(self, zeek_cfg, scanner_ip: str = "") -> None:
        self.cfg = zeek_cfg
        self.scanner_ip = scanner_ip
        self.aggregates: Dict[Tuple, ZeekFlowAggregate] = {}
        self.uid_to_key: Dict[str, Tuple] = {}
        self.seen_uids: set = set()
        self.duplicate_uids = 0
        self.total_records = 0
        self.earliest: Optional[float] = None
        self.latest: Optional[float] = None

    def _ignored(self, record: ZeekConnectionRecord) -> bool:
        def _in(ip: str, entries: List[str]) -> bool:
            try:
                addr = ipaddress.ip_address(ip.split("%")[0])
            except ValueError:
                return False
            for entry in entries:
                try:
                    net = ipaddress.ip_network(str(entry), strict=False)
                except ValueError:
                    continue
                if addr.version == net.version and addr in net:
                    return True
            return False

        return _in(record.orig_h, self.cfg.ignored_sources) or _in(
            record.resp_h, self.cfg.ignored_destinations
        )

    def add(self, raw: Dict[str, object]) -> None:
        record = _record_from_conn(raw)
        if record is None:
            return
        self.total_records += 1
        if record.uid:
            if record.uid in self.seen_uids:
                self.duplicate_uids += 1
                return
            self.seen_uids.add(record.uid)
        if record.ts is not None:
            self.earliest = record.ts if self.earliest is None else min(self.earliest, record.ts)
            self.latest = record.ts if self.latest is None else max(self.latest, record.ts)

        key = (record.orig_h, record.resp_h, record.proto, record.resp_p)
        agg = self.aggregates.get(key)
        if agg is None:
            try:
                version = ipaddress.ip_address(record.resp_h.split("%")[0]).version
            except ValueError:
                version = 4
            agg = ZeekFlowAggregate(
                originator=record.orig_h,
                responder=record.resp_h,
                protocol=record.proto,
                responder_port=record.resp_p,
                ip_version=version,
                originator_port_min=record.orig_p or 0,
                originator_port_max=record.orig_p or 0,
            )
            self.aggregates[key] = agg
        if record.uid:
            self.uid_to_key[record.uid] = key
            _bounded_add(agg.sample_uids, record.uid, self.cfg.max_sample_uids)

        outcome = classify_connection(
            record.proto, record.conn_state,
            record.orig_pkts, record.resp_pkts,
            record.orig_bytes, record.resp_bytes,
        )
        agg.connection_count += 1
        if outcome == OUTCOME_SUCCESSFUL:
            agg.successful_count += 1
        elif outcome == OUTCOME_REJECTED:
            agg.rejected_count += 1
        elif outcome == OUTCOME_FAILED:
            agg.failed_count += 1
        elif outcome == OUTCOME_ONE_WAY:
            agg.one_way_count += 1
        elif outcome == OUTCOME_PARTIAL:
            agg.partial_count += 1
        else:
            agg.ambiguous_count += 1

        if record.service:
            for svc in record.service.split(","):
                _bounded_add(agg.services, svc.strip(), self.cfg.max_sample_names)
        if record.conn_state and record.conn_state not in agg.conn_states:
            agg.conn_states.append(record.conn_state)
            agg.conn_states.sort()
        if record.orig_p:
            agg.originator_ports_seen += 1
            if not agg.originator_port_min or record.orig_p < agg.originator_port_min:
                agg.originator_port_min = record.orig_p
            agg.originator_port_max = max(agg.originator_port_max, record.orig_p)
        agg.originator_bytes += record.orig_bytes
        agg.responder_bytes += record.resp_bytes
        agg.originator_ip_bytes += record.orig_ip_bytes
        agg.responder_ip_bytes += record.resp_ip_bytes
        agg.originator_packets += record.orig_pkts
        agg.responder_packets += record.resp_pkts
        agg.total_duration += record.duration
        agg.max_duration = max(agg.max_duration, record.duration)
        agg.missed_bytes += record.missed_bytes
        for parent in record.tunnel_parents:
            _bounded_add(agg.tunnel_parents, parent, self.cfg.max_sample_uids)
        _bounded_add(agg.vlans, record.vlan, self.cfg.max_sample_names)
        _bounded_add(agg.community_ids, record.community_id, self.cfg.max_sample_uids)

        ts = iso_utc(record.ts)
        if ts:
            if not agg.first_seen or ts < agg.first_seen:
                agg.first_seen = ts
            if not agg.last_seen or ts > agg.last_seen:
                agg.last_seen = ts

        if self.scanner_ip and record.orig_h == self.scanner_ip:
            agg.scanner_traffic = True
        if self._ignored(record):
            agg.ignored_by_config = True

    def finalize(self) -> List[ZeekFlowAggregate]:
        for agg in self.aggregates.values():
            agg.sensor_quality = "degraded" if agg.missed_bytes else "ok"
            agg.outcome_label = agg.outcome
        return sorted(
            self.aggregates.values(),
            key=lambda a: (a.responder, a.protocol, a.responder_port, a.originator),
        )


# ---------------------------------------------------------------------------
# Enrichment (uid-correlated, bounded)
# ---------------------------------------------------------------------------

_QUERYSTRING_RE = re.compile(r"[?#].*$")


def strip_uri(uri: str) -> str:
    """Remove query strings and fragments (possible tokens) from a URI."""
    return _QUERYSTRING_RE.sub("", str(uri))[:200]


#: Application-protocol logs consumed as bounded uid-matched confirmations.
#: Each maps a Zeek log type to (service_label, display_label): the first is
#: the lowercase token added to the aggregate's service list, the second the
#: human-readable protocol confirmation. None of these can create a flow or a
#: rule - they annotate a connection conn.log already established. Each file
#: is read exactly once, inside apply_enrichment.
PROTOCOL_CONFIRMATION_LOGS = {
    "ssh": ("ssh", "SSH"), "rdp": ("rdp", "RDP"),
    "smb_cmd": ("smb", "SMB"), "smb_files": ("smb", "SMB"),
    "smb_mapping": ("smb", "SMB"), "dce_rpc": ("dce-rpc", "DCE/RPC"),
    "kerberos": ("krb", "Kerberos"), "ntlm": ("ntlm", "NTLM"),
    "ldap": ("ldap", "LDAP"), "ldap_search": ("ldap", "LDAP"),
    "ntp": ("ntp", "NTP"), "smtp": ("smtp", "SMTP"),
    "postgresql": ("postgresql", "PostgreSQL"), "quic": ("quic", "QUIC"),
    "tunnel": ("tunnel", "Tunnel"),
}


def apply_enrichment(
    logs: Dict[str, List[Path]],
    aggregator: ZeekAggregator,
    metadata: ZeekInputMetadata,
    zeek_cfg,
    dns_aliases: Dict[str, List[str]],
    dhcp_names: Dict[str, str],
    cert_identities: Dict[str, List[str]],
    log_format: str = "auto",
    extras: Optional[ZeekExtras] = None,
    x509_index: Optional[Dict[str, ZeekCertificate]] = None,
) -> None:
    """Correlate optional logs to aggregates via Zeek uid (bounded lists)."""
    cap = zeek_cfg.max_sample_names

    def _agg_for(raw) -> Optional[ZeekFlowAggregate]:
        uid = as_str(raw, "uid")
        key = aggregator.uid_to_key.get(uid)
        return aggregator.aggregates.get(key) if key else None

    for path in logs.get("dns", []):
        for raw in iter_log_records(path, "dns", metadata, log_format,
                                    zeek_cfg.max_line_length_bytes,
                                    zeek_cfg.max_records_per_file):
            query = as_str(raw, "query")
            answers = as_list(raw, "answers")
            agg = _agg_for(raw)
            if agg is not None and query:
                _bounded_add(agg.dns_names, query, cap)
            for answer in answers:
                try:
                    ipaddress.ip_address(answer.split("%")[0])
                except ValueError:
                    continue
                aliases = dns_aliases.setdefault(answer, [])
                _bounded_add(aliases, query, cap)

    for path in logs.get("ssl", []):
        for raw in iter_log_records(path, "ssl", metadata, log_format,
                                    zeek_cfg.max_line_length_bytes,
                                    zeek_cfg.max_records_per_file):
            agg = _agg_for(raw)
            if agg is None:
                continue
            sni = as_str(raw, "server_name")
            _bounded_add(agg.tls_server_names, sni, cap)
            version = as_str(raw, "version")
            if version:
                _bounded_add(agg.enrichment_notes, f"TLS {version}", cap)
            subject = as_str(raw, "subject")
            if subject:
                cert_identities.setdefault(agg.responder, [])
                _bounded_add(cert_identities[agg.responder], subject, cap)
            # Correlate the certificate chain with x509.log records. The
            # SERVER chain belongs to the responder; the client chain is
            # recorded against the originator, never mixed together.
            if extras is not None:
                for position, field_name, endpoint in (
                    ("server", "cert_chain_fuids", agg.responder),
                    ("client", "client_cert_chain_fuids", agg.originator),
                ):
                    fuids = as_list(raw, field_name)[:MAX_CHAIN_DEPTH]
                    for index, fuid in enumerate(fuids):
                        cert = x509_index.get(fuid) if x509_index else None
                        if cert is None:
                            continue  # referenced cert absent: not an error
                        resolved = ZeekCertificate(**vars(cert))
                        resolved.chain_position = (
                            "client" if position == "client"
                            else ("server-leaf" if index == 0 else "server-chain")
                        )
                        _add_certificate(extras, endpoint, resolved)
                        if position == "server" and resolved.subject:
                            cert_identities.setdefault(agg.responder, [])
                            _bounded_add(
                                cert_identities[agg.responder],
                                resolved.subject, cap,
                            )

    for path in logs.get("http", []):
        for raw in iter_log_records(path, "http", metadata, log_format,
                                    zeek_cfg.max_line_length_bytes,
                                    zeek_cfg.max_records_per_file):
            agg = _agg_for(raw)
            if agg is None:
                continue
            _bounded_add(agg.http_hosts, as_str(raw, "host"), cap)
            method = as_str(raw, "method")
            uri = strip_uri(as_str(raw, "uri"))
            if method and uri:
                _bounded_add(agg.enrichment_notes, f"HTTP {method} {uri}", cap)

    for path in logs.get("dhcp", []):
        for raw in iter_log_records(path, "dhcp", metadata, log_format,
                                    zeek_cfg.max_line_length_bytes,
                                    zeek_cfg.max_records_per_file):
            host = as_str(raw, "host_name")
            for ip in as_list(raw, "assigned_addr", "client_addr"):
                if host and ip not in dhcp_names:
                    dhcp_names[ip] = host

    # Application-protocol logs (ssh/rdp/smb_*/kerberos/... ): each physical
    # file is read exactly ONCE here. A single streaming pass performs every
    # required action for the record - uid correlation, the lowercase service
    # confirmation, the human-readable protocol confirmation, and (via
    # iter_log_records) file and malformed accounting - so a protocol file is
    # never read a second time merely to re-confirm its service name.
    for log_type, spec in PROTOCOL_CONFIRMATION_LOGS.items():
        service, label = spec
        for path in logs.get(log_type, []):
            for raw in iter_log_records(path, log_type, metadata, log_format,
                                        zeek_cfg.max_line_length_bytes,
                                        zeek_cfg.max_records_per_file):
                agg = _agg_for(raw)
                if agg is None:
                    continue
                _bounded_add(agg.services, service, cap)
                _bounded_add(
                    agg.enrichment_notes,
                    f"{log_type}.log confirms {service}", cap,
                )
                _bounded_add(agg.protocol_confirmations,
                             f"{label} ({log_type}.log)", cap)


def _nested(record: Dict[str, object], *names: str) -> str:
    """Read a Zeek field that may be flattened ("certificate.subject") or
    nested ({"certificate": {"subject": ...}}), returning "" when absent."""
    for name in names:
        if name in record and record[name] not in (None, ""):
            return str(record[name])
        if "." in name:
            head, tail = name.split(".", 1)
            container = record.get(head)
            if isinstance(container, dict) and container.get(tail) not in (None, ""):
                return str(container[tail])
    return ""


def _certificate_from_record(raw: Dict[str, object], source_log: str) -> ZeekCertificate:
    """Bounded certificate metadata; never keys, contents, or full chains."""
    return ZeekCertificate(
        fuid=as_str(raw, "id", "fuid")[:64],
        subject=_nested(raw, "certificate.subject", "subject")[:200],
        issuer=_nested(raw, "certificate.issuer", "issuer")[:200],
        serial=_nested(raw, "certificate.serial", "serial")[:64],
        not_valid_before=_nested(
            raw, "certificate.not_valid_before", "not_valid_before"
        )[:32],
        not_valid_after=_nested(
            raw, "certificate.not_valid_after", "not_valid_after"
        )[:32],
        key_algorithm=_nested(raw, "certificate.key_alg", "key_alg")[:32],
        key_length=_nested(raw, "certificate.key_length", "key_length")[:16],
        signature_algorithm=_nested(raw, "certificate.sig_alg", "sig_alg")[:64],
        source_log=source_log,
    )


#: Hard cap on stored certificates per endpoint and chain depth per session.
MAX_CERTS_PER_ENDPOINT = 5
MAX_CHAIN_DEPTH = 3


def _add_certificate(extras: ZeekExtras, ip: str, cert: ZeekCertificate) -> None:
    """Attach a certificate to an endpoint, de-duplicated by fuid+subject."""
    if not ip or (not cert.subject and not cert.fuid):
        return
    bucket = extras.certificates.setdefault(ip, [])
    for existing in bucket:
        if existing.fuid and existing.fuid == cert.fuid:
            # Prefer the richer x509 record over a known_certs stub.
            if existing.source_log == "known_certs" and cert.source_log == "x509":
                bucket[bucket.index(existing)] = cert
            return
        if not cert.fuid and existing.subject == cert.subject:
            return
    if len(bucket) < MAX_CERTS_PER_ENDPOINT:
        bucket.append(cert)


def process_optional_logs(
    logs: Dict[str, List[Path]],
    aggregator: "ZeekAggregator",
    metadata: ZeekInputMetadata,
    zeek_cfg,
    extras: ZeekExtras,
    x509_index: Dict[str, ZeekCertificate],
    log_format: str = "auto",
) -> None:
    """Parse the supporting logs that corroborate conn.log evidence.

    Every log opened here is recorded in ``metadata.files_processed`` by
    ``iter_log_records``, so a discovered file is never silently ignored.
    None of this evidence can create a firewall rule on its own.
    """
    cap = zeek_cfg.max_sample_names

    def _records(log_type: str):
        for path in logs.get(log_type, []):
            for raw in iter_log_records(path, log_type, metadata, log_format,
                                        zeek_cfg.max_line_length_bytes,
                                        zeek_cfg.max_records_per_file):
                yield raw

    # known_hosts.log: an endpoint was seen by Zeek. NOT proof of an open
    # service or a successful dependency.
    for raw in _records("known_hosts"):
        host = as_str(raw, "host")
        if host and host not in extras.known_hosts and len(extras.known_hosts) < 5000:
            extras.known_hosts.append(host)

    # known_services.log: supporting service evidence only.
    for raw in _records("known_services"):
        host = as_str(raw, "host")
        port = as_int(raw, "port_num")
        proto = as_str(raw, "port_proto").lower()
        if not host or not proto:
            continue
        key = f"{host}/{proto}/{port}"
        bucket = extras.known_services.setdefault(key, [])
        for service in as_list(raw, "service"):
            _bounded_add(bucket, service, cap)

    # software.log: bounded observations; never auto-classified as vulnerable.
    for raw in _records("software"):
        host = as_str(raw, "host")
        name = as_str(raw, "name")
        if not host or not name:
            continue
        version = ".".join(
            part for part in (
                _nested(raw, "version.major"), _nested(raw, "version.minor"),
                _nested(raw, "version.minor2"),
            ) if part
        )
        label = f"{name} {version}".strip()
        software_type = as_str(raw, "software_type")
        if software_type:
            label = f"{label} ({software_type})"
        _bounded_add(extras.software.setdefault(host, []), label[:120], cap)

    # x509.log: index certificates by file id so ssl.log chains resolve.
    for raw in _records("x509"):
        cert = _certificate_from_record(raw, "x509")
        if cert.fuid:
            x509_index[cert.fuid] = cert

    # known_certs.log: additional certificate observations, de-duplicated
    # against x509 enrichment by fuid.
    for raw in _records("known_certs"):
        host = as_str(raw, "host")
        cert = _certificate_from_record(raw, "known_certs")
        if not cert.subject:
            cert.subject = as_str(raw, "subject")[:200]
        if not cert.issuer:
            cert.issuer = as_str(raw, "issuer")[:200]
        cert.chain_position = "server-leaf"
        if host:
            _add_certificate(extras, host, cert)

    # files.log: bounded transfer metadata; never contents, never full paths.
    # The whole file is streamed and accounted; only sample STORAGE is capped,
    # so record and malformed counts stay complete and later malformed lines
    # are still detected after the cap is hit (issue 2, v1.2.2).
    FILES_CAP = 200
    for raw in _records("files"):
        if len(extras.file_transfers) >= FILES_CAP:
            metadata.samples_truncated["files"] = (
                metadata.samples_truncated.get("files", 0) + 1
            )
            continue
        filename = as_str(raw, "filename")
        extras.file_transfers.append({
            "uid": (as_list(raw, "conn_uids") or [""])[0][:64],
            "source": as_str(raw, "source")[:32],
            "tx_host": as_str(raw, "tx_hosts", "id.orig_h")[:64],
            "rx_host": as_str(raw, "rx_hosts", "id.resp_h")[:64],
            "mime_type": as_str(raw, "mime_type")[:64],
            "filename": Path(filename).name[:80] if filename else "",
            "total_bytes": as_int(raw, "total_bytes", "seen_bytes"),
        })
    if "files" in metadata.record_counts:
        metadata.samples_retained["files"] = len(extras.file_transfers)

    # notice.log: surfaced for review; never auto-labeled a vulnerability.
    # Streamed and accounted in full; only sample storage is capped (issue 2).
    NOTICE_CAP = 100
    for raw in _records("notice"):
        if len(extras.notices) >= NOTICE_CAP:
            metadata.samples_truncated["notice"] = (
                metadata.samples_truncated.get("notice", 0) + 1
            )
            continue
        extras.notices.append({
            "note": as_str(raw, "note")[:80],
            "message": as_str(raw, "msg", "message")[:300],
            "source": as_str(raw, "src", "id.orig_h")[:64],
            "destination": as_str(raw, "dst", "id.resp_h")[:64],
            "protocol": as_str(raw, "proto")[:8],
            "port": str(as_int(raw, "p", "id.resp_p") or ""),
        })
    if "notice" in metadata.record_counts:
        metadata.samples_retained["notice"] = len(extras.notices)

    # weird.log: bounded protocol-anomaly summary, not proof of compromise.
    for raw in _records("weird"):
        name = as_str(raw, "name")[:80]
        if not name:
            continue
        extras.weird_counts[name] = extras.weird_counts.get(name, 0) + 1
        if len(extras.weird_samples) < 20:
            extras.weird_samples.append({
                "name": name,
                "source": as_str(raw, "id.orig_h")[:64],
                "destination": as_str(raw, "id.resp_h")[:64],
                "notice": str(raw.get("notice", "")),
            })


# ---------------------------------------------------------------------------
# Sensor health
# ---------------------------------------------------------------------------

def assess_sensor_health(
    logs: Dict[str, List[Path]],
    aggregates: List[ZeekFlowAggregate],
    metadata: ZeekInputMetadata,
    zeek_cfg,
    log_format: str = "auto",
) -> ZeekSensorHealth:
    health = ZeekSensorHealth()
    health.observation_start = metadata.earliest_timestamp
    health.observation_end = metadata.latest_timestamp
    health.malformed_records = sum(metadata.malformed_counts.values())

    if not metadata.conn_log_available:
        health.status = "unusable"
        health.notes.append("conn.log was not available; Zeek analysis is unusable")
        return health

    for path in logs.get("capture_loss", []):
        for raw in iter_log_records(path, "capture_loss", metadata, log_format,
                                    zeek_cfg.max_line_length_bytes,
                                    zeek_cfg.max_records_per_file):
            health.capture_loss_available = True
            loss = as_float(raw, "percent_lost")
            if loss is not None:
                health.capture_loss_samples += 1
                health.max_capture_loss_percent = max(
                    health.max_capture_loss_percent, loss
                )
    metadata.capture_loss_available = health.capture_loss_available

    for path in logs.get("reporter", []):
        for raw in iter_log_records(path, "reporter", metadata, log_format,
                                    zeek_cfg.max_line_length_bytes,
                                    zeek_cfg.max_records_per_file):
            level = as_str(raw, "level").lower()
            message = as_str(raw, "message")[:300]
            if "error" in level:
                if len(health.reporter_errors) < 20:
                    health.reporter_errors.append(message)
            elif len(health.reporter_warnings) < 20:
                health.reporter_warnings.append(message)

    health.aggregates_with_missed_bytes = sum(1 for a in aggregates if a.missed_bytes)
    health.total_missed_bytes = sum(a.missed_bytes for a in aggregates)

    degraded = (
        (health.capture_loss_available
         and health.max_capture_loss_percent > zeek_cfg.capture_loss_warning_percent)
        or health.aggregates_with_missed_bytes > 0
        or bool(health.reporter_errors)
    )
    if degraded:
        health.status = "degraded"
        if health.max_capture_loss_percent > zeek_cfg.capture_loss_warning_percent:
            health.notes.append(
                f"Capture loss {health.max_capture_loss_percent:.2f}% exceeds the "
                f"configured threshold ({zeek_cfg.capture_loss_warning_percent}%)"
            )
        if health.aggregates_with_missed_bytes:
            health.notes.append(
                f"{count_noun(health.aggregates_with_missed_bytes, 'flow aggregate')} "
                f"{verb(health.aggregates_with_missed_bytes, 'contains', 'contain')} "
                "missed bytes (content gaps)"
            )
        for err in health.reporter_errors[:3]:
            health.notes.append(f"Zeek reporter error: {err}")
    elif not health.capture_loss_available:
        health.status = "unknown"  # never assume healthy without evidence
        health.notes.append(
            "capture_loss.log was not provided; sensor completeness is unknown"
        )
    else:
        health.status = "healthy"
    health.notes.append(
        "Zeek can only describe traffic visible to its sensor; degradation "
        "lowers confidence but observed flows are never deleted"
    )
    return health


# ---------------------------------------------------------------------------
# Pipeline entry point
# ---------------------------------------------------------------------------

#: Log types whose sample storage is capped globally across rotated files.
_GLOBAL_SAMPLE_CAP_LOG_TYPES = ("files", "notice")


def build_log_type_summaries(metadata: ZeekInputMetadata) -> None:
    """Roll per-file entries up into one summary per log type (issue 3).

    files_processed stays strictly per physical file. Global sample-retention
    totals (which span all rotated files of a capped type) are reported here
    exactly once, at log-type scope, with sample_scope naming the cap's reach.
    """
    order: List[str] = []
    by_type: Dict[str, Dict[str, object]] = {}
    for entry in metadata.files_processed:
        lt = entry["log_type"]
        if lt not in by_type:
            order.append(lt)
            by_type[lt] = {
                "log_type": lt,
                "files_processed": 0,
                "records": 0,
                "malformed": 0,
                "data_records_seen": 0,
            }
        summary = by_type[lt]
        summary["files_processed"] += 1
        summary["records"] += entry.get("records", 0)
        summary["malformed"] += entry.get("malformed", 0)
        summary["data_records_seen"] += entry.get("data_records_seen", 0)
    for lt in order:
        summary = by_type[lt]
        if lt in _GLOBAL_SAMPLE_CAP_LOG_TYPES:
            summary["samples_retained"] = metadata.samples_retained.get(lt, 0)
            summary["samples_truncated"] = metadata.samples_truncated.get(lt, 0)
            summary["sample_scope"] = "global_across_log_type"
        metadata.log_type_summaries.append(summary)


def load_zeek(directories: List[Path], log_format: str, config, scanner_ip: str = ""):
    """Discover, parse, aggregate, enrich, and health-check Zeek logs.

    Returns a ZeekAnalysis bundle.  Missing conn.log leaves
    ``metadata.conn_log_available`` False (the caller decides whether that
    is fatal via --zeek-required).
    """
    from .zeek_correlation import ZeekAnalysis
    from .zeek_parser import discover_logs

    metadata = ZeekInputMetadata()
    zcfg = config.zeek
    logs = discover_logs([Path(d) for d in directories], metadata)
    aggregator = ZeekAggregator(zcfg, scanner_ip=scanner_ip)
    for path in logs.get("conn", []):
        for raw in iter_log_records(path, "conn", metadata, log_format,
                                    zcfg.max_line_length_bytes,
                                    zcfg.max_records_per_file):
            aggregator.add(raw)
    metadata.conn_log_available = bool(logs.get("conn")) and aggregator.total_records > 0
    if logs.get("conn") and aggregator.total_records == 0:
        metadata.warnings.append("conn.log files contained no usable records")
    if not logs.get("conn"):
        metadata.warnings.append("No conn.log found in the Zeek input directories")
    if aggregator.duplicate_uids:
        metadata.warnings.append(
            f"{aggregator.duplicate_uids} duplicate conn.log uid(s) skipped"
        )
    metadata.earliest_timestamp = iso_utc(aggregator.earliest)
    metadata.latest_timestamp = iso_utc(aggregator.latest)

    dns_aliases: Dict[str, List[str]] = {}
    dhcp_names: Dict[str, str] = {}
    cert_identities: Dict[str, List[str]] = {}
    extras = ZeekExtras()
    x509_index: Dict[str, ZeekCertificate] = {}
    if metadata.conn_log_available:
        # Supporting logs first: x509/known_certs must be indexed before
        # ssl.log chains are resolved against them.
        process_optional_logs(logs, aggregator, metadata, zcfg, extras,
                              x509_index, log_format)
        apply_enrichment(logs, aggregator, metadata, zcfg,
                         dns_aliases, dhcp_names, cert_identities, log_format,
                         extras=extras, x509_index=x509_index)
    aggregates = aggregator.finalize()
    health = assess_sensor_health(logs, aggregates, metadata, zcfg, log_format)
    health.malformed_records = sum(metadata.malformed_counts.values())
    build_log_type_summaries(metadata)
    return ZeekAnalysis(
        metadata=metadata,
        aggregates=aggregates,
        health=health,
        dns_aliases=dns_aliases,
        dhcp_names=dhcp_names,
        cert_identities=cert_identities,
        extras=extras,
    )
