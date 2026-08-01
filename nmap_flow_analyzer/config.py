"""Configuration loading and validation.

Configuration is optional; without it the analyzer still works but marks the
scanner as unverified and cannot resolve zones, roles, or approved scopes.
YAML is loaded exclusively with ``yaml.safe_load``.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .pluralize import count_noun

LOG = logging.getLogger("nmap_flow_analyzer.config")

SUPPORTED_PROTOCOLS = {"tcp", "udp", "sctp", "ip"}
FIREWALL_MODES = {"stateful", "stateless"}
DEVICE_CLASSES = {
    "server",
    "workstation",
    "network device",
    "security appliance",
    "printer",
    "storage device",
    "hypervisor",
    "unknown",
}
INFRASTRUCTURE_KEYS = [
    "dns_servers",
    "ntp_servers",
    "domain_controllers",
    "authentication_servers",
    "logging_servers",
    "patch_servers",
    "backup_servers",
    "mail_relay_servers",
    "proxy_servers",
]


class ConfigError(Exception):
    """Raised for invalid or unreadable configuration files."""


@dataclass
class PolicyConfig:
    default_source_scope: str = "scanner-ip"  # "scanner-ip" | "scanner-zone"
    management_source: str = ""
    max_source_prefixlen_ipv4: int = 24
    max_source_prefixlen_ipv6: int = 64
    always_manual_review: List[Dict[str, Any]] = field(default_factory=list)
    risk_overrides: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class RuleGenerationConfig:
    """How defined/expected flows are turned into candidate rules."""

    generate_source_outbound: bool = True
    generate_destination_inbound: bool = True
    enforcement_model: str = "endpoint_and_network"  # | endpoint_only | network_only


#: inference_policy category -> infrastructure key
INFERENCE_CATEGORIES = {
    "dns": "dns_servers",
    "ntp": "ntp_servers",
    "active_directory": "domain_controllers",
    "logging": "logging_servers",
    "patch_management": "patch_servers",
    "backup": "backup_servers",
}

ENFORCEMENT_MODELS = {"endpoint_and_network", "endpoint_only", "network_only"}


@dataclass
class InferenceCategoryPolicy:
    enabled: bool = True
    protocols: List[str] = field(default_factory=list)
    enabled_for_roles: List[str] = field(default_factory=list)
    preferred_transport: Dict[str, Any] = field(default_factory=dict)
    fallback_transports: List[Dict[str, Any]] = field(default_factory=list)


def _default_inference_categories() -> Dict[str, "InferenceCategoryPolicy"]:
    return {
        "dns": InferenceCategoryPolicy(enabled=True, protocols=["udp", "tcp"]),
        "ntp": InferenceCategoryPolicy(enabled=True),
        "active_directory": InferenceCategoryPolicy(
            enabled=True,
            enabled_for_roles=[
                "Windows server",
                "Windows workstation",
                "Domain controller",
            ],
        ),
        "logging": InferenceCategoryPolicy(
            enabled=True,
            preferred_transport={"protocol": "tcp", "port": 6514},
        ),
        "patch_management": InferenceCategoryPolicy(enabled=False),
        "backup": InferenceCategoryPolicy(enabled=False),
    }


@dataclass
class InferencePolicy:
    minimum_confidence_for_candidate_rule: int = 70
    categories: Dict[str, InferenceCategoryPolicy] = field(
        default_factory=_default_inference_categories
    )


@dataclass
class ZeekConfig:
    """Passive-sensor (Zeek) ingestion and correlation settings."""

    sensor_name: str = ""
    monitored_networks: List[str] = field(default_factory=list)
    external_zone_name: str = "External"
    exclude_nmap_scanner_traffic_from_rules: bool = True
    ignored_sources: List[str] = field(default_factory=list)
    ignored_destinations: List[str] = field(default_factory=list)
    minimum_successful_connections_for_rule: int = 1
    minimum_success_ratio_for_rule: float = 0.0
    capture_loss_warning_percent: float = 1.0
    max_sample_uids: int = 5
    max_sample_names: int = 10
    max_line_length_bytes: int = 1048576
    max_records_per_file: int = 10_000_000
    include_attempted_flows_in_diagram: bool = False
    include_external_dependencies_in_rules: bool = False


@dataclass
class HostConfig:
    hostname: str = ""
    role: str = ""
    device_class: str = ""
    owner: str = ""
    purpose: str = ""
    approved_services: List[Dict[str, Any]] = field(default_factory=list)
    expected_inbound: List[Dict[str, Any]] = field(default_factory=list)
    expected_outbound: List[Dict[str, Any]] = field(default_factory=list)
    approved_source_networks: List[str] = field(default_factory=list)
    approved_destination_networks: List[str] = field(default_factory=list)

    def approved_entry(self, protocol: str, port: int) -> Optional[Dict[str, Any]]:
        for entry in self.approved_services:
            if (
                str(entry.get("protocol", "tcp")).lower() == protocol
                and int(entry.get("port", -1)) == port
            ):
                return entry
        return None


@dataclass
class AnalyzerConfig:
    scanner_ip: str = ""
    scanner_hostname: str = ""
    scanner_zone: str = ""
    firewall_mode: str = "stateful"
    local_networks: List[str] = field(default_factory=list)
    zones: Dict[str, List[str]] = field(default_factory=dict)
    hosts: Dict[str, HostConfig] = field(default_factory=dict)
    infrastructure: Dict[str, List[str]] = field(default_factory=dict)
    defined_flows: List[Dict[str, Any]] = field(default_factory=list)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    rule_generation: RuleGenerationConfig = field(default_factory=RuleGenerationConfig)
    inference_policy: InferencePolicy = field(default_factory=InferencePolicy)
    #: zone name -> {"approved_source_networks": [...], "approved_destination_networks": [...]}
    zone_policies: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    #: global approved networks ({} entries absent when not configured)
    global_policy: Dict[str, List[str]] = field(default_factory=dict)
    zeek: ZeekConfig = field(default_factory=ZeekConfig)
    warnings: List[str] = field(default_factory=list)
    source_file: str = ""

    # -- lookups ------------------------------------------------------------

    def _zone_networks(self) -> List[Tuple[Any, str]]:
        nets: List[Tuple[Any, str]] = []
        for zone, cidrs in self.zones.items():
            for cidr in cidrs:
                try:
                    nets.append((ipaddress.ip_network(cidr, strict=False), zone))
                except ValueError:
                    continue
        # most specific prefix wins
        nets.sort(key=lambda item: (-item[0].prefixlen, str(item[0])))
        return nets

    def zone_for_ip(self, ip: str) -> str:
        """Resolve a zone name for an IP; 'Internal' for local ranges, else 'Unknown'."""
        if not ip:
            return "Unknown"
        if self.scanner_ip and ip == self.scanner_ip and self.scanner_zone:
            return self.scanner_zone
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "Unknown"
        for net, zone in self._zone_networks():
            if addr.version == net.version and addr in net:
                return zone
        for cidr in self.local_networks:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if addr.version == net.version and addr in net:
                return "Internal"
        return "Unknown"

    def resolve_source(self, token: str) -> List[str]:
        """Resolve a source token (zone name, IP, or CIDR) to normalized CIDRs."""
        token = str(token).strip()
        if token in self.zones:
            return [
                str(ipaddress.ip_network(c, strict=False)) for c in self.zones[token]
            ]
        try:
            return [str(ipaddress.ip_network(token, strict=False))]
        except ValueError:
            return []

    def host_cfg(self, ip: str) -> Optional[HostConfig]:
        return self.hosts.get(ip)


_TRUE_STRINGS = {"true", "yes", "on", "1"}
_FALSE_STRINGS = {"false", "no", "off", "0"}


def parse_boolean(value: Any, field_name: str) -> bool:
    """Strictly parse a configuration Boolean.

    Accepts real Booleans, the strings true/false, yes/no, on/off, 1/0
    (case-insensitive, surrounding whitespace ignored), and the integers
    0 and 1.  Everything else — empty strings, arbitrary words, floats,
    other integers, lists, mappings, None — raises ConfigError instead of
    being silently coerced, so a quoted "false" can never become True.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _TRUE_STRINGS:
            return True
        if normalized in _FALSE_STRINGS:
            return False
    raise ConfigError(
        f"{field_name} must be a Boolean value "
        f"(true/false, yes/no, on/off, or 1/0); got {value!r}"
    )


def _parse_boolean_field(
    value: Any, field_name: str, errors: List[str], default: bool
) -> bool:
    """Boolean parsing that reports into the loader's error list."""
    try:
        return parse_boolean(value, field_name)
    except ConfigError as exc:
        errors.append(str(exc))
        return default


def default_config() -> AnalyzerConfig:
    """A validated empty configuration."""
    return AnalyzerConfig()


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _require_mapping(value: Any, name: str, errors: List[str]) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        errors.append(f"'{name}' must be a mapping, got {type(value).__name__}")
        return {}
    return value


def _require_list(value: Any, name: str, errors: List[str]) -> List[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        errors.append(f"'{name}' must be a list, got {type(value).__name__}")
        return []
    return value


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _valid_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _valid_port(value: Any) -> bool:
    try:
        return 0 <= int(value) <= 65535
    except (TypeError, ValueError):
        return False


def _check_service_entries(
    entries: List[Any], context: str, errors: List[str]
) -> List[Dict[str, Any]]:
    cleaned: List[Dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            errors.append(f"{context}: entries must be mappings, got {entry!r}")
            continue
        proto = str(entry.get("protocol", "tcp")).lower()
        if proto not in SUPPORTED_PROTOCOLS:
            errors.append(f"{context}: unsupported protocol {proto!r}")
            continue
        if "port" in entry and not _valid_port(entry["port"]):
            errors.append(f"{context}: invalid port {entry.get('port')!r}")
            continue
        entry = dict(entry)
        entry["protocol"] = proto
        if "approved" in entry:
            try:
                entry["approved"] = parse_boolean(
                    entry["approved"], f"{context}.approved"
                )
            except ConfigError as exc:
                errors.append(str(exc))
                continue
        cleaned.append(entry)
    return cleaned


def _parse_host_cfg(ip: str, raw: Any, errors: List[str]) -> HostConfig:
    raw = _require_mapping(raw, f"hosts.{ip}", errors)
    cfg = HostConfig(
        hostname=str(raw.get("hostname", "") or ""),
        role=str(raw.get("role", "") or ""),
        device_class=str(raw.get("device_class", "") or "").lower(),
        owner=str(raw.get("owner", "") or ""),
        purpose=str(raw.get("purpose", "") or ""),
    )
    if cfg.device_class and cfg.device_class not in DEVICE_CLASSES:
        errors.append(
            f"hosts.{ip}: device_class {cfg.device_class!r} is not one of {sorted(DEVICE_CLASSES)}"
        )
    cfg.approved_services = _check_service_entries(
        _require_list(raw.get("approved_services"), f"hosts.{ip}.approved_services", errors),
        f"hosts.{ip}.approved_services",
        errors,
    )
    cfg.expected_inbound = _check_service_entries(
        _require_list(raw.get("expected_inbound"), f"hosts.{ip}.expected_inbound", errors),
        f"hosts.{ip}.expected_inbound",
        errors,
    )
    cfg.expected_outbound = _check_service_entries(
        _require_list(raw.get("expected_outbound"), f"hosts.{ip}.expected_outbound", errors),
        f"hosts.{ip}.expected_outbound",
        errors,
    )
    for key in ("approved_source_networks", "approved_destination_networks"):
        values = _require_list(raw.get(key), f"hosts.{ip}.{key}", errors)
        cleaned = []
        for value in values:
            if _valid_cidr(str(value)):
                cleaned.append(str(value))
            else:
                errors.append(f"hosts.{ip}.{key}: invalid network {value!r}")
        setattr(cfg, key, cleaned)
    for entry in cfg.expected_outbound:
        dest = str(entry.get("destination", ""))
        if dest and not (_valid_ip(dest) or _valid_cidr(dest)):
            errors.append(f"hosts.{ip}.expected_outbound: invalid destination {dest!r}")
    return cfg


def load_config(path: Path) -> AnalyzerConfig:
    """Load and validate a YAML configuration file.

    Raises :class:`ConfigError` when the file is unreadable, is not valid
    YAML, or contains invalid values.  Non-fatal issues are collected in
    ``config.warnings``.
    """
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise ConfigError(
            "PyYAML is required to load configuration files (pip install PyYAML)"
        ) from exc

    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"Configuration file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path.name}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Could not read {path.name}: {exc}") from exc

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path.name}: top level must be a mapping")

    errors: List[str] = []
    cfg = AnalyzerConfig(source_file=path.name)

    scanner = _require_mapping(raw.get("scanner"), "scanner", errors)
    cfg.scanner_ip = str(scanner.get("ip", "") or "")
    cfg.scanner_hostname = str(scanner.get("hostname", "") or "")
    cfg.scanner_zone = str(scanner.get("zone", "") or "")
    if cfg.scanner_ip and not _valid_ip(cfg.scanner_ip):
        errors.append(f"scanner.ip is not a valid IP address: {cfg.scanner_ip!r}")

    mode = str(raw.get("firewall_mode", "stateful") or "stateful").lower()
    if mode not in FIREWALL_MODES:
        errors.append(f"firewall_mode must be one of {sorted(FIREWALL_MODES)}, got {mode!r}")
    else:
        cfg.firewall_mode = mode

    for cidr in _require_list(raw.get("local_networks"), "local_networks", errors):
        if _valid_cidr(str(cidr)):
            cfg.local_networks.append(str(cidr))
        else:
            errors.append(f"local_networks: invalid network {cidr!r}")

    seen_nets: Dict[str, str] = {}
    zones = _require_mapping(raw.get("zones"), "zones", errors)
    for zone, cidrs in zones.items():
        cleaned: List[str] = []
        if isinstance(cidrs, dict):
            # Extended form: {cidrs: [...], approved_source_networks: [...],
            #                 approved_destination_networks: [...]}
            zone_pol: Dict[str, List[str]] = {}
            for pol_key in ("approved_source_networks", "approved_destination_networks"):
                if pol_key in cidrs:
                    nets_ok: List[str] = []
                    for net in _require_list(cidrs.get(pol_key), f"zones.{zone}.{pol_key}", errors):
                        if _valid_cidr(str(net)) or _valid_ip(str(net)):
                            nets_ok.append(str(net))
                        else:
                            errors.append(f"zones.{zone}.{pol_key}: invalid network {net!r}")
                    zone_pol[pol_key] = nets_ok
            if zone_pol:
                cfg.zone_policies[str(zone)] = zone_pol
            cidrs = cidrs.get("cidrs", [])
        for cidr in _require_list(cidrs, f"zones.{zone}", errors):
            if not _valid_cidr(str(cidr)):
                errors.append(f"zones.{zone}: invalid network {cidr!r}")
                continue
            norm = str(ipaddress.ip_network(str(cidr), strict=False))
            if norm in seen_nets and seen_nets[norm] != zone:
                errors.append(
                    f"Contradictory zone definitions: {norm} assigned to both "
                    f"'{seen_nets[norm]}' and '{zone}'"
                )
                continue
            seen_nets[norm] = zone
            cleaned.append(norm)
        cfg.zones[str(zone)] = cleaned
    # Overlapping (but not identical) networks across zones: warn, most
    # specific prefix wins at lookup time.
    nets = [(ipaddress.ip_network(n), z) for n, z in seen_nets.items()]
    for i, (net_a, zone_a) in enumerate(nets):
        for net_b, zone_b in nets[i + 1:]:
            if zone_a != zone_b and net_a.version == net_b.version and (
                net_a.subnet_of(net_b) or net_b.subnet_of(net_a)
            ):
                cfg.warnings.append(
                    f"Zones '{zone_a}' ({net_a}) and '{zone_b}' ({net_b}) overlap; "
                    "the most specific prefix wins"
                )

    for ip, host_raw in _require_mapping(raw.get("hosts"), "hosts", errors).items():
        ip = str(ip)
        if not _valid_ip(ip):
            errors.append(f"hosts: key {ip!r} is not a valid IP address")
            continue
        cfg.hosts[ip] = _parse_host_cfg(ip, host_raw, errors)

    infra = _require_mapping(raw.get("infrastructure"), "infrastructure", errors)
    for key, values in infra.items():
        if key not in INFRASTRUCTURE_KEYS:
            cfg.warnings.append(f"infrastructure: unknown key {key!r} ignored")
            continue
        cleaned = []
        for value in _require_list(values, f"infrastructure.{key}", errors):
            if _valid_ip(str(value)):
                cleaned.append(str(value))
            else:
                errors.append(f"infrastructure.{key}: invalid IP {value!r}")
        cfg.infrastructure[key] = cleaned

    for entry in _require_list(raw.get("defined_flows"), "defined_flows", errors):
        if not isinstance(entry, dict):
            errors.append(f"defined_flows: entries must be mappings, got {entry!r}")
            continue
        src, dst = str(entry.get("source", "")), str(entry.get("destination", ""))
        proto = str(entry.get("protocol", "tcp")).lower()
        if not (_valid_ip(src) or _valid_cidr(src)) or not (
            _valid_ip(dst) or _valid_cidr(dst)
        ):
            errors.append(f"defined_flows: invalid source/destination in {entry!r}")
            continue
        port_value = entry.get("port", entry.get("destination_port"))
        if proto not in SUPPORTED_PROTOCOLS or not _valid_port(port_value):
            errors.append(f"defined_flows: invalid protocol/port in {entry!r}")
            continue
        entry = dict(entry)
        entry["protocol"] = proto
        entry["port"] = port_value
        cfg.defined_flows.append(entry)

    policy_raw = _require_mapping(raw.get("policy"), "policy", errors)
    policy = PolicyConfig()
    scope = str(policy_raw.get("default_source_scope", policy.default_source_scope))
    if scope not in {"scanner-ip", "scanner-zone"}:
        errors.append(
            f"policy.default_source_scope must be 'scanner-ip' or 'scanner-zone', got {scope!r}"
        )
    else:
        policy.default_source_scope = scope
    mgmt = str(policy_raw.get("management_source", "") or "")
    if mgmt and not _valid_cidr(mgmt):
        errors.append(f"policy.management_source: invalid network {mgmt!r}")
    else:
        policy.management_source = mgmt
    for attr in ("max_source_prefixlen_ipv4", "max_source_prefixlen_ipv6"):
        if attr in policy_raw:
            try:
                setattr(policy, attr, int(policy_raw[attr]))
            except (TypeError, ValueError):
                errors.append(f"policy.{attr} must be an integer")
    policy.always_manual_review = _check_service_entries(
        _require_list(policy_raw.get("always_manual_review"), "policy.always_manual_review", errors),
        "policy.always_manual_review",
        errors,
    )
    for override in _require_list(policy_raw.get("risk_overrides"), "policy.risk_overrides", errors):
        if not isinstance(override, dict) or "level" not in override:
            errors.append(f"policy.risk_overrides: invalid entry {override!r}")
            continue
        policy.risk_overrides.append(override)
    cfg.policy = policy

    # -- rule_generation ----------------------------------------------------
    rg_raw = _require_mapping(raw.get("rule_generation"), "rule_generation", errors)
    rg = RuleGenerationConfig()
    if "generate_source_outbound" in rg_raw:
        rg.generate_source_outbound = _parse_boolean_field(
            rg_raw["generate_source_outbound"],
            "rule_generation.generate_source_outbound", errors,
            rg.generate_source_outbound,
        )
    if "generate_destination_inbound" in rg_raw:
        rg.generate_destination_inbound = _parse_boolean_field(
            rg_raw["generate_destination_inbound"],
            "rule_generation.generate_destination_inbound", errors,
            rg.generate_destination_inbound,
        )
    model = str(rg_raw.get("enforcement_model", rg.enforcement_model))
    if model not in ENFORCEMENT_MODELS:
        errors.append(
            f"rule_generation.enforcement_model must be one of "
            f"{sorted(ENFORCEMENT_MODELS)}, got {model!r}"
        )
    else:
        rg.enforcement_model = model
    cfg.rule_generation = rg

    # -- inference_policy ---------------------------------------------------
    ip_raw = _require_mapping(raw.get("inference_policy"), "inference_policy", errors)
    inference = InferencePolicy()
    if "minimum_confidence_for_candidate_rule" in ip_raw:
        try:
            threshold = int(ip_raw["minimum_confidence_for_candidate_rule"])
            if not 0 <= threshold <= 100:
                raise ValueError
            inference.minimum_confidence_for_candidate_rule = threshold
        except (TypeError, ValueError):
            errors.append(
                "inference_policy.minimum_confidence_for_candidate_rule "
                "must be an integer between 0 and 100"
            )
    for cat_name, cat_raw in ip_raw.items():
        if cat_name == "minimum_confidence_for_candidate_rule":
            continue
        if cat_name not in INFERENCE_CATEGORIES:
            cfg.warnings.append(f"inference_policy: unknown category {cat_name!r} ignored")
            continue
        if not isinstance(cat_raw, dict):
            errors.append(f"inference_policy.{cat_name}: must be a mapping")
            continue
        cat = inference.categories.setdefault(cat_name, InferenceCategoryPolicy())
        if "enabled" in cat_raw:
            cat.enabled = _parse_boolean_field(
                cat_raw["enabled"], f"inference_policy.{cat_name}.enabled",
                errors, cat.enabled,
            )
        if "protocols" in cat_raw:
            protos = []
            for proto in _require_list(cat_raw["protocols"], f"inference_policy.{cat_name}.protocols", errors):
                proto = str(proto).lower()
                if proto not in SUPPORTED_PROTOCOLS:
                    errors.append(f"inference_policy.{cat_name}.protocols: invalid protocol {proto!r}")
                else:
                    protos.append(proto)
            cat.protocols = protos
        if "enabled_for_roles" in cat_raw:
            cat.enabled_for_roles = [
                str(r) for r in _require_list(cat_raw["enabled_for_roles"], f"inference_policy.{cat_name}.enabled_for_roles", errors)
            ]
        if "preferred_transport" in cat_raw:
            pt = cat_raw["preferred_transport"]
            if not (isinstance(pt, dict) and str(pt.get("protocol", "")).lower() in SUPPORTED_PROTOCOLS and _valid_port(pt.get("port"))):
                errors.append(f"inference_policy.{cat_name}.preferred_transport: needs valid protocol and port")
            else:
                cat.preferred_transport = {"protocol": str(pt["protocol"]).lower(), "port": int(pt["port"])}
        if "fallback_transports" in cat_raw:
            fallbacks = []
            for ft in _require_list(cat_raw["fallback_transports"], f"inference_policy.{cat_name}.fallback_transports", errors):
                if not (isinstance(ft, dict) and str(ft.get("protocol", "")).lower() in SUPPORTED_PROTOCOLS and _valid_port(ft.get("port"))):
                    errors.append(f"inference_policy.{cat_name}.fallback_transports: invalid entry {ft!r}")
                else:
                    fallbacks.append({"protocol": str(ft["protocol"]).lower(), "port": int(ft["port"])})
            cat.fallback_transports = fallbacks
    cfg.inference_policy = inference

    # -- global_policy ------------------------------------------------------
    gp_raw = _require_mapping(raw.get("global_policy"), "global_policy", errors)
    for pol_key in ("approved_source_networks", "approved_destination_networks"):
        if pol_key in gp_raw:
            nets_ok: List[str] = []
            for net in _require_list(gp_raw.get(pol_key), f"global_policy.{pol_key}", errors):
                if _valid_cidr(str(net)) or _valid_ip(str(net)):
                    nets_ok.append(str(net))
                else:
                    errors.append(f"global_policy.{pol_key}: invalid network {net!r}")
            cfg.global_policy[pol_key] = nets_ok

    # -- zeek ---------------------------------------------------------------
    zk_raw = _require_mapping(raw.get("zeek"), "zeek", errors)
    zk = ZeekConfig()
    _ZEEK_KNOWN = {
        "sensor_name", "monitored_networks", "external_zone_name",
        "exclude_nmap_scanner_traffic_from_rules", "ignored_sources",
        "ignored_destinations", "minimum_successful_connections_for_rule",
        "minimum_success_ratio_for_rule", "capture_loss_warning_percent",
        "max_sample_uids", "max_sample_names", "max_line_length_bytes",
        "max_records_per_file", "include_attempted_flows_in_diagram",
        "include_external_dependencies_in_rules",
    }
    for zkey in zk_raw:
        if zkey not in _ZEEK_KNOWN:
            cfg.warnings.append(f"zeek: unknown key {zkey!r} ignored")
    if "sensor_name" in zk_raw:
        zk.sensor_name = str(zk_raw["sensor_name"] or "")
    if "external_zone_name" in zk_raw:
        name = str(zk_raw["external_zone_name"] or "").strip()
        if not name:
            errors.append("zeek.external_zone_name must be a non-empty string")
        else:
            zk.external_zone_name = name
    for list_key, target in (
        ("monitored_networks", "monitored_networks"),
        ("ignored_sources", "ignored_sources"),
        ("ignored_destinations", "ignored_destinations"),
    ):
        if list_key in zk_raw:
            nets_ok: List[str] = []
            for net in _require_list(zk_raw[list_key], f"zeek.{list_key}", errors):
                if _valid_cidr(str(net)) or _valid_ip(str(net)):
                    nets_ok.append(str(net))
                else:
                    errors.append(f"zeek.{list_key}: invalid network {net!r}")
            setattr(zk, target, nets_ok)
    for bool_key in (
        "exclude_nmap_scanner_traffic_from_rules",
        "include_attempted_flows_in_diagram",
        "include_external_dependencies_in_rules",
    ):
        if bool_key in zk_raw:
            setattr(zk, bool_key, _parse_boolean_field(
                zk_raw[bool_key], f"zeek.{bool_key}", errors,
                getattr(zk, bool_key),
            ))
    for int_key, minimum in (
        ("minimum_successful_connections_for_rule", 0),
        ("max_sample_uids", 1),
        ("max_sample_names", 1),
        ("max_line_length_bytes", 1024),
        ("max_records_per_file", 1),
    ):
        if int_key in zk_raw:
            value = zk_raw[int_key]
            try:
                if isinstance(value, bool):
                    raise ValueError
                value = int(value)
                if value < minimum:
                    raise ValueError
                setattr(zk, int_key, value)
            except (TypeError, ValueError):
                errors.append(
                    f"zeek.{int_key} must be an integer >= {minimum}, got {value!r}"
                )
    for pct_key, low, high in (
        ("minimum_success_ratio_for_rule", 0.0, 1.0),
        ("capture_loss_warning_percent", 0.0, 100.0),
    ):
        if pct_key in zk_raw:
            value = zk_raw[pct_key]
            try:
                if isinstance(value, bool):
                    raise ValueError
                value = float(value)
                if not low <= value <= high:
                    raise ValueError
                setattr(zk, pct_key, value)
            except (TypeError, ValueError):
                errors.append(
                    f"zeek.{pct_key} must be a number between {low} and {high}, "
                    f"got {value!r}"
                )
    cfg.zeek = zk

    known_top = {
        "scanner",
        "zeek",
        "firewall_mode",
        "local_networks",
        "zones",
        "hosts",
        "infrastructure",
        "defined_flows",
        "policy",
        "rule_generation",
        "inference_policy",
        "global_policy",
    }
    for key in raw:
        if key not in known_top:
            cfg.warnings.append(f"Unknown top-level configuration key {key!r} ignored")

    if errors:
        raise ConfigError(
            f"Configuration errors in {path.name}:\n  - " + "\n  - ".join(errors)
        )
    for warning in cfg.warnings:
        LOG.warning("%s: %s", path.name, warning)
    LOG.info(
        "Loaded configuration %s (%s, %s)",
        path.name,
        count_noun(len(cfg.zones), "zone"),
        count_noun(len(cfg.hosts), "host"),
    )
    return cfg