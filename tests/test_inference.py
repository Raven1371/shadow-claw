"""Tests for restricted, policy-driven inferred outbound dependencies."""

from nmap_flow_analyzer.config import HostConfig
from nmap_flow_analyzer.flow_analysis import AnalysisOptions
from nmap_flow_analyzer.models import EvidenceClass
from tests.fixtures import (
    DC_HOST_XML,
    MULTI_HOST_XML,
    SINGLE_HOST_XML,
    XML_FOOTER,
    XML_HEADER,
    base_config,
    run_pipeline,
)

OPTS = AnalysisOptions(include_inferred_outbound=True)

WINDOWS_SERVER_XML = XML_HEADER + """
<host><status state="up" reason="arp-response"/>
<address addr="192.168.10.80" addrtype="ipv4"/>
<hostnames><hostname name="app01.example.local" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="445">
<state state="open" reason="syn-ack"/>
<service name="microsoft-ds" method="probed" conf="10"/>
</port></ports>
<os><osmatch name="Microsoft Windows Server 2022" accuracy="95">
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2022" accuracy="95"/>
</osmatch></os>
</host>
""" + XML_FOOTER


def _inferred(data, port=None):
    flows = [
        f for f in data["flows"]
        if f.evidence_class == EvidenceClass.INFERRED.value
    ]
    if port is not None:
        flows = [f for f in flows if f.destination_port == port]
    return flows


def test_inference_disabled_by_default():
    cfg = base_config()
    cfg.infrastructure = {"dns_servers": ["192.168.1.10"]}
    data = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    assert not _inferred(data)
    assert not data["outbound"]


def test_inference_enabled_produces_labeled_flows():
    cfg = base_config()
    cfg.infrastructure = {"dns_servers": ["192.168.1.10"]}
    data = run_pipeline(MULTI_HOST_XML, cfg, OPTS)
    flows = _inferred(data, 53)
    assert flows
    for flow in flows:
        assert "inference_policy.dns" in flow.evidence
        assert "infrastructure.dns_servers" in flow.evidence
        assert flow.confidence > 0
        assert flow.direction == "outbound"


def test_no_ad_inference_for_linux_hosts():
    cfg = base_config()
    cfg.infrastructure = {"domain_controllers": ["192.168.10.10"]}
    # SINGLE_HOST_XML is a Linux web server.
    data = run_pipeline(SINGLE_HOST_XML, cfg, OPTS)
    assert not _inferred(data, 88)
    assert not _inferred(data, 389)


def test_ad_inference_for_windows_server():
    cfg = base_config()
    cfg.infrastructure = {"domain_controllers": ["192.168.10.10"]}
    data = run_pipeline(WINDOWS_SERVER_XML, cfg, OPTS)
    assert _inferred(data, 88)
    assert _inferred(data, 389)


def test_ad_inference_for_linux_only_when_role_explicitly_enabled():
    cfg = base_config()
    cfg.infrastructure = {"domain_controllers": ["192.168.10.10"]}
    cfg.hosts["192.168.10.20"] = HostConfig(role="Linux domain member")
    cfg.inference_policy.categories["active_directory"].enabled_for_roles.append(
        "Linux domain member"
    )
    data = run_pipeline(SINGLE_HOST_XML, cfg, OPTS)
    assert _inferred(data, 88)


def test_domain_controller_self_dependency_prevented():
    cfg = base_config()
    # dc01 (192.168.10.10) is itself the configured DC and DNS server.
    cfg.infrastructure = {
        "domain_controllers": ["192.168.10.10"],
        "dns_servers": ["192.168.10.10"],
        "ntp_servers": ["192.168.10.10"],
        "logging_servers": ["192.168.10.10"],
        "backup_servers": ["192.168.10.10"],
    }
    cfg.inference_policy.categories["backup"].enabled = True
    data = run_pipeline(DC_HOST_XML, cfg, OPTS)
    self_flows = [
        f for f in _inferred(data)
        if f.source == "192.168.10.10" and f.destination == "192.168.10.10"
    ]
    assert not self_flows


def test_preferred_logging_transport_only():
    cfg = base_config()
    cfg.infrastructure = {"logging_servers": ["192.168.1.20"]}
    data = run_pipeline(SINGLE_HOST_XML, cfg, OPTS)
    syslog = [f for f in _inferred(data) if f.destination == "192.168.1.20"]
    assert syslog
    assert {(f.protocol, f.destination_port) for f in syslog} == {("tcp", 6514)}
    # UDP 514 must NOT be inferred unless explicitly configured as fallback.


def test_fallback_logging_transport_when_configured():
    cfg = base_config()
    cfg.infrastructure = {"logging_servers": ["192.168.1.20"]}
    cfg.inference_policy.categories["logging"].fallback_transports = [
        {"protocol": "udp", "port": 514}
    ]
    data = run_pipeline(SINGLE_HOST_XML, cfg, OPTS)
    pairs = {
        (f.protocol, f.destination_port)
        for f in _inferred(data)
        if f.destination == "192.168.1.20"
    }
    assert pairs == {("tcp", 6514), ("udp", 514)}


def test_missing_logging_destination_goes_to_manual_review():
    cfg = base_config()
    cfg.infrastructure = {"logging_servers": []}  # declared but empty
    data = run_pipeline(SINGLE_HOST_XML, cfg, OPTS)
    assert not [f for f in _inferred(data) if f.normalized_service == "Syslog"]
    assert any(
        "logging_servers" in rv.finding
        for rv in data["reviews"]
        if rv.category == "Unresolved inferred dependency"
    )


def test_duplicate_infrastructure_servers_deduplicate():
    cfg = base_config()
    cfg.infrastructure = {"dns_servers": ["192.168.1.10", "192.168.1.10"]}
    data = run_pipeline(SINGLE_HOST_XML, cfg, OPTS)
    udp = [
        f for f in _inferred(data, 53)
        if f.protocol == "udp" and f.destination == "192.168.1.10"
    ]
    assert len(udp) == 1


def test_multiple_dns_and_ntp_servers_each_get_flows():
    cfg = base_config()
    cfg.infrastructure = {
        "dns_servers": ["192.168.1.10", "192.168.1.11"],
        "ntp_servers": ["192.168.1.12", "192.168.1.13"],
    }
    data = run_pipeline(SINGLE_HOST_XML, cfg, OPTS)
    dns_dsts = {f.destination for f in _inferred(data, 53) if f.protocol == "udp"}
    ntp_dsts = {f.destination for f in _inferred(data, 123)}
    assert dns_dsts == {"192.168.1.10", "192.168.1.11"}
    assert ntp_dsts == {"192.168.1.12", "192.168.1.13"}


def test_dns_protocols_configurable():
    cfg = base_config()
    cfg.infrastructure = {"dns_servers": ["192.168.1.10"]}
    cfg.inference_policy.categories["dns"].protocols = ["udp"]
    data = run_pipeline(SINGLE_HOST_XML, cfg, OPTS)
    protos = {f.protocol for f in _inferred(data, 53)}
    assert protos == {"udp"}


def test_confidence_below_threshold_withheld_to_review():
    cfg = base_config()
    cfg.infrastructure = {"patch_servers": ["192.168.1.30"]}
    cfg.inference_policy.categories["patch_management"].enabled = True
    # patch confidence (55) < default threshold (70)
    data = run_pipeline(SINGLE_HOST_XML, cfg, OPTS)
    patch_flows = [f for f in _inferred(data) if f.destination == "192.168.1.30"]
    assert patch_flows
    assert all(f.manual_review_reason for f in patch_flows)
    assert not [r for r in data["outbound"] if r.destination == "192.168.1.30"]
    assert any(
        "192.168.1.30" in rv.finding and rv.category == "Rule withheld"
        for rv in data["rule_reviews"]
    )


def test_lower_threshold_allows_the_same_dependency():
    cfg = base_config()
    cfg.infrastructure = {"patch_servers": ["192.168.1.30"]}
    cfg.inference_policy.categories["patch_management"].enabled = True
    cfg.inference_policy.minimum_confidence_for_candidate_rule = 50
    data = run_pipeline(SINGLE_HOST_XML, cfg, OPTS)
    assert [r for r in data["outbound"] if r.destination == "192.168.1.30"]


def test_category_disabled_produces_nothing():
    cfg = base_config()
    cfg.infrastructure = {"dns_servers": ["192.168.1.10"]}
    cfg.inference_policy.categories["dns"].enabled = False
    data = run_pipeline(SINGLE_HOST_XML, cfg, OPTS)
    assert not _inferred(data, 53)
