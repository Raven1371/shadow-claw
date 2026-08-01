"""Tests for strict Boolean configuration parsing (v1.1.1)."""

import tempfile
from pathlib import Path

from nmap_flow_analyzer.config import ConfigError, load_config, parse_boolean
from nmap_flow_analyzer.flow_analysis import AnalysisOptions
from nmap_flow_analyzer.models import EvidenceClass
from tests.fixtures import MULTI_HOST_XML, run_pipeline

TRUE_VALUES = [True, "true", "TRUE", "True", " true ", "yes", "on", "1", 1]
FALSE_VALUES = [False, "false", "FALSE", "False", "no", "off", "0", 0]
REJECTED_VALUES = ["", "disabled", "enable", 2, -1, [], {}, None, 1.5, "truthy"]


def test_accepted_true_values():
    for value in TRUE_VALUES:
        assert parse_boolean(value, "f") is True, repr(value)


def test_accepted_false_values():
    for value in FALSE_VALUES:
        assert parse_boolean(value, "f") is False, repr(value)


def test_rejected_values_raise_config_error():
    for value in REJECTED_VALUES:
        try:
            parse_boolean(value, "some.field")
        except ConfigError as exc:
            assert "some.field" in str(exc)
        else:  # pragma: no cover
            raise AssertionError(f"{value!r} was not rejected")


def _load_yaml(text: str):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "cfg.yaml"
        path.write_text(text, encoding="utf-8")
        return load_config(path)


def test_quoted_false_in_yaml_disables_rule_generation():
    cfg = _load_yaml(
        'rule_generation:\n'
        '  generate_source_outbound: "false"\n'
        '  generate_destination_inbound: "FALSE"\n'
    )
    assert cfg.rule_generation.generate_source_outbound is False
    assert cfg.rule_generation.generate_destination_inbound is False


def test_quoted_false_disables_inference_category():
    cfg = _load_yaml(
        'inference_policy:\n'
        '  dns:\n'
        '    enabled: "false"\n'
    )
    assert cfg.inference_policy.categories["dns"].enabled is False


def test_quoted_true_and_variants_in_yaml():
    cfg = _load_yaml(
        'rule_generation:\n'
        '  generate_source_outbound: "yes"\n'
        '  generate_destination_inbound: "on"\n'
    )
    assert cfg.rule_generation.generate_source_outbound is True
    assert cfg.rule_generation.generate_destination_inbound is True


def test_invalid_boolean_string_is_a_clear_config_error():
    for bad in ('""', '"disabled"', '"enable"', "2", "-1", "[]", "{}", "null"):
        try:
            _load_yaml(
                "rule_generation:\n"
                f"  generate_source_outbound: {bad}\n"
            )
        except ConfigError as exc:
            assert "generate_source_outbound" in str(exc)
        else:  # pragma: no cover
            raise AssertionError(f"{bad} accepted")


def test_approved_service_flag_parses_strictly():
    cfg = _load_yaml(
        "hosts:\n"
        "  192.168.10.20:\n"
        "    approved_services:\n"
        "      - protocol: tcp\n"
        "        port: 443\n"
        '        approved: "false"\n'
    )
    entry = cfg.hosts["192.168.10.20"].approved_services[0]
    assert entry["approved"] is False
    try:
        _load_yaml(
            "hosts:\n"
            "  192.168.10.20:\n"
            "    approved_services:\n"
            "      - protocol: tcp\n"
            "        port: 443\n"
            '        approved: "maybe"\n'
        )
    except ConfigError:
        pass
    else:  # pragma: no cover
        raise AssertionError("'maybe' accepted as approved value")


def test_quoted_false_end_to_end_produces_no_defined_flow_rules():
    cfg = _load_yaml(
        'rule_generation:\n'
        '  generate_source_outbound: "false"\n'
        '  generate_destination_inbound: "false"\n'
        "defined_flows:\n"
        "  - source: 192.168.10.20\n"
        "    destination: 192.168.10.30\n"
        "    protocol: tcp\n"
        "    port: 5432\n"
    )
    data = run_pipeline(MULTI_HOST_XML, cfg, AnalysisOptions())
    defined = [
        r for r in data["inbound"] + data["outbound"]
        if r.evidence_class == EvidenceClass.USER_DEFINED.value
    ]
    assert defined == []
    assert any(
        "no rule perspectives" in rv.finding for rv in data["reviews"]
    )
