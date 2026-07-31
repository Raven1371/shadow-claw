"""Unit coverage for the v1.2.4/v1.2.5 compatibility comparator."""

from scripts.compare_v124_v125 import normalize_value


def test_normalization_removes_only_approved_metadata():
    value = {
        "version": "1.2.4",
        "run_id": "abc",
        "started_at": "now",
        "source_ip": "10.0.0.1",
        "confidence": "high",
        "generated_files": [{"path": "a.json", "size": 1, "sha256": "x"}],
    }
    normalized = normalize_value(value)
    assert normalized["version"] == "<VERSION>"
    assert "run_id" not in normalized
    assert "started_at" not in normalized
    assert normalized["source_ip"] == "10.0.0.1"
    assert normalized["confidence"] == "high"
    assert normalized["generated_files"] == [{"path": "a.json"}]


def test_security_semantics_are_not_normalized():
    left = normalize_value({"port": 443, "direction": "outbound"})
    right = normalize_value({"port": 80, "direction": "outbound"})
    assert left != right
