import importlib.util
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location(
    "native_inventory", Path(__file__).parents[1] / "scripts" / "collect-license-inventory.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_ldconfig_resolution_is_exact_by_soname():
    output = "\tlibxcb.so.1 (libc6,x86-64) => /lib64/libxcb.so.1\n\tlibxcb.so (libc6) => /other"
    assert MODULE.parse_ldconfig(output, "libxcb.so.1") == [Path("/lib64/libxcb.so.1")]


def test_ldconfig_missing_soname_blocks():
    assert MODULE.parse_ldconfig("", "libmissing.so.1") == []


def test_symlink_canonicalization_and_chain(tmp_path):
    real = tmp_path / "lib.real"
    real.write_bytes(b"library")
    second = tmp_path / "lib.second"
    try:
        second.symlink_to(real.name)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable on this host: {exc}")
    first = tmp_path / "lib.so.1"
    first.symlink_to(second.name)
    assert MODULE.symlink_chain(first) == [str(first), str(second), str(real)]
    assert first.resolve() == real


def test_exact_source_rpm_selection():
    expected = Path("/tmp/gcc-1.src.rpm")
    assert MODULE.require_exact_file([expected], expected.name) == expected


@pytest.mark.parametrize("paths", [[], [Path("a/x.src.rpm"), Path("b/x.src.rpm")]])
def test_missing_or_ambiguous_source_rpm_blocks(paths):
    with pytest.raises(RuntimeError):
        MODULE.require_exact_file(paths, "x.src.rpm")


def test_mismatched_source_rpm_version_blocks():
    with pytest.raises(RuntimeError):
        MODULE.require_exact_file([Path("gcc-2.src.rpm")], "gcc-1.src.rpm")


def test_verified_rocky_signature_is_accepted():
    MODULE.verify_rpm_signature("pkg.src.rpm: digests signatures OK")


@pytest.mark.parametrize("bad", ["digests OK", "NOT OK", "", "unsigned"])
def test_missing_or_malformed_signature_blocks(bad):
    with pytest.raises(RuntimeError):
        MODULE.verify_rpm_signature(bad)


def test_checksum_verification_accepts_identical_copy(tmp_path):
    source, bundled = tmp_path / "source", tmp_path / "bundled"
    source.write_bytes(b"same")
    bundled.write_bytes(b"same")
    MODULE.verify_same_file(source, bundled)


def test_bundled_file_hash_mismatch_blocks(tmp_path):
    source, bundled = tmp_path / "source", tmp_path / "bundled"
    source.write_bytes(b"source")
    bundled.write_bytes(b"changed")
    with pytest.raises(RuntimeError):
        MODULE.verify_same_file(source, bundled)


def test_license_filename_discovery_is_narrow():
    assert MODULE.LICENSE_NAME.match("COPYING.RUNTIME")
    assert MODULE.LICENSE_NAME.match("LICENSE")
    assert MODULE.LICENSE_NAME.match("NOTICE.txt")
    assert not MODULE.LICENSE_NAME.match("random-license-comment.c")


def test_verified_vault_mapping_is_exact_not_filename_guessing():
    assert set(MODULE.ROCKY_SOURCE_RPM_VAULT) == {"gcc-11.4.1-2.1.el9.src.rpm"}
    assert MODULE.ROCKY_SOURCE_RPM_VAULT["gcc-11.4.1-2.1.el9.src.rpm"].endswith(
        "/gcc-11.4.1-2.1.el9.src.rpm"
    )
