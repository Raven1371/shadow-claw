import importlib.util
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "native_inventory", Path(__file__).parents[1] / "scripts" / "collect-license-inventory.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class NativeLicenseAttributionTests(unittest.TestCase):
    def test_ldconfig_resolution_is_exact_by_soname(self):
        output = "\tlibxcb.so.1 (libc6,x86-64) => /lib64/libxcb.so.1\n\tlibxcb.so (libc6) => /other"
        self.assertEqual(MODULE.parse_ldconfig(output, "libxcb.so.1"), [Path("/lib64/libxcb.so.1")])

    def test_ldconfig_missing_soname_blocks(self):
        self.assertEqual(MODULE.parse_ldconfig("", "libmissing.so.1"), [])

    def test_symlink_canonicalization_and_chain(self):
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            real = root / "lib.real"
            real.write_bytes(b"library")
            second, first = root / "lib.second", root / "lib.so.1"
            try:
                second.symlink_to(real.name)
                first.symlink_to(second.name)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable on this host: {exc}")
            self.assertEqual(MODULE.symlink_chain(first), [str(first), str(second), str(real)])
            self.assertEqual(first.resolve(), real)

    def test_exact_source_rpm_selection(self):
        expected = Path("/tmp/gcc-1.src.rpm")
        self.assertEqual(MODULE.require_exact_file([expected], expected.name), expected)

    def test_missing_source_rpm_blocks(self):
        with self.assertRaises(RuntimeError):
            MODULE.require_exact_file([], "x.src.rpm")

    def test_ambiguous_source_rpm_blocks(self):
        with self.assertRaises(RuntimeError):
            MODULE.require_exact_file([Path("a/x.src.rpm"), Path("b/x.src.rpm")], "x.src.rpm")

    def test_mismatched_source_rpm_version_blocks(self):
        with self.assertRaises(RuntimeError):
            MODULE.require_exact_file([Path("gcc-2.src.rpm")], "gcc-1.src.rpm")

    def test_verified_rocky_signature_is_accepted(self):
        MODULE.verify_rpm_signature("pkg.src.rpm: digests signatures OK")

    def test_missing_or_malformed_signature_blocks(self):
        for bad in ("digests OK", "NOT OK", "", "unsigned"):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                MODULE.verify_rpm_signature(bad)

    def test_checksum_verification_accepts_identical_copy(self):
        with tempfile.TemporaryDirectory() as raw_tmp:
            source, bundled = Path(raw_tmp) / "source", Path(raw_tmp) / "bundled"
            source.write_bytes(b"same")
            bundled.write_bytes(b"same")
            MODULE.verify_same_file(source, bundled)

    def test_bundled_file_hash_mismatch_blocks(self):
        with tempfile.TemporaryDirectory() as raw_tmp:
            source, bundled = Path(raw_tmp) / "source", Path(raw_tmp) / "bundled"
            source.write_bytes(b"source")
            bundled.write_bytes(b"changed")
            with self.assertRaises(RuntimeError):
                MODULE.verify_same_file(source, bundled)

    def test_license_filename_discovery_is_narrow(self):
        self.assertTrue(MODULE.LICENSE_NAME.match("COPYING.RUNTIME"))
        self.assertTrue(MODULE.LICENSE_NAME.match("LICENSE"))
        self.assertTrue(MODULE.LICENSE_NAME.match("NOTICE.txt"))
        self.assertFalse(MODULE.LICENSE_NAME.match("random-license-comment.c"))

    def test_verified_vault_mapping_is_exact_not_filename_guessing(self):
        self.assertEqual(set(MODULE.ROCKY_SOURCE_RPM_VAULT), {"gcc-11.4.1-2.1.el9.src.rpm"})
        self.assertTrue(MODULE.ROCKY_SOURCE_RPM_VAULT["gcc-11.4.1-2.1.el9.src.rpm"].endswith(
            "/gcc-11.4.1-2.1.el9.src.rpm"
        ))


if __name__ == "__main__":
    unittest.main()
