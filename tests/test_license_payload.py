import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLYFORM_SHA256 = "c0ea4a896d2c8c394b29f9427589996db826cd501c512279ff0ed3ef48fabbe5"


def test_project_license_payload_and_inventory_are_resolved():
    for name in ("LICENSE", "NOTICE", "COPYRIGHT.md", "COMMERCIAL_USE.md",
                 "TRADEMARKS.md", "THIRD_PARTY_NOTICES.md", "licenses/README.md"):
        assert (ROOT / name).is_file()
    inventory = json.loads(
        (ROOT / "licenses/DEPENDENCY_LICENSE_INVENTORY.json").read_text("utf-8")
    )
    assert inventory["project"]["license"] == "PolyForm-Noncommercial-1.0.0"
    assert not [item for item in inventory["components"] if item["release_blocker"]]
    license_bytes = (ROOT / "LICENSE").read_text("utf-8").replace("\r\n", "\n").encode()
    assert hashlib.sha256(license_bytes).hexdigest() == POLYFORM_SHA256
    assert "Required Notice: Copyright 2026 Kache Flanery." in (ROOT / "NOTICE").read_text("utf-8")
    metadata = (ROOT / "pyproject.toml").read_text("utf-8")
    assert "OSI Approved" not in metadata
    assert "Apache Software License" not in metadata


def test_appimage_tool_is_immutable_and_checksum_guarded():
    script = (ROOT / "scripts/try-build-appimage.sh").read_text("utf-8")
    assert "/continuous/" not in script
    assert 'tool_version=13' in script
    assert 'releases/download/$tool_version/$tool_name' in script
    assert "df3baf5ca5facbecfc2f3fa6713c29ab9cefa8fd8c1eac5d283b79cab33e4acb" in script
    assert "sha256sum --check --strict" in script
    appimage_license = (ROOT / "licenses/appimage/LICENSE").read_text("utf-8").replace("\r\n", "\n").encode()
    assert hashlib.sha256(appimage_license).hexdigest() == (
        "9cb22a08334c3a108ec4da96c1d6aea7a17a732fa9f5ca3413a9b4ce651397d8"
    )


def test_release_lock_files_use_exact_versions():
    for lock in ("requirements.lock", "requirements-build.lock", "requirements-dev.lock"):
        for raw in (ROOT / lock).read_text("utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-r"):
                continue
            requirement = line.split(";", 1)[0].strip()
            assert "==" in requirement, f"unlocked requirement in {lock}: {line}"


def test_license_validator_accepts_complete_synthetic_payload():
    (ROOT / "build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
        root = Path(temporary)
        for name in ("LICENSE", "NOTICE", "COPYRIGHT.md", "COMMERCIAL_USE.md",
                     "TRADEMARKS.md", "THIRD_PARTY_NOTICES.md"):
            (root / name).write_bytes((ROOT / name).read_bytes())
        licenses = root / "licenses"
        licenses.mkdir()
        (licenses / "README.md").write_text("inventory", encoding="utf-8")
        (licenses / "DEPENDENCY_LICENSE_INVENTORY.json").write_text("{}", encoding="utf-8")
        (licenses / "NATIVE_DEPENDENCY_INVENTORY.json").write_text(
            json.dumps({"release_blocked": False, "unattributed": [], "files": []}),
            encoding="utf-8",
        )
        subprocess.run(
            [sys.executable, str(ROOT / "scripts/validate-license-payload.py"), str(root)],
            check=True,
        )
