"""
tests/test_unpacker.py — Tests for core/unpacker.py (Phase 1).

Usage:
    export APKSEC_TEST_APK=/path/to/any.apk
    pytest tests/test_unpacker.py -v
"""

from pathlib import Path
from core.unpacker import UnpackedAPK


def test_package_nonempty(unpacked: UnpackedAPK):
    assert unpacked.package, "package should be non-empty"
    assert "." in unpacked.package, "package should be a dotted name"


def test_metadata_keys(unpacked: UnpackedAPK):
    required = {"package", "version_name", "version_code", "min_sdk", "target_sdk"}
    assert required.issubset(unpacked.metadata.keys())


def test_temp_dir_exists(unpacked: UnpackedAPK):
    assert unpacked.temp_dir is not None
    assert unpacked.temp_dir.exists()


def test_manifest_extracted(unpacked: UnpackedAPK):
    assert unpacked.manifest is not None
    assert unpacked.manifest.exists()
    assert unpacked.manifest.stat().st_size > 0


def test_dex_extracted(unpacked: UnpackedAPK):
    assert len(unpacked.dex_files) >= 1, "at least one .dex should be extracted"


def test_files_list_nonempty(unpacked: UnpackedAPK):
    assert len(unpacked.files) > 0
    assert "AndroidManifest.xml" in unpacked.files
