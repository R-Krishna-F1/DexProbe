"""
tests/conftest.py — Shared pytest fixtures.

Set APKSEC_TEST_APK to your CTF/HTB APK path before running:
    export APKSEC_TEST_APK=/path/to/your.apk
    pytest tests/ -v
"""

import os
import pytest
from pathlib import Path
from core.unpacker import open_apk, cleanup, UnpackedAPK


def _apk_path() -> Path | None:
    raw = os.getenv("APKSEC_TEST_APK")
    if not raw:
        return None
    p = Path(raw)
    return p if p.exists() and p.suffix == ".apk" else None


@pytest.fixture(scope="session")
def unpacked():
    """
    Open and extract a real APK once for the whole test session.
    Skipped automatically when APKSEC_TEST_APK is not set.
    """
    path = _apk_path()
    if path is None:
        pytest.skip("APKSEC_TEST_APK not set or file not found")

    u = open_apk(path, verbose=False)
    yield u
    cleanup(u)
