#!/usr/bin/env python3
"""
pipelines/dependencies.py — Dependency & CVE Analysis Pipeline.

Input  → UnpackedAPK
Output → list[Finding]

Entry point
-----------
    run(unpacked: UnpackedAPK) -> list[Finding]
"""

from __future__ import annotations

from core.unpacker  import UnpackedAPK
from core.logger    import section, info
from models.finding import Finding

PIPELINE_NAME = "dependencies"


def run(unpacked: UnpackedAPK) -> list[Finding]:
    """
    Analyse the APK for dependencies-related security issues.

    Parameters
    ----------
    unpacked : UnpackedAPK
        Fully extracted APK object from core.unpacker.open_apk().

    Returns
    -------
    list[Finding]
        All findings. Empty list if none found or not yet implemented.
    """
    section(f"PIPELINE: {PIPELINE_NAME.upper()}")
    info("(stub — implementation coming in a future phase)")

    findings: list[Finding] = []
    # ── implementation goes here ───────────────────────────────────────────────

    info(f"{PIPELINE_NAME}: {len(findings)} finding(s).")
    return findings
