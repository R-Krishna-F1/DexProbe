#!/usr/bin/env python3
"""
core/runner.py — Pipeline Executor.

Responsibilities (per spec):
    Executes all pipelines in sequence, collects Finding lists.

Input  → UnpackedAPK object + pipeline selection
Output → Combined list of Finding objects (unscored)

Public API
----------
    run_pipelines(unpacked, pipelines, verbose) → list[Finding]
"""

from __future__ import annotations

import importlib
import traceback
from colorama import Fore, Style

from core.unpacker import UnpackedAPK
from core.logger   import section, info, err
from models.finding import Finding

ALL_PIPELINES = ["manifest", "secrets", "dependencies", "network", "dynamic"]


def run_pipelines(
    unpacked:  UnpackedAPK,
    pipelines: list[str] | None = None,
    verbose:   bool = False,
) -> list[Finding]:
    """
    Run each named pipeline in sequence and return the combined findings.

    Parameters
    ----------
    unpacked  : UnpackedAPK   Fully extracted APK object from core.unpacker.
    pipelines : list[str]     Names to run. Defaults to ALL_PIPELINES.
    verbose   : bool          Pass through to pipelines for extra output.

    Returns
    -------
    list[Finding]
        All findings from all pipelines, in pipeline order, unscored.
    """
    to_run   = pipelines or ALL_PIPELINES
    combined : list[Finding] = []

    section("ANALYSIS PIPELINES")

    for name in to_run:
        print(f"{Fore.CYAN}[Pipeline]{Style.RESET_ALL} Running: {name} …")
        try:
            module   = importlib.import_module(f"pipelines.{name}")
            results  = module.run(unpacked)
            combined.extend(results)
            _summary(name, results)
        except Exception as exc:
            err(f"Pipeline '{name}' failed: {exc}")
            if verbose:
                traceback.print_exc()

    info(f"All pipelines done — {len(combined)} total finding(s).")
    return combined


# ── Internal ──────────────────────────────────────────────────────────────────

def _summary(name: str, findings: list[Finding]) -> None:
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = [f"{sev}: {n}" for sev, n in sorted(counts.items())]
    label = ", ".join(parts) if parts else "none"
    print(f"{Fore.GREEN}[OK]{Style.RESET_ALL}    {name} → {len(findings)} finding(s)  [{label}]")
