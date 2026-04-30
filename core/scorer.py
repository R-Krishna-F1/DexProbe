#!/usr/bin/env python3
"""
core/scorer.py — Severity Scoring & Sorting.

Responsibilities (per spec):
    Assigns severity levels to all findings, sorts by score.

Input  → Unscored list[Finding]
Output → Scored + sorted list[Finding]

Scoring is implemented per-pipeline in Phase 10.
This module holds the sorting logic and the label assignment that
every pipeline can call during its own run() via score_finding().

Public API
----------
    score_findings(findings)    → list[Finding]  sorted descending by score
    severity_label(score)       → str            CRITICAL / HIGH / MEDIUM / LOW
"""

from __future__ import annotations

from config import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM
from models.finding import Finding


def score_findings(findings: list[Finding]) -> list[Finding]:
    """
    Apply severity labels where missing, then sort by score descending.

    Pipelines are expected to set finding.score themselves.
    This function ensures the .severity label is consistent with the score
    and returns a clean sorted list.

    Parameters
    ----------
    findings : list[Finding]   Raw findings from all pipelines.

    Returns
    -------
    list[Finding]
        Same findings, severity labels normalised, sorted by score descending.
    """
    for f in findings:
        f.severity = severity_label(f.score)
    return sorted(findings, key=lambda f: f.score, reverse=True)


def severity_label(score: float) -> str:
    """
    Map a numeric score (0–10) to a severity label.

    Thresholds are set in config.py:
        SEVERITY_CRITICAL = 9.0
        SEVERITY_HIGH     = 7.0
        SEVERITY_MEDIUM   = 4.0
        below MEDIUM      → LOW
    """
    if score >= SEVERITY_CRITICAL:
        return "CRITICAL"
    if score >= SEVERITY_HIGH:
        return "HIGH"
    if score >= SEVERITY_MEDIUM:
        return "MEDIUM"
    return "LOW"
