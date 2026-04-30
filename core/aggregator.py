#!/usr/bin/env python3
"""
core/aggregator.py — Finding Aggregator.

Responsibilities (per spec):
    Merges Finding lists from all pipelines into one flat list.

This is intentionally thin in Phase 1 — it's a pass-through today
and will gain deduplication + cross-pipeline correlation logic in Phase 10.

Public API
----------
    aggregate(findings_by_pipeline) → list[Finding]
"""

from __future__ import annotations

from models.finding import Finding


def aggregate(findings_by_pipeline: dict[str, list[Finding]]) -> list[Finding]:
    """
    Flatten per-pipeline Finding lists into one combined list.

    Parameters
    ----------
    findings_by_pipeline : dict[str, list[Finding]]
        Keys are pipeline names; values are their Finding lists.
        Example: {"manifest": [...], "secrets": [...], ...}

    Returns
    -------
    list[Finding]
        All findings in pipeline order (unsorted — call scorer after this).
    """
    combined: list[Finding] = []
    for pipeline_name, findings in findings_by_pipeline.items():
        for f in findings:
            if not f.pipeline:          # back-fill pipeline name if stub forgot
                f.pipeline = pipeline_name
        combined.extend(findings)
    return combined
