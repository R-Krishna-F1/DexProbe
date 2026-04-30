#!/usr/bin/env python3
"""
pipelines/base.py — Shared Finding dataclass.

Every pipeline returns list[Finding].  The orchestrator aggregates these,
scores them, and hands them to the report generator.

Severity labels map to config.SEVERITY_* thresholds.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


SEVERITY_LABELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass
class Finding:
    """
    A single security finding from any pipeline.

    Attributes
    ----------
    pipeline      Name of the pipeline that produced this finding
                  (e.g. "manifest", "secrets", "network").
    title         Short one-line summary (≤ 80 chars).
    detail        Longer description of what was found and where.
    severity      One of CRITICAL / HIGH / MEDIUM / LOW / INFO.
    score         Raw numeric score 0–10 (used for sorting).
    location      File path + line reference inside the APK or temp tree.
    evidence      The raw value that triggered the finding
                  (e.g. partial key, URL, class name).
    tags          Free-form labels for filtering (e.g. ["exported", "no-permission"]).
    llm_risk      Gemini-generated risk explanation (filled in Phase 9).
    llm_attack    Gemini-generated attack scenario (filled in Phase 9).
    llm_fix       Gemini-generated fix recommendation (filled in Phase 9).
    """
    pipeline  : str
    title     : str
    detail    : str
    severity  : str  = "LOW"
    score     : float = 0.0
    location  : str  = ""
    evidence  : str  = ""
    tags      : list[str] = field(default_factory=list)

    # Populated by LLM layer (Phase 9)
    llm_risk   : Optional[str] = None
    llm_attack : Optional[str] = None
    llm_fix    : Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "pipeline":   self.pipeline,
            "title":      self.title,
            "detail":     self.detail,
            "severity":   self.severity,
            "score":      self.score,
            "location":   self.location,
            "evidence":   self.evidence,
            "tags":       self.tags,
            "llm_risk":   self.llm_risk,
            "llm_attack": self.llm_attack,
            "llm_fix":    self.llm_fix,
        }
