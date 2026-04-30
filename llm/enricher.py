#!/usr/bin/env python3
"""
llm/enricher.py — Gemini Enrichment Layer.

Responsibilities (per spec):
    Sends findings to Gemini, parses responses, handles retries.

Input  → list[Finding]
Output → list[Finding] with llm_risk, llm_attack, llm_fix populated

Activated in Phase 9.
"""

from __future__ import annotations
from models.finding import Finding
from core.logger import section, info

def enrich(findings: list[Finding], skip_llm: bool = False) -> list[Finding]:
    """Send each finding to Gemini and fill llm_risk/llm_attack/llm_fix."""
    if skip_llm:
        info("LLM enrichment skipped (--skip-llm).")
        return findings

    section("LLM ENRICHMENT")
    info("(stub — Gemini integration coming in Phase 9)")
    return findings
