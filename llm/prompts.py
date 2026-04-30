#!/usr/bin/env python3
"""
llm/prompts.py — Prompt templates for Gemini enrichment.

One build_prompt() function per pipeline type.
Activated in Phase 9.
"""

from models.finding import Finding

def build_prompt(finding: Finding) -> str:
    """Build a structured Gemini prompt for a single finding."""
    return (
        f"Pipeline: {finding.pipeline}\n"
        f"Finding: {finding.title}\n"
        f"Detail: {finding.detail}\n"
        f"Evidence: {finding.evidence}\n\n"
        "Respond with three sections:\n"
        "1. RISK: Plain-English explanation of the security risk.\n"
        "2. ATTACK: Step-by-step attack scenario.\n"
        "3. FIX: Exact code or config change needed to fix it."
    )
