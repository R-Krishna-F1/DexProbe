#!/usr/bin/env python3
"""
output/report.py — Terminal Renderer + JSON Exporter.

Responsibilities (per spec):
    Terminal renderer (ANSI colors) + JSON file exporter.

Input  → list[Finding] + scan metadata
Output → Coloured terminal output + optional JSON file

Activated in Phase 11.
"""

from __future__ import annotations
import json
from pathlib import Path
from colorama import Fore, Style
from models.finding import Finding
from core.logger import section, info, ok

SEVERITY_COLOUR = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.RED,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.CYAN,
    "INFO":     Fore.WHITE,
}


def render_terminal(findings: list[Finding], meta: dict) -> None:
    """Print a colour-coded findings report to stdout."""
    section("SCAN REPORT")

    if not findings:
        print(f"{Fore.GREEN}  No findings.{Style.RESET_ALL}\n")
        return

    for f in findings:
        colour = SEVERITY_COLOUR.get(f.severity, Fore.WHITE)
        print(f"  {colour}[{f.severity}]{Style.RESET_ALL}  {f.title}")
        if f.location:
            print(f"           {Fore.WHITE}{f.location}{Style.RESET_ALL}")
        if f.evidence:
            print(f"           Evidence: {f.evidence}")
        print()

    _print_summary(findings)


def export_json(findings: list[Finding], meta: dict, output_path: Path) -> None:
    """Write all findings to a structured JSON file."""
    payload = {
        "meta":     meta,
        "findings": [f.to_dict() for f in findings],
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    ok(f"JSON report → {output_path}")


def _print_summary(findings: list[Finding]) -> None:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"{Fore.CYAN}{'─' * 54}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 54}{Style.RESET_ALL}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = counts.get(sev, 0)
        colour = SEVERITY_COLOUR.get(sev, Fore.WHITE)
        print(f"  {colour}{sev:<10}{Style.RESET_ALL}  {n}")
    print(f"{Fore.CYAN}{'─' * 54}{Style.RESET_ALL}\n")
