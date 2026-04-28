#!/usr/bin/env python3
"""
main.py — APK Security Intelligence Platform
Entry point. Accepts an APK file via CLI and orchestrates all analysis pipelines.

Usage:
    python main.py <path/to/app.apk> [options]
    python main.py --help
"""

import sys
import os
import argparse
import time
from pathlib import Path

from colorama import init, Fore, Style

from config import TOOL_NAME, TOOL_VERSION

# Initialize colorama for cross-platform color support
init(autoreset=True)


# ── Banner ────────────────────────────────────────────────────────────────────

def print_banner():
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
  █████╗ ██████╗ ██╗  ██╗    ██╗███╗   ██╗████████╗███████╗██╗     
 ██╔══██╗██╔══██╗██║ ██╔╝    ██║████╗  ██║╚══██╔══╝██╔════╝██║     
 ███████║██████╔╝█████╔╝     ██║██╔██╗ ██║   ██║   █████╗  ██║     
 ██╔══██║██╔═══╝ ██╔═██╗     ██║██║╚██╗██║   ██║   ██╔══╝  ██║     
 ██║  ██║██║     ██║  ██╗    ██║██║ ╚████║   ██║   ███████╗███████╗
 ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝    ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝
{Style.RESET_ALL}
{Fore.WHITE}  {TOOL_NAME} v{TOOL_VERSION} — Android APK Security Intelligence Platform
{Fore.YELLOW}  5 Pipelines · LLM-Powered Explanations · Reachability Analysis
{Style.RESET_ALL}
"""
    print(banner)


# ── Argument Parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apk-intel",
        description=(
            f"{TOOL_NAME} v{TOOL_VERSION} — Tear apart Android APKs across "
            "5 security pipelines and generate LLM-powered threat reports."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Pipelines:
  1  dependency   Third-party library CVE lookup + reachability analysis
  2  secrets      Hardcoded secrets, keys, tokens, and encoded credentials
  3  manifest     AndroidManifest.xml risk profiling
  4  network      Hardcoded URLs, plain HTTP endpoints, suspicious domains
  5  dynload      Dynamic class loading and reflection API usage

Examples:
  python main.py app.apk
  python main.py app.apk --output report.json
  python main.py app.apk --skip-llm --pipeline manifest
  python main.py app.apk --verbose
        """,
    )

    # Positional
    parser.add_argument(
        "apk_file",
        metavar="APK_FILE",
        help="Path to the .apk file to analyse",
    )

    # Output
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        default=None,
        help="Path to write the JSON report (default: <apk_name>_report.json)",
    )

    # Speed / scope
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        default=False,
        help="Skip Gemini LLM calls — run analysis only, no explanations (faster)",
    )
    parser.add_argument(
        "--pipeline",
        metavar="NAME",
        choices=["dependency", "secrets", "manifest", "network", "dynload"],
        default=None,
        help="Run only a single named pipeline instead of all five",
    )

    # Verbosity
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable verbose/debug output",
    )

    # Meta
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )

    return parser


# ── File Validation ───────────────────────────────────────────────────────────

def validate_apk(path: str, verbose: bool = False) -> Path:
    """
    Validate that the supplied path points to a readable .apk file.
    Returns a resolved Path object on success, exits with a clear error on failure.
    """
    apk_path = Path(path)

    # Existence check
    if not apk_path.exists():
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} File not found: {path}")
        sys.exit(1)

    # Is it actually a file (not a directory)?
    if not apk_path.is_file():
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Path is not a file: {path}")
        sys.exit(1)

    # Extension check
    if apk_path.suffix.lower() != ".apk":
        print(
            f"{Fore.RED}[ERROR]{Style.RESET_ALL} "
            f"Expected a .apk file, got: {apk_path.suffix or '(no extension)'}"
        )
        sys.exit(1)

    # Readability check
    if not os.access(apk_path, os.R_OK):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} File is not readable: {path}")
        sys.exit(1)

    # Minimum size sanity check — a valid APK is at minimum a ZIP file (22 bytes)
    size = apk_path.stat().st_size
    if size < 22:
        print(
            f"{Fore.RED}[ERROR]{Style.RESET_ALL} "
            f"File is too small to be a valid APK ({size} bytes)"
        )
        sys.exit(1)

    # ZIP magic bytes check — APKs are ZIP archives; first 4 bytes = PK\x03\x04
    with open(apk_path, "rb") as f:
        magic = f.read(4)
    if magic != b"PK\x03\x04":
        print(
            f"{Fore.RED}[ERROR]{Style.RESET_ALL} "
            "File does not appear to be a valid APK (bad magic bytes). "
            "The file may be corrupt or not a ZIP-based APK."
        )
        sys.exit(1)

    if verbose:
        print(
            f"{Fore.GREEN}[OK]{Style.RESET_ALL} "
            f"APK validated: {apk_path.resolve()} ({size:,} bytes)"
        )

    return apk_path.resolve()


# ── Scan Orchestrator (stub — filled in Phase 2+) ────────────────────────────

def run_scan(apk_path: Path, args: argparse.Namespace) -> dict:
    """
    Orchestrate all analysis pipelines against the validated APK.
    Each pipeline will be imported and called here as it is built.
    Returns a unified findings dict for report generation.
    """
    findings = {
        "meta": {
            "tool":      TOOL_NAME,
            "version":   TOOL_VERSION,
            "apk_path":  str(apk_path),
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "skip_llm":  args.skip_llm,
            "pipeline":  args.pipeline,
        },
        "manifest":   [],
        "secrets":    [],
        "network":    [],
        "dynload":    [],
        "dependency": [],
    }

    print(f"\n{Fore.CYAN}[APK Intel]{Style.RESET_ALL} Target: {apk_path.name}")
    print(f"{Fore.CYAN}[APK Intel]{Style.RESET_ALL} Scan started at {findings['meta']['scan_time']}\n")

    # ── Pipeline stubs (activated in later phases) ────────────────────────────
    pipelines_to_run = (
        [args.pipeline] if args.pipeline
        else ["manifest", "secrets", "network", "dynload", "dependency"]
    )

    for pipeline in pipelines_to_run:
        print(f"{Fore.YELLOW}[--]{Style.RESET_ALL} Pipeline '{pipeline}' — coming in a future phase.")

    print(
        f"\n{Fore.GREEN}[APK Intel]{Style.RESET_ALL} "
        "Phase 0 complete. Project scaffold is ready.\n"
    )

    return findings


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    print_banner()

    parser  = build_parser()
    args    = parser.parse_args()

    if args.verbose:
        print(f"{Fore.BLUE}[VERBOSE]{Style.RESET_ALL} Arguments: {vars(args)}\n")

    # Validate APK before doing anything else
    apk_path = validate_apk(args.apk_file, verbose=args.verbose)

    # Run the scan
    run_scan(apk_path, args)


if __name__ == "__main__":
    main()
