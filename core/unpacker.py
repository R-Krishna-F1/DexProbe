#!/usr/bin/env python3
"""
core/unpacker.py — APK Opening, Extraction & Cleanup.

Responsibilities (per spec):
    Opens APK with Androguard, extracts files to temp dir, handles cleanup.

Input  → APK file path
Output → UnpackedAPK (Androguard APK object + temp dir paths)

Public API
----------
    open_apk(apk_path, verbose)   → UnpackedAPK
    cleanup(unpacked)             → None
"""

from __future__ import annotations

import sys
import shutil
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from colorama import Fore, Style, init
from core.logger import ok, info, warn, err, step, section

from config import TEMP_DIR

init(autoreset=True)

# ── Androguard import (supports old and new layouts) ─────────────────────────
try:
    from androguard.core.apk import APK
except ImportError:
    from androguard.core.bytecodes.apk import APK  # type: ignore


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class UnpackedAPK:
    """
    Holds the parsed APK object and all extraction results.
    Passed to every pipeline by core/runner.py.

    Attributes
    ----------
    apk_path     Resolved source .apk path.
    apk          Parsed Androguard APK object — do NOT re-open the file.
    metadata     dict: package, version_name, version_code, sdk targets.
    files        Sorted list of all internal APK paths.
    temp_dir     Root of the extracted temp tree (None after cleanup).
    manifest     Path to raw binary AndroidManifest.xml (or None).
    dex_files    Paths of extracted .dex files.
    res_files    Paths of extracted res/ + assets/ files.
    """
    apk_path  : Path
    apk       : APK
    metadata  : dict            = field(default_factory=dict)
    files     : list[str]       = field(default_factory=list)
    temp_dir  : Optional[Path]  = field(default=None)
    manifest  : Optional[Path]  = field(default=None)
    dex_files : list[Path]      = field(default_factory=list)
    res_files : list[Path]      = field(default_factory=list)

    @property
    def package(self) -> str:
        return self.metadata.get("package", "unknown")

    @property
    def apk_name(self) -> str:
        return self.apk_path.name


# ── Public: open + extract ────────────────────────────────────────────────────

def open_apk(apk_path: str | Path, verbose: bool = False) -> UnpackedAPK:
    """
    Validate, parse, and fully extract an APK into a temp directory.

    Parameters
    ----------
    apk_path : str | Path   Path to the .apk file.
    verbose  : bool         Print full internal file list.

    Returns
    -------
    UnpackedAPK
        Fully populated — all files extracted to temp dir.

    Raises / exits
    --------------
    SystemExit(1)  on any validation or parse failure.
    """
    apk_path = Path(apk_path).resolve()
    section(f"APK UNPACKER — {apk_path.name}")

    _validate(apk_path)

    step(f"Parsing with Androguard: {apk_path.name} …")
    try:
        apk = APK(str(apk_path))
    except Exception as exc:
        err(f"Androguard failed: {exc}")
        sys.exit(1)

    metadata = _read_metadata(apk)
    _print_metadata(metadata)

    files    = _list_files(apk, verbose)
    temp_dir = _make_temp_dir(apk_path.name)
    info(f"Temp directory: {temp_dir}")

    unpacked = UnpackedAPK(
        apk_path=apk_path,
        apk=apk,
        metadata=metadata,
        files=files,
        temp_dir=temp_dir,
    )

    unpacked.manifest  = _extract_manifest(unpacked)
    unpacked.dex_files = _extract_dex(unpacked)
    unpacked.res_files = _extract_resources(unpacked)

    ok(f"Unpack complete — {len(files)} files, "
       f"{len(unpacked.dex_files)} DEX, {len(unpacked.res_files)} resources.")
    return unpacked


# ── Public: cleanup ───────────────────────────────────────────────────────────

def cleanup(unpacked: UnpackedAPK) -> None:
    """
    Delete the temp directory tree. Safe to call even if already cleaned.
    Sets unpacked.temp_dir = None after deletion.
    """
    if unpacked.temp_dir is None:
        return
    if not unpacked.temp_dir.exists():
        warn(f"Temp dir already gone: {unpacked.temp_dir}")
        unpacked.temp_dir = None
        return

    step(f"Cleaning up: {unpacked.temp_dir} …")
    shutil.rmtree(unpacked.temp_dir, ignore_errors=True)
    if not unpacked.temp_dir.exists():
        ok("Temp directory deleted.")
    else:
        warn("Some files could not be removed — manual cleanup may be needed.")
    unpacked.temp_dir = None


# ── Internal: validation ──────────────────────────────────────────────────────

def _validate(apk_path: Path) -> None:
    if not apk_path.exists():
        err(f"File not found: {apk_path}"); sys.exit(1)
    if not apk_path.is_file():
        err(f"Not a file: {apk_path}"); sys.exit(1)
    if apk_path.suffix.lower() != ".apk":
        err(f"Expected .apk, got: {apk_path.suffix or '(no extension)'}"); sys.exit(1)
    if not zipfile.is_zipfile(apk_path):
        err(f"Not a valid APK (ZIP) archive: {apk_path}"); sys.exit(1)
    size = apk_path.stat().st_size
    if size < 22:
        err(f"File too small ({size} bytes)"); sys.exit(1)
    with open(apk_path, "rb") as f:
        if f.read(4) != b"PK\x03\x04":
            err("Bad magic bytes — not a ZIP-based APK."); sys.exit(1)


# ── Internal: metadata ────────────────────────────────────────────────────────

def _read_metadata(apk: APK) -> dict:
    return {
        "package":      apk.get_package(),
        "version_name": apk.get_androidversion_name() or None,
        "version_code": apk.get_androidversion_code() or None,
        "min_sdk":      apk.get_min_sdk_version()     or None,
        "target_sdk":   apk.get_target_sdk_version()  or None,
        "max_sdk":      apk.get_max_sdk_version()     or None,
    }


def _print_metadata(meta: dict) -> None:
    W, C, R = Fore.WHITE, Fore.CYAN, Style.RESET_ALL
    print(f"\n{C}{'─' * 54}{R}")
    print(f"{C}  APK METADATA{R}")
    print(f"{C}{'─' * 54}{R}")
    for label, key in [
        ("Package",      "package"),
        ("Version Name", "version_name"),
        ("Version Code", "version_code"),
        ("Min SDK",      "min_sdk"),
        ("Target SDK",   "target_sdk"),
        ("Max SDK",      "max_sdk"),
    ]:
        print(f"  {label:<16} {W}{meta.get(key) or '(not set)'}{R}")
    print(f"{C}{'─' * 54}{R}\n")


# ── Internal: file listing ────────────────────────────────────────────────────

def _list_files(apk: APK, verbose: bool) -> list[str]:
    files = sorted(set(apk.get_files()))
    info(f"Total files inside APK: {len(files)}")
    if verbose:
        _EXT = {".dex": Fore.YELLOW, ".xml": Fore.CYAN, ".arsc": Fore.CYAN}
        print()
        for i, f in enumerate(files, 1):
            ext = Path(f).suffix.lower()
            c = (_EXT.get(ext) or
                 (Fore.GREEN if f.startswith("assets/")   else
                  Fore.BLUE  if f.startswith("res/")      else
                  Fore.RED   if f.startswith("META-INF/") else Style.RESET_ALL))
            print(f"  {i:>4}.  {c}{f}{Style.RESET_ALL}")
        print()
    return files


# ── Internal: temp dir factory ────────────────────────────────────────────────

def _make_temp_dir(apk_name: str) -> Path:
    base = Path(TEMP_DIR) / Path(apk_name).stem
    for sub in ("manifest", "dex", "resources/res", "resources/assets"):
        (base / sub).mkdir(parents=True, exist_ok=True)
    return base


def _read_raw(unpacked: UnpackedAPK, internal_path: str) -> Optional[bytes]:
    try:
        data = unpacked.apk.get_file(internal_path)
        return data if data else None
    except Exception:
        return None


# ── Internal: manifest ────────────────────────────────────────────────────────

def _extract_manifest(unpacked: UnpackedAPK) -> Optional[Path]:
    step("Extracting AndroidManifest.xml …")
    dest_dir = unpacked.temp_dir / "manifest"
    raw = _read_raw(unpacked, "AndroidManifest.xml")
    if raw is None:
        warn("AndroidManifest.xml not found."); return None

    raw_dest = dest_dir / "AndroidManifest.xml"
    raw_dest.write_bytes(raw)
    ok(f"Raw manifest → {raw_dest}  ({len(raw):,} bytes)")

    try:
        from androguard.core.axml import AXMLPrinter
        from lxml import etree
        xml_obj  = AXMLPrinter(raw).get_xml_obj()
        decoded  = etree.tostring(xml_obj, pretty_print=True, encoding="unicode")
        dec_dest = dest_dir / "AndroidManifest_decoded.xml"
        dec_dest.write_text(decoded, encoding="utf-8")
        ok(f"Decoded manifest → {dec_dest}")
    except Exception as exc:
        warn(f"Could not decode manifest: {exc}")

    return raw_dest


# ── Internal: DEX ─────────────────────────────────────────────────────────────

def _extract_dex(unpacked: UnpackedAPK) -> list[Path]:
    step("Extracting .dex files …")
    dex_dir = unpacked.temp_dir / "dex"
    entries = sorted(f for f in unpacked.files if f.lower().endswith(".dex"))
    if not entries:
        warn("No .dex files found."); return []

    extracted = []
    for entry in entries:
        raw = _read_raw(unpacked, entry)
        if raw is None:
            warn(f"  Could not read {entry} — skipping."); continue
        dest = dex_dir / Path(entry).name
        dest.write_bytes(raw)
        ok(f"  {Path(entry).name:<22} ({len(raw):,} bytes)")
        extracted.append(dest)

    info(f"Extracted {len(extracted)}/{len(entries)} .dex file(s).")
    return extracted


# ── Internal: resources ───────────────────────────────────────────────────────

def _extract_resources(unpacked: UnpackedAPK) -> list[Path]:
    step("Extracting resources (res/, assets/) …")
    res_root = unpacked.temp_dir / "resources"
    entries  = sorted(
        f for f in unpacked.files
        if f.startswith("res/") or f.startswith("assets/")
    )
    if not entries:
        warn("No res/ or assets/ files found."); return []

    extracted, res_c, asset_c = [], 0, 0
    for entry in entries:
        raw = _read_raw(unpacked, entry)
        if raw is None:
            warn(f"  Could not read {entry} — skipping."); continue
        dest = res_root / entry
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        extracted.append(dest)
        if entry.startswith("res/"): res_c += 1
        else: asset_c += 1

    ok(f"  res/: {res_c}   assets/: {asset_c}")
    info(f"Extracted {len(extracted)} resource file(s).")
    return extracted
