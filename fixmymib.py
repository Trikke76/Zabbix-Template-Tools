#!/usr/bin/env python3
"""
fixmymib.py
===========

Best-effort auto-fixer for ugly vendor MIBs.

Given a MIB file, it tries to apply a couple of conservative text-level
fixes that make life easier for net-snmp, PySMI etc.

Current passes:

  1) Duplicate OBJECT IDENTIFIER definitions:
     - Pattern:  <name> OBJECT IDENTIFIER ::= { ... }
     - First definition is kept.
     - Subsequent definitions of the same <name> are commented out and
       annotated with a FIXMIB marker.

  2) Reserved / core OID names:
     - Some vendor MIBs redefine core names like "system", "interfaces",
       "ip", "tcp", "udp", etc. This often leads to "Duplicate symbol"
       errors in compilers.
     - For any OBJECT IDENTIFIER definition whose name is in a small
       RESERVED_OID_NAMES set, we comment it out and annotate with FIXMIB.

  3) IMPORTS block semicolon:
     - If the IMPORTS block exists but does not contain a terminating ';',
       append ';' to the last non-comment line in the IMPORTS block.

  4) Missing DisplayString import:
     - If "DisplayString" is used but not imported anywhere, inject
       "DisplayString FROM SNMPv2-TC" into the IMPORTS block.

All other content is left untouched as much as possible.

This tool is intentionally conservative: if a MIB is truly garbage,
you may still need to fix it manually or rely on auto_oid_finder.py
to discover OIDs directly from the device.

Usage:
  fixmymib.py file.mib
  fixmymib.py file.mib --output fixed_mibs/MyModule.mib

By default the output goes to:
  fixed_mibs/<ModuleName>.mib
where <ModuleName> is taken from "MODULE-NAME DEFINITIONS ::= BEGIN".
"""

import argparse
import os
import re
import sys
from typing import List, Tuple

# Names that very often collide with core MIBs
RESERVED_OID_NAMES = {
    "system",
    "interfaces",
    "ip",
    "tcp",
    "udp",
    "snmp",
    "internet",
    "mgmt",
    "mib-2",
    "enterprises",
}


def log_info(msg: str):
    print(f"[fixmib][info] {msg}")


def log_warn(msg: str):
    print(f"[fixmib][warn] {msg}")


def log_error(msg: str):
    print(f"[fixmib][error] {msg}", file=sys.stderr)


def detect_module_name(text: str) -> str:
    """
    Extract module name from 'NAME DEFINITIONS ::= BEGIN'.
    """
    m = re.search(
        r"^\s*([A-Za-z0-9_-]+)\s+DEFINITIONS\s+::=\s+BEGIN",
        text,
        re.MULTILINE | re.IGNORECASE,
    )
    if not m:
        return "UnknownModule"
    return m.group(1)


def split_lines(text: str) -> List[str]:
    """
    Normalize line endings and split into lines.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.split("\n")


def join_lines(lines: List[str]) -> str:
    return "\n".join(lines) + "\n"


def fix_imports_block(lines: List[str]) -> Tuple[List[str], bool]:
    """
    Fixes:
      - Missing semicolon in IMPORTS block.
      - Missing DisplayString import if DisplayString is used.

    Returns (new_lines, changed_flag).
    """
    changed = False
    joined = "\n".join(lines)

    # Find IMPORTS block range
    imports_match = re.search(r"^\s*IMPORTS\b", joined, re.MULTILINE)
    if not imports_match:
        # No IMPORTS block at all
        return lines, changed

    start_idx = joined[: imports_match.start()].count("\n")
    # Approximate end: first line after IMPORTS that has ';'
    # or first non-indented, non-empty, non-comment line after a blank line
    end_idx = start_idx
    semicolon_found = False

    for idx in range(start_idx, len(lines)):
        ln = lines[idx]
        if ";" in ln:
            semicolon_found = True
        # Heuristic: IMPORTS usually ends at first completely empty line
        # after we've seen at least one "FROM" or type line.
        if idx > start_idx and ln.strip() == "":
            end_idx = idx
            break
    else:
        end_idx = len(lines)

    # Narrow down IMPORTS block lines
    imp_lines = lines[start_idx:end_idx]

    # 1) Add ';' if missing
    if not semicolon_found and imp_lines:
        # Find last non-comment, non-empty line in imports block
        for i in range(len(imp_lines) - 1, -1, -1):
            stripped = imp_lines[i].strip()
            if stripped and not stripped.startswith("--"):
                if not stripped.endswith(";"):
                    imp_lines[i] = imp_lines[i] + " ;  -- FIXMIB: added missing ';' in IMPORTS"
                    changed = True
                break

    # 2) Ensure DisplayString is imported if used
    full_text = "\n".join(lines)
    uses_displaystring = "DisplayString" in full_text
    imports_displaystring = any(
        re.search(r"\bDisplayString\b", ln) and "FROM" in ln for ln in imp_lines
    )

    if uses_displaystring and not imports_displaystring:
        # Insert DisplayString import just before the terminating ';'
        insert_line = "    DisplayString\n        FROM SNMPv2-TC  -- FIXMIB: auto-added for DisplayString"
        # Try to insert before the line containing ';' in IMPORTS block
        inserted = False
        for i in range(len(imp_lines) - 1, -1, -1):
            if ";" in imp_lines[i]:
                imp_lines.insert(i, insert_line)
                inserted = True
                break
        if not inserted:
            # Append at the end
            imp_lines.append(insert_line)
        changed = True
        log_info("Added DisplayString FROM SNMPv2-TC to IMPORTS block.")

    # Replace IMPORTS block in original lines
    new_lines = list(lines)
    new_lines[start_idx:end_idx] = imp_lines
    return new_lines, changed


def fix_duplicate_oids(lines: List[str]) -> Tuple[List[str], bool]:
    """
    Detect and comment out duplicate OBJECT IDENTIFIER definitions and
    reserved/core names.
    """
    changed = False
    seen_names = set()
    new_lines: List[str] = []

    oid_def_re = re.compile(
        r"^\s*([A-Za-z0-9_.-]+)\s+OBJECT\s+IDENTIFIER\s+::=\s*\{[^\}]*\}\s*$"
    )

    for ln in lines:
        m = oid_def_re.match(ln)
        if not m:
            new_lines.append(ln)
            continue

        name = m.group(1)

        # Duplicate within this MIB: remove second and later
        if name in seen_names:
            changed = True
            log_warn(f"Commenting out duplicate OBJECT IDENTIFIER for '{name}'.")
            new_lines.append(
                f"-- FIXMIB: removed duplicate OID definition for {name}"
            )
            new_lines.append(f"-- FIXMIB: original: {ln}")
            continue

        seen_names.add(name)

        # Reserved core names we prefer not to redefine
        if name.lower() in {n.lower() for n in RESERVED_OID_NAMES}:
            changed = True
            log_warn(
                f"Commenting out OBJECT IDENTIFIER for reserved/core name '{name}'."
            )
            new_lines.append(
                f"-- FIXMIB: commented reserved/core OID name '{name}' to avoid conflicts"
            )
            new_lines.append(f"-- FIXMIB: original: {ln}")
            continue

        new_lines.append(ln)

    return new_lines, changed


def main():
    ap = argparse.ArgumentParser(
        description="Best-effort auto-fixer for ugly vendor MIBs."
    )
    ap.add_argument("mib_file", help="Input MIB file to fix")
    ap.add_argument(
        "--output",
        "-o",
        help="Output MIB file (default: fixed_mibs/<ModuleName>.mib)",
    )
    args = ap.parse_args()

    in_path = args.mib_file
    if not os.path.exists(in_path):
        log_error(f"Input file '{in_path}' does not exist.")
        sys.exit(1)

    with open(in_path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    module_name = detect_module_name(text)
    log_info(f"Detected module name: {module_name}")

    lines = split_lines(text)
    changed_any = False

    # Pass 1: IMPORTS block fixes
    lines, changed = fix_imports_block(lines)
    changed_any = changed_any or changed

    # Pass 2: duplicate OBJECT IDENTIFIERs + reserved names
    lines, changed = fix_duplicate_oids(lines)
    changed_any = changed_any or changed

    out_path = args.output
    if not out_path:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        fixed_dir = os.path.join(base_dir, "fixed_mibs")
        os.makedirs(fixed_dir, exist_ok=True)
        out_path = os.path.join(fixed_dir, f"{module_name}.mib")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(join_lines(lines))

    if changed_any:
        log_info(f"Fixed MIB written to: {out_path}")
    else:
        log_info(
            f"No changes were necessary; copied input to: {out_path}"
        )


if __name__ == "__main__":
    main()

