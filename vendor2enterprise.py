#!/usr/bin/env python3
"""
vendor2enterprise.py
====================

Version: 1.0.0

A modern helper tool that maps vendor names to IANA Enterprise Numbers.
It supports:
    - Full IANA enterprise-numbers list (cached locally)
    - Fuzzy vendor matching on the entire IANA database
    - Manual enterprise override via --enterprise
    - Optional generation of filter YAML extensions for auto_oid_finder.py
    - Offline-safe cached mode

Cache:
    data/iana_enterprise_numbers.txt
Source:
    https://www.iana.org/assignments/enterprise-numbers/

"""

import argparse
import os
import re
import sys
import urllib.request
import textwrap
import ssl
from pathlib import Path
from typing import List, Dict, Any

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------

VERSION = "1.0.0"

IANA_URL = (
    "https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers"
)
DEFAULT_CACHE_PATH = Path("data/iana_enterprise_numbers.txt")


# ----------------------------------------------------------------------------
# Utility: Slugify
# ----------------------------------------------------------------------------

def slugify(name: str) -> str:
    s = name.lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s)
    return s.strip("_") or "vendor"


# ----------------------------------------------------------------------------
# IANA Cache Management
# ----------------------------------------------------------------------------

def download_iana_list(cache_path: Path) -> bool:
    """
    Download the IANA enterprise numbers list and save locally.
    """
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[info] Downloading IANA enterprise numbers from {IANA_URL} ...")

    try:
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(IANA_URL, timeout=20, context=ctx) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        cache_path.write_text(text, encoding="utf-8")
        print(f"[info] IANA list saved to {cache_path}")
        return True
    except Exception as e:
        print(f"[error] Failed to download IANA data: {e}")
        return False


def ensure_iana_cache(cache_path: Path, auto_sync: bool = False) -> str | None:
    """
    Ensure cached IANA file exists. Ask user if missing, unless auto_sync is on.
    Returns the file content or None.
    """
    if not cache_path.exists():
        print(f"[warn] No IANA cache found at: {cache_path}")

        if not auto_sync:
            ans = input("[prompt] Download IANA enterprise numbers now? [Y/n]: ").strip().lower()
            if ans not in ("", "y", "yes"):
                print("[info] Skipping download; cannot perform vendor lookup.")
                return None

        if not download_iana_list(cache_path):
            return None

    try:
        return cache_path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[error] Failed to read IANA cache: {e}")
        return None


# ----------------------------------------------------------------------------
# Parsing IANA Text
# ----------------------------------------------------------------------------
def parse_iana_entries(text: str) -> List[Dict[str, Any]]:
    """
    Parse IANA enterprise-numbers file to a list of entries.

    Het IANA-formaat is ongeveer:
        <number>
          <org-name>
              <contact stuff...>
        <next number>
          <next org-name>
        ...

    Soms staan number en name op dezelfde lijn, dat ondersteunen we ook:
        9   Cisco Systems, Inc.
    """
    entries: List[Dict[str, Any]] = []

    current_ent: int | None = None
    waiting_for_name = False

    for line in text.splitlines():
        raw = line.rstrip("\n")
        s = raw.strip()

        if not s or s.startswith("#"):
            continue

        # Case 1: lijn begint met een nummer
        m = re.match(r"^(\d+)\s*(.+)?$", s)
        if m:
            ent = int(m.group(1))
            rest = (m.group(2) or "").strip()

            if rest:
                # "9 Cisco Systems, Inc." op één lijn
                name = rest
                entries.append(
                    {
                        "enterprise": ent,
                        "name": name,
                        "raw": raw,
                    }
                )
                current_ent = None
                waiting_for_name = False
            else:
                # "9" alleen → volgende niet-lege niet-comment lijn is de naam
                current_ent = ent
                waiting_for_name = True
            continue

        # Case 2: we hebben net een nummer gezien en wachten op de naam
        if waiting_for_name and current_ent is not None:
            name = s
            entries.append(
                {
                    "enterprise": current_ent,
                    "name": name,
                    "raw": raw,
                }
            )
            current_ent = None
            waiting_for_name = False
            continue

        # Alle andere lijnen (contact, e-mails, etc.) negeren we

    return entries


def norm(s: str) -> str:
    """
    Normalise a string for fuzzy matching:
      - lowercase
      - remove all non-alphanumeric characters
    So: 'Cisco Systems, Inc.' -> 'ciscosystemsinc'
         'ciscoSystems'       -> 'ciscosystems'
    """
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", "", s)
    return s

# ----------------------------------------------------------------------------
# Fuzzy match on IANA database
# ----------------------------------------------------------------------------

def find_matches(query: str, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Fuzzy vendor-name search on IANA entries, with a smarter scoring:
      - exact normalised match: highest
      - name starts with query: high
      - query is prefix of name: high
      - query only appears somewhere inside: lower

    Tie-break:
      1) smallest enterprise ID (bijv. Cisco = 9 wint van Cisco Sera = 45091)
      2) shortest normalised name
      3) alphabetical
    """
    q_raw = query.strip()
    q_norm = norm(q_raw)

    ranked: List[tuple[int, int, int, str, Dict[str, Any]]] = []

    for v in entries:
        ent = v["enterprise"]
        name_raw = v["name"]
        name_norm = norm(name_raw)

        if not name_norm:
            continue

        score = 0

        if q_norm == name_norm:
            score = 100
        elif name_norm.startswith(q_norm):
            # "cisco" vs "ciscosystems" / "ciscosera"
            score = 90
        elif q_norm.startswith(name_norm):
            score = 80
        elif q_norm in name_norm:
            score = 70
        elif name_norm in q_norm:
            score = 60

        if score > 0:
            ranked.append((score, ent, len(name_norm), name_raw.lower(), v))

    # Sorteer: hoogste score, dan kleinste enterprise ID, dan kortste naam, dan alfabetisch
    ranked.sort(key=lambda x: (-x[0], x[1], x[2], x[3]))
    return [r[4] for r in ranked]


# ----------------------------------------------------------------------------
# Filter YAML generation
# ----------------------------------------------------------------------------

def generate_filter_yaml(ent: int, canonical: str) -> str:
    """
    Generate a simple vendor filter YAML (extension-style).
    This is merged with filters.yaml by auto_oid_finder.py.
    """
    root = f".1.3.6.1.4.1.{ent}"

    return textwrap.dedent(
        f"""\
        Version: 1.0

        # Vendor: {canonical}
        # Enterprise ID: {ent}
        # Vendor OID root: {root}

        # This file extends filters.yaml. Only vendor-specific parts need to be included.

        lld:
          include_roots:
            - "{root}"

          # Example of vendor-specific exact names (empty by default)
          exact_names: []

          # Example vendor exclusions (user may extend)
          exclude_roots: []

        vendor:
          # Extend vendor regex minimally (optional)
          regex: "(disk|storage|temp|fan|power|status)"

        """
    ).rstrip() + "\n"


def write_filter_file(canonical: str, ent: int, filters_dir: str, force: bool=False) -> str:
    os.makedirs(filters_dir, exist_ok=True)

    slug = slugify(canonical)
    fname = f"filters-{slug}.yml"
    path = os.path.join(filters_dir, fname)

    if os.path.exists(path) and not force:
        print(f"[warn] Not overwriting existing filter: {path}")
        print("       Use --force to override.")
        return path

    content = generate_filter_yaml(ent, canonical)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"[info] Wrote vendor filter: {path}")
    return path


# ----------------------------------------------------------------------------
# Main CLI
# ----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Map vendor names to IANA enterprise IDs and optionally generate filter YAML."
    )

    parser.add_argument("vendor_name", nargs="*", help="Vendor name for fuzzy search (ignored if --enterprise is used)")
    parser.add_argument("--enterprise", type=int, help="Direct enterprise ID (overrides fuzzy matching).")
    parser.add_argument("--name", help="Canonical vendor name when using --enterprise.")
    parser.add_argument("--write-filter", action="store_true", help="Generate vendor filter file.")
    parser.add_argument("--filters-dir", default="filters", help="Directory for vendor filter files.")
    parser.add_argument("--iana-cache", default=str(DEFAULT_CACHE_PATH), help="Path to cached IANA list.")
    parser.add_argument("--sync-iana", action="store_true", help="Force update IANA cache without prompting.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing filter file.")
    parser.add_argument("--version", action="store_true", help="Show tool version and exit.")

    args = parser.parse_args()

    if args.version:
        print(f"vendor2enterprise.py version {VERSION}")
        sys.exit(0)

    cache_path = Path(args.iana_cache)

    # --------------------------------------------------------------
    # Mode 1: Direct enterprise ID (no fuzzy match)
    # --------------------------------------------------------------
    if args.enterprise is not None:
        ent = args.enterprise
        canonical = args.name or f"Enterprise {ent}"

        print(f"[info] Using manually supplied enterprise ID: {ent}")
        print(f"[info] Canonical name: {canonical}")
        print(f"OID root: .1.3.6.1.4.1.{ent}")

        if args.write_filter:
            write_filter_file(canonical, ent, args.filters_dir, force=args.force)

        return

    # --------------------------------------------------------------
    # Mode 2: Fuzzy vendor match via IANA database
    # --------------------------------------------------------------

    if not args.vendor_name:
        print("[error] No vendor name provided and no --enterprise specified.")
        sys.exit(1)

    raw_iana = ensure_iana_cache(cache_path, auto_sync=args.sync_iana)
    if raw_iana is None:
        print("[error] No IANA data available.")
        sys.exit(1)

    entries = parse_iana_entries(raw_iana)
    if not entries:
        print("[error] Could not parse IANA enterprise list.")
        sys.exit(1)

    query = " ".join(args.vendor_name)
    matches = find_matches(query, entries)

    if not matches:
        print(f"No matches found for: {query!r}")
        print("Check the IANA list manually:")
        print("  https://www.iana.org/assignments/enterprise-numbers/")
        sys.exit(1)

    best = matches[0]
    ent = best["enterprise"]
    canonical = best["name"]

    print(f"Best match:   {canonical}")
    print(f"Enterprise:   {ent}")
    print(f"OID root:     .1.3.6.1.4.1.{ent}")
    print(f"Raw entry:    {best['raw']}")

    print()
    print("Suggested LLD include:")
    print(f'  - ".1.3.6.1.4.1.{ent}"')

    if args.write_filter:
        write_filter_file(canonical, ent, args.filters_dir, force=args.force)


if __name__ == "__main__":
    main()

