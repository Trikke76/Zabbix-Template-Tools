#!/usr/bin/env python3
"""
vendor2enterprise.py
====================

Version: 1.1.0

Helper tool to map vendor names to IANA enterprise numbers and generate
a filters/filters_<vendor>.yaml file suitable for auto_oid_finder.py.

Data source for enterprise numbers:
    https://www.iana.org/assignments/enterprise-numbers/

Features:
  - Fuzzy matching on vendor name (e.g. "nimble", "hpe nimble", "qnap", "cisco").
  - Prints enterprise ID and .1.3.6.1.4.1.<enterprise> root.
  - Caches IANA enterprise list locally (data/iana_enterprise_numbers.txt).
  - Tries to locate vendor MIBs under a LibreNMS-style tree:
        librenms_mibs/mibs/<vendor>/
  - Parses MIB files for OBJECT-TYPE names and builds:
        * vendor.regex       → match interessante metrics
        * lld.exact_names    → kolomnamen die vaak als LLD-macro nuttig zijn
  - With --write-filter, generates a filter YAML in filters/:

      * If MIBs gevonden → vendor-specifieke filter op basis van MIB-names.
      * Anders → generic boilerplate filter (backwards compatible).

Usage examples:
  ./vendor2enterprise.py qnap --write-filter
  ./vendor2enterprise.py cisco --write-filter
"""

import argparse
import os
import re
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import ssl
import urllib.request

VERSION = "1.1.0"

# ---------------------------------------------------------------------------
# Config & paths
# ---------------------------------------------------------------------------

IANA_URL = "https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers"
DEFAULT_IANA_CACHE = "data/iana_enterprise_numbers.txt"
DEFAULT_FILTERS_DIR = "filters"
DEFAULT_MIB_ROOT = "librenms_mibs/mibs"

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------


def log_info(msg: str) -> None:
    print(f"[info] {msg}")


def log_warn(msg: str) -> None:
    print(f"[warn] {msg}")


def log_error(msg: str) -> None:
    print(f"[error] {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# IANA enterprise list handling
# ---------------------------------------------------------------------------


def ensure_iana_cache(
    cache_path: str = DEFAULT_IANA_CACHE,
    force_sync: bool = False,
    allow_prompt: bool = True,
) -> Optional[str]:
    """
    Ensure the local IANA enterprise cache exists.

    Returns the path to the cache file, or None if not available.
    """
    cache = Path(cache_path)

    if cache.exists() and not force_sync:
        log_info(f"Using existing IANA cache: {cache}")
        return str(cache)

    if not allow_prompt and not force_sync:
        log_warn(f"No IANA cache at {cache} and no sync requested.")
        return None

    # Ask user if we should download (unless force_sync)
    if allow_prompt and not force_sync:
        ans = input(
            f"[prompt] Download IANA enterprise numbers now into {cache}? [Y/n]: "
        ).strip().lower()
        if ans not in ("", "y", "yes"):
            log_warn("User opted not to download IANA enterprise list.")
            return None

    log_info(f"Downloading IANA enterprise numbers from {IANA_URL} ...")
    cache.parent.mkdir(parents=True, exist_ok=True)

    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(IANA_URL, context=ctx) as resp:
            data = resp.read().decode("utf-8", errors="replace")
        cache.write_text(data, encoding="utf-8")
        log_info(f"Wrote IANA cache to {cache}")
        return str(cache)
    except Exception as e:
        log_error(f"Failed to download IANA data: {e!r}")
        return None


def parse_iana_entries(cache_path: str) -> List[Dict[str, Any]]:
    """
    Parse the IANA enterprise file into a list of entries:
      [{"id": 9, "name": "ciscoSystems", "raw": "9  ciscoSystems ..."}, ...]

    We only look at lines that start with an integer ID.
    """
    p = Path(cache_path)
    text = p.read_text(encoding="utf-8", errors="replace")
    entries: List[Dict[str, Any]] = []

    for line in text.splitlines():
        # Typical format: "9   ciscoSystems          ..." OR "9  ciscoSystems"
        m = re.match(r"^\s*(\d+)\s+([^\t#]+)", line)
        if not m:
            continue
        ent_id = int(m.group(1))
        name = m.group(2).strip()
        if not name:
            continue
        entries.append(
            {
                "id": ent_id,
                "name": name,
                "raw": line.rstrip(),
            }
        )

    return entries


def fuzzy_find_iana(
    query: str,
    entries: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Fuzzy match the vendor query against IANA 'name' field.

    Scoring:
      3 = exact match (case-insensitive)
      2 = query is substring of name or vice versa
      1 = token overlap / partial word match
    """
    q = query.lower().strip()
    if not q:
        return None

    best: Optional[Tuple[int, Dict[str, Any]]] = None

    q_tokens = set(re.split(r"[^a-z0-9]+", q))

    for e in entries:
        name = e["name"]
        n = name.lower()

        score = 0
        if q == n:
            score = 3
        elif q in n or n in q:
            score = 2
        else:
            n_tokens = set(re.split(r"[^a-z0-9]+", n))
            if q_tokens.intersection(n_tokens):
                score = 1

        if score > 0:
            if best is None or score > best[0]:
                best = (score, e)

    return best[1] if best else None


# ---------------------------------------------------------------------------
# MIB directory discovery (LibreNMS-style)
# ---------------------------------------------------------------------------


def slugify_name(name: str) -> str:
    s = name.lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "vendor"


def find_vendor_mib_dir(
    vendor_name: str,
    mib_root: str = DEFAULT_MIB_ROOT,
) -> Optional[str]:
    """
    Try to locate a matching vendor MIB directory under mib_root.

    For example:
      vendor_name = "ciscoSystems"
      mib_root    = "librenms_mibs/mibs"
      possible dirs: "cisco", "cisco-wlc", ...

    We pick the best match based on a simple fuzzy scoring.
    """
    root = Path(mib_root)
    if not root.is_dir():
        log_warn(f"MIB root '{mib_root}' does not exist; skipping MIB-based tuning.")
        return None

    candidates = [d for d in root.iterdir() if d.is_dir()]
    if not candidates:
        log_warn(f"No subdirs under MIB root '{mib_root}'.")
        return None

    v_slug = slugify_name(vendor_name)
    v_lower = vendor_name.lower()
    v_tokens = set(re.split(r"[^a-z0-9]+", v_lower))

    best: Optional[Tuple[int, Path]] = None

    for d in candidates:
        name = d.name
        n = name.lower()
        score = 0

        if n == v_slug or n == v_lower:
            score = 4
        elif v_slug in n or n in v_slug:
            score = 3
        elif v_lower in n or n in v_lower:
            score = 2
        else:
            n_tokens = set(re.split(r"[^a-z0-9]+", n))
            if v_tokens.intersection(n_tokens):
                score = 1

        if score > 0:
            if best is None or score > best[0]:
                best = (score, d)

    if not best:
        log_warn(
            f"No matching vendor MIB directory found under '{mib_root}' for '{vendor_name}'."
        )
        return None

    chosen = best[1]
    log_info(f"Using vendor MIB directory: {chosen}")
    return str(chosen)


# ---------------------------------------------------------------------------
# MIB parser (very lightweight)
# ---------------------------------------------------------------------------


def collect_mib_object_names(mib_dir: str) -> List[str]:
    """
    Scan all MIB files under mib_dir and extract OBJECT-TYPE names.

    We only care about lines that look like:
        someName  OBJECT-TYPE

    Returns a de-duplicated, sorted list of object names.
    """
    names: set[str] = set()
    base = Path(mib_dir)

    exts = {".txt", ".my", ".mib", ".asn1"}

    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in exts:
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            log_warn(f"Failed to read MIB file {path}: {e}")
            continue

        for line in text.splitlines():
            # Very common pattern: "HdTemperature OBJECT-TYPE  -- Disk temp"
            m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9\-]*)\s+OBJECT-TYPE\b", line)
            if not m:
                continue
            name = m.group(1).strip()
            if name:
                names.add(name)

    result = sorted(names)
    log_info(f"Collected {len(result)} OBJECT-TYPE names from MIBs in {mib_dir}")
    return result


def classify_names_for_vendor(names: List[str]) -> Tuple[List[str], List[str]]:
    """
    Given a list of OBJECT-TYPE names, decide:
      - which ones are useful for vendor.regex (metrics & statuses)
      - which ones should go into lld.exact_names (columns that identify rows)

    Returns (vendor_regex_names, exact_names).
    """
    vendor_names: List[str] = []
    exact_names: List[str] = []

    # Keywords – vendor metrics we care about
    METRIC_KEYWORDS = [
        "temp",
        "temperature",
        "thermal",
        "fan",
        "rpm",
        "speed",
        "volt",
        "voltage",
        "amp",
        "current",
        "watt",
        "power",
        "psu",
        "disk",
        "hdd",
        "ssd",
        "raid",
        "array",
        "lun",
        "volume",
        "pool",
        "capacity",
        "size",
        "usage",
        "used",
        "free",
        "space",
        "load",
        "cpu",
        "mem",
        "memory",
        "cache",
        "bandwidth",
        "throughput",
        "errors",
        "error",
        "discard",
        "status",
        "state",
        "health",
        "alarm",
        "alert",
        "critical",
    ]

    # Exact-name candidates – good LLD columns / labels
    EXACT_HINTS = [
        "descr",
        "description",
        "name",
        "index",
        "id",
        "label",
        "mount",
        "fs",
        "filesystem",
        "disk",
        "volume",
        "slot",
        "bay",
        "port",
    ]

    for n in names:
        lower = n.lower()

        # Vendor regex: any metric-ish keyword
        if any(kw in lower for kw in METRIC_KEYWORDS):
            vendor_names.append(n)

        # exact_names: columns with label/descr/name/capacity/temperature/status etc.
        score = 0
        for kw in EXACT_HINTS:
            if kw in lower:
                score += 1

        # Bonus for "nice shapes"
        if lower.endswith(("descr", "description", "name", "index", "id")):
            score += 2

        if any(
            kw in lower
            for kw in [
                "capacity",
                "temperature",
                "temp",
                "status",
                "health",
                "size",
                "speed",
                "serial",
            ]
        ):
            score += 1

        if score > 0:
            exact_names.append(n)

    # Dedup & sort
    vendor_names = sorted(set(vendor_names))
    exact_names = sorted(set(exact_names))

    return vendor_names, exact_names


def build_vendor_regex_from_names(vendor_names: List[str]) -> Optional[str]:
    """
    Turn a list of OBJECT-TYPE names into a vendor.regex pattern.

    We build something like:
      (HdTemperature|HdCapacity|sysFanSpeed|... )

    To keep regex manageable, we cap the number of names.
    """
    if not vendor_names:
        return None

    MAX_NAMES = 80  # cap to avoid insane regex length
    selected = vendor_names[:MAX_NAMES]

    # Escape names for regex
    parts = [re.escape(n) for n in selected]
    pattern = "|".join(parts)

    # Wrap in non-capturing group to combine with base vendor.regex via OR
    return f"(?:{pattern})"


# ---------------------------------------------------------------------------
# Filter YAML generation
# ---------------------------------------------------------------------------


def generate_filter_yaml_from_mibs(
    ent: int,
    canonical: str,
    mib_dir: str,
) -> str:
    """
    Build a vendor-specific filter YAML based on parsed MIB names.
    """
    root = f".1.3.6.1.4.1.{ent}"
    names = collect_mib_object_names(mib_dir)
    vendor_names, exact_names = classify_names_for_vendor(names)
    vendor_pattern = build_vendor_regex_from_names(vendor_names)

    if vendor_pattern:
        vendor_regex = vendor_pattern
    else:
        # fallback minimal pattern
        vendor_regex = "(disk|storage|temp|fan|power|status)"

    # exact_names can be empty – that's fine
    exact_names_yaml = "\n".join(f"    - {name}" for name in exact_names) if exact_names else "    # (none detected)"

    yaml_content = textwrap.dedent(
        f"""\
        Version: 1.1-mib

        # Vendor: {canonical}
        # Enterprise ID: {ent}
        # Vendor OID root: {root}
        #
        # This file extends filters.yaml. Only vendor-specific parts are included.
        # It was generated from OBJECT-TYPE names found under:
        #   {mib_dir}

        lld:
          # Vendor-specific tables we always want to consider (root subtree)
          include_roots:
            - "{root}"

          # Columns that are good candidates for LLD macros (MODULE::name)
          exact_names:
{exact_names_yaml}

          # Optional vendor-specific LLD exclusions (add here if you find junk tables)
          exclude_roots: []

        vendor:
          # Vendor-specific scalar filter based on MIB OBJECT-TYPE names.
          # This will be OR'ed with the base vendor.regex from filters.yaml.
          regex: >
            {vendor_regex}
        """
    ).rstrip() + "\n"

    return yaml_content


def generate_generic_filter_yaml(ent: int, canonical: str) -> str:
    """
    Fallback template for vendors without MIBs or where parsing fails.
    """
    root = f".1.3.6.1.4.1.{ent}"
    return textwrap.dedent(
        f"""\
        Version: 1.0-generic

        # Vendor: {canonical}
        # Enterprise ID: {ent}
        # Vendor OID root: {root}
        #
        # This file extends filters.yaml. Only vendor-specific parts are included.

        lld:
          include_roots:
            - "{root}"

          # Example of vendor-specific exact names (empty by default)
          exact_names: []

          # Example vendor exclusions (user may extend)
          exclude_roots: []

        vendor:
          # Minimal generic vendor filter (safe baseline).
          regex: "(disk|storage|temp|fan|power|status)"
        """
    ).rstrip() + "\n"


def write_filter_file(
    enterprise_id: int,
    canonical_name: str,
    filters_dir: str,
    mib_root: str,
    force: bool = False,
) -> str:
    """
    Generate a filters/filters_<slug>.yaml file for the given vendor.

    Returns the path to the written file.
    """
    os.makedirs(filters_dir, exist_ok=True)

    slug = slugify_name(canonical_name)
    filename = f"filters-{slug}.yaml"
    path = os.path.join(filters_dir, filename)

    if os.path.exists(path) and not force:
        log_warn(f"Filter file already exists: {path}")
        log_warn("Use --force to overwrite.")
        return path

    # Try to locate vendor MIB dir
    mib_dir = find_vendor_mib_dir(canonical_name, mib_root=mib_root)

    if mib_dir:
        log_info("Building vendor-specific filter from MIB OBJECT-TYPE names.")
        content = generate_filter_yaml_from_mibs(enterprise_id, canonical_name, mib_dir)
    else:
        log_warn("No vendor MIB directory found; using generic fallback filter.")
        content = generate_generic_filter_yaml(enterprise_id, canonical_name)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    log_info(f"Wrote vendor filter: {path}")
    return path


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Map vendor name to enterprise ID and generate a filters/*.yaml "
            "file suitable for auto_oid_finder.py (using filters.yaml as base)."
        )
    )
    parser.add_argument(
        "vendor_name",
        nargs="+",
        help="Vendor name (e.g. 'nimble', 'qnap', 'cisco', 'hpe nimble')",
    )
    parser.add_argument(
        "--write-filter",
        action="store_true",
        help="Generate a filters/filters-<vendor>.yaml file for the best match.",
    )
    parser.add_argument(
        "--filters-dir",
        default=DEFAULT_FILTERS_DIR,
        help=f"Directory where filter files are stored (default: {DEFAULT_FILTERS_DIR}).",
    )
    parser.add_argument(
        "--mib-root",
        default=DEFAULT_MIB_ROOT,
        help=f"Root directory of LibreNMS-style MIB tree (default: {DEFAULT_MIB_ROOT}).",
    )
    parser.add_argument(
        "--iana-cache",
        default=DEFAULT_IANA_CACHE,
        help=f"Path to local IANA enterprise cache (default: {DEFAULT_IANA_CACHE}).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing filter file if it already exists.",
    )
    parser.add_argument(
        "--force-iana-sync",
        action="store_true",
        help="Force re-download of IANA enterprise list into cache.",
    )
    parser.add_argument(
        "--enterprise",
        type=int,
        help="Explicit enterprise ID (skip IANA lookup; still uses vendor_name as canonical).",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show script version and exit.",
    )

    args = parser.parse_args()

    if args.version:
        print(f"vendor2enterprise.py version {VERSION}")
        sys.exit(0)

    query = " ".join(args.vendor_name).strip()
    if not query:
        parser.error("vendor_name is required")

    # Determine enterprise ID & canonical name
    enterprise_id: Optional[int] = args.enterprise
    canonical_name: Optional[str] = None
    raw_line: Optional[str] = None

    if enterprise_id is not None:
        canonical_name = query
        log_info(
            f"Using explicit enterprise ID {enterprise_id} for vendor '{canonical_name}'."
        )
    else:
        # IANA lookup path
        cache_path = ensure_iana_cache(
            cache_path=args.iana_cache,
            force_sync=args.force_iana_sync,
            allow_prompt=True,
        )
        if not cache_path:
            log_error(
                "No IANA data available and no --enterprise provided.\n"
                "Check the IANA list manually:\n"
                "  https://www.iana.org/assignments/enterprise-numbers/"
            )
            sys.exit(1)

        entries = parse_iana_entries(cache_path)
        if not entries:
            log_error(
                "IANA cache appears empty or could not be parsed.\n"
                "Check the file or re-download."
            )
            sys.exit(1)

        best = fuzzy_find_iana(query, entries)
        if not best:
            print(f"No matches found for: {query!r}")
            print("Check the IANA list manually:")
            print("  https://www.iana.org/assignments/enterprise-numbers/")
            sys.exit(1)

        enterprise_id = best["id"]
        canonical_name = best["name"]
        raw_line = best["raw"]

    # Safety assertion
    assert enterprise_id is not None
    assert canonical_name is not None

    root = f".1.3.6.1.4.1.{enterprise_id}"

    print(f"Best match:   {canonical_name}")
    print(f"Enterprise:   {enterprise_id}")
    print(f"OID root:     {root}")
    if raw_line:
        print(f"Raw entry:      {raw_line}")

    print()
    print("Suggested LLD include:")
    print(f'  - "{root}"')

    slug = slugify_name(canonical_name)
    filter_file = f"filters-{slug}.yaml"
    print()
    print("Suggested filter filename:")
    print(f"  {args.filters_dir}/{filter_file}")

    if args.write_filter:
        print()
        write_filter_file(
            enterprise_id=enterprise_id,
            canonical_name=canonical_name,
            filters_dir=args.filters_dir,
            mib_root=args.mib_root,
            force=args.force,
        )


if __name__ == "__main__":
    main()

