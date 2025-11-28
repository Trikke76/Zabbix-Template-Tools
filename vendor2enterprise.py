#!/usr/bin/env python3
"""
vendor2enterprise.py
====================

Version: 1.1.1

Helper tool to map vendor names to IANA enterprise numbers and optionally
generate a filters/filters-<vendor>.yml file suitable for auto_oid_finder.py.

Data source for enterprise numbers:
    https://www.iana.org/assignments/enterprise-numbers/

Key features:
  - Downloads and caches the IANA enterprise-numbers file in
    data/iana_enterprise_numbers.txt
  - Parses the real IANA layout:

        <id>
          <name>
              <contact>
              ...

  - Fuzzy-matches vendor names, e.g.:
        ./vendor2enterprise.py cisco --write-filter
        ./vendor2enterprise.py qnap  --write-filter

  - Or bypass IANA and force a specific enterprise ID/name:
        ./vendor2enterprise.py --enterprise 9 --name "ciscoSystems" --write-filter

  - Writes small vendor extension files that MERGE with filters/filters.yaml:
        filters/filters-ciscosystems.yml
        filters/filters-qnap_systems_inc.yml

  - For some vendors (QNAP, Cisco, ...) we use a built-in profile to:
        * add extra include_roots (QNAP 24681 + 55062)
        * set lld.exact_names (HdCapacity, HdSmartInfo, ...)
        * set lld.exclude_roots (junk tables)
        * set vendor.regex
"""

import argparse
import os
import re
import sys
import textwrap
from typing import List, Dict, Any, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

VERSION = "1.1.1"

IANA_URL = "https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers"
DEFAULT_CACHE_PATH = os.path.join("data", "iana_enterprise_numbers.txt")


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
# IANA enterprise-numbers handling
# ---------------------------------------------------------------------------

def download_iana_cache(cache_path: str) -> bool:
    """
    Download the IANA enterprise-numbers file and save it as cache_path.

    Returns True on success, False otherwise.
    """
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)

    log_info(f"Downloading IANA enterprise numbers from {IANA_URL} ...")
    req = Request(IANA_URL, headers={"User-Agent": "vendor2enterprise/1.1.1"})
    try:
        with urlopen(req, timeout=30) as resp:
            data = resp.read()
    except (URLError, HTTPError) as e:
        log_error(f"Failed to download IANA data: {e}")
        return False

    text = data.decode("utf-8", errors="replace")
    with open(cache_path, "w", encoding="utf-8") as f:
        f.write(text)

    log_info(f"Saved IANA enterprise numbers to {cache_path}")
    return True


def ensure_iana_cache(cache_path: str) -> str | None:
    """
    Ensure the IANA cache file exists. If not, ask the user if we may download it.

    Returns the path if available, or None if not.
    """
    if os.path.exists(cache_path):
        log_info(f"Using existing IANA cache: {cache_path}")
        return cache_path

    # No cache yet: prompt user
    print(f"[warn] No IANA cache found at: {cache_path}")
    ans = input("[prompt] Download IANA enterprise numbers now? [Y/n]: ").strip().lower()
    if ans in ("", "y", "yes"):
        ok = download_iana_cache(cache_path)
        if not ok:
            return None
        return cache_path

    log_warn("User declined to download IANA enterprise numbers.")
    return None


def parse_iana_entries(text: str) -> List[Dict[str, Any]]:
    """
    Parse the content of the IANA enterprise-numbers file.

    The real format is roughly:

        <id>
          <name>
              <contact>
              ...

    So we look for a line that is ONLY digits, treat that as the ID, and then
    the next non-empty, non-comment line is the name.

    Returns a list of:
        { "enterprise": <int>, "name": <str> }
    """
    entries: List[Dict[str, Any]] = []
    lines = text.splitlines()
    n = len(lines)
    i = 0

    while i < n:
        line = lines[i].strip()
        # Skip empty or comment lines
        if not line or line.startswith("#"):
            i += 1
            continue

        # ID line: must be all digits
        if line.isdigit():
            ent = int(line)
            name = None

            j = i + 1
            while j < n:
                name_line = lines[j].rstrip("\n")
                stripped = name_line.strip()

                if not stripped:
                    j += 1
                    continue
                if stripped.startswith("#"):
                    j += 1
                    continue

                # This is our canonical name
                name = stripped
                break

            if name:
                entries.append({"enterprise": ent, "name": name})
            i = j if j > i else i + 1
            continue

        # Not an ID, skip
        i += 1

    return entries


def load_iana_entries(cache_path: str) -> List[Dict[str, Any]]:
    """
    Load and parse the IANA enterprise-numbers cache.
    """
    with open(cache_path, "r", encoding="utf-8") as f:
        text = f.read()
    entries = parse_iana_entries(text)
    if not entries:
        log_warn("No entries parsed from IANA cache (unexpected).")
    return entries


# ---------------------------------------------------------------------------
# Fuzzy matching + helpers
# ---------------------------------------------------------------------------

def slugify(name: str) -> str:
    """
    Convert to a safe filename slug: letters/numbers/underscore only.
    """
    s = name.lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "vendor"


def tokenize_name(s: str) -> List[str]:
    """
    Split a name into simple tokens (letters/digits only), lowercased.
    """
    s = s.lower()
    tokens = re.findall(r"[a-z0-9]+", s)
    return tokens


def normalize_flat_name(s: str) -> str:
    """
    Lowercase, remove non-alnum, concat.  e.g. 'Cisco Systems, Inc.' -> 'ciscosystemsinc'.
    """
    return "".join(re.findall(r"[a-z0-9]+", s.lower()))


def fuzzy_find_iana(query: str, entries: List[Dict[str, Any]]) -> List[Tuple[int, Dict[str, Any]]]:
    """
    Fuzzy match query against IANA entries.

    Returns a list of (score, entry) sorted by best score first.
    """
    q_tokens = tokenize_name(query)
    q_str = " ".join(q_tokens)
    results: List[Tuple[int, Dict[str, Any]]] = []

    for e in entries:
        name = e["name"]
        ent = e["enterprise"]
        name_tokens = tokenize_name(name)
        name_str = " ".join(name_tokens)

        score = 0

        # Exact normalized match (rare)
        if q_str == name_str:
            score += 100

        # Any token exact match (e.g. "cisco" in "ciscoSystems")
        for qt in q_tokens:
            if qt in name_tokens:
                score += 10

        # Substring match on flattened name
        if q_str and q_str in name_str:
            score += 5

        # Bonus if vendor name appears at the start
        if name_tokens and q_tokens and name_tokens[0].startswith(q_tokens[0]):
            score += 3

        if score > 0:
            results.append((score, e))

    results.sort(key=lambda x: (-x[0], x[1]["enterprise"]))
    return results


# small hint map for “preferred” entry per query
PREFERRED_VENDOR_NAMES: Dict[str, List[str]] = {
    # query_slug -> list of normalized preferred IANA names
    "cisco": [
        "ciscosystems",
        "ciscosystemsinc",
        "ciscosystemsincformerlyarchrockcorporation",
    ],
    "qnap": [
        "qnapsystemsinc",
        "qnapinc",
    ],
}


def choose_best_match(query: str, matches: List[Tuple[int, Dict[str, Any]]]) -> Dict[str, Any]:
    """
    From fuzzy matches, optionally bias to a preferred vendor canonical name.
    For example: for 'cisco' we prefer ciscoSystems (enterprise 9) over 'Cisco's Etc.'.
    """
    if not matches:
        raise ValueError("choose_best_match called with empty matches")

    q_slug = normalize_flat_name(query)
    preferred_list = PREFERRED_VENDOR_NAMES.get(q_slug)
    if not preferred_list:
        # no special preference -> best score
        return matches[0][1]

    # look for first match whose normalized name is in preferred_list
    for score, e in matches:
        n = normalize_flat_name(e["name"])
        if n in preferred_list:
            return e

    # fallback to best score
    return matches[0][1]


# ---------------------------------------------------------------------------
# Vendor profiles (extra roots, junk tables, exact names, regex)
# ---------------------------------------------------------------------------

# Default generic vendor regex if we don't have a vendor-specific one
DEFAULT_VENDOR_REGEX = (
    "("
    "disk|hdd|ssd|raid|array|lun|volume|pool|storage|"
    "psu|power|watt|volt|voltage|current|amps?|"
    "temp|temperature|thermal|fan|rpm|"
    "status|state|health|error|fail|failed|fault|alarm|alert|critical"
    ")"
)

VENDOR_PROFILES: Dict[str, Dict[str, Any]] = {
    # Keyed by a simple vendor slug (we will map canonical name/query -> slug)
    "qnap": {
        # QNAP has TWO enterprise IDs: 24681 and 55062
        "extra_include_roots": [
            ".1.3.6.1.4.1.55062",
        ],
        # Columns we always want as LLD if present
        "lld_exact_names": [
            "HdCapacity",
            "HdSmartInfo",
            "HdTemperature",
            "hrStorageDescr",
            "hrStorageSize",
            "hrStorageUsed",
            "ifAdminStatus",
            "ifHCInOctets",
            "ifHCOutOctets",
            "ifHighSpeed",
            "ifInDiscards",
            "ifInErrors",
            "ifInOctets",
            "ifOperStatus",
            "ifOutDiscards",
            "ifOutErrors",
            "ifOutOctets",
            "ifSpeed",
            "ifType",
        ],
        # Known junk tables we don't want as LLD for QNAP NAS
        "lld_exclude_roots": [
            # --- IP / routing / ARP / TCP ---
            ".1.3.6.1.2.1.4.21",         # ipRouteTable
            ".1.3.6.1.2.1.4.24",         # ipCidrRouteTable
            ".1.3.6.1.2.1.4.22",         # ipNetToMediaTable (ARP)
            ".1.3.6.1.2.1.6.13",         # tcpConnTable

            # --- Host Resources junk/directory tables ---
            ".1.3.6.1.2.1.25.3.2.1",     # hrDeviceTable
            ".1.3.6.1.2.1.25.3.7.1.1",   # hrFSIndex-like
            ".1.3.6.1.2.1.25.3.8.1",     # hrPartitionIndex-like
            ".1.3.6.1.2.1.25.4.2.1",     # hrSWRunTable
            ".1.3.6.1.2.1.25.5.1.1",     # hrSWRunPerfTable
            ".1.3.6.1.2.1.25.3.6.1",     # hrDiskStorageAccess (junk on QNAP)

            # --- Net-SNMP cache tables (no useful metrics) ---
            ".1.3.6.1.4.1.8072.1.5.3",   # nsCache* (NET-SNMP-AGENT-MIB)

            # --- QNAP NAS-MIB: directory-like trees ---
            ".1.3.6.1.4.1.24681.1.3.9.1",
            ".1.3.6.1.4.1.24681.1.4.1.1.1",
            ".1.3.6.1.4.1.24681.1.4.1.1.2",
            ".1.3.6.1.4.1.24681.1.4.1.1.3",
            ".1.3.6.1.4.1.24681.1.4.1.1.4",
            ".1.3.6.1.4.1.24681.1.4.1.1.5",
            ".1.3.6.1.4.1.24681.1.2.17.1",

            # --- QNAP 55062 junk tables ---
            ".1.3.6.1.4.1.55062.1.10.2.1",
            ".1.3.6.1.4.1.55062.1.10.3.1",
            ".1.3.6.1.4.1.55062.1.10.5.1",
            ".1.3.6.1.4.1.55062.1.10.9.1",
            ".1.3.6.1.4.1.55062.1.10.34.1",
            ".1.3.6.1.4.1.55062.1.15.1.1",
        ],
        # QNAP-specific vendor regex (storage + env + health)
        "vendor_regex": (
            "("
            # Hardware / platform
            "model|system|hardware|"
            "chassis|board|"
            # CPU / load
            "cpu|processor|load|usage|util|"
            # Memory
            "mem|memory|ram|swap|"
            # Storage
            "disk|hdd|ssd|raid|array|lun|volume|pool|storage|"
            # Power / PSU
            "psu|ps|power|watt|volt|voltage|current|amps?|"
            # Networking
            "net|nic|link|throughput|bandwidth|speed|"
            # Environmental
            "temp|temperature|thermal|fan|rpm|humidity|"
            # Health / status
            "error|errors|fail|failed|fault|"
            "status|state|health|ok|"
            "alarm|alert|warning|critical|"
            # UPS / battery
            "ups|battery|runtime|charge|capacity"
            ")"
        ),
    },

    # Placeholder for Cisco – for now we just make sure we pick the right
    # enterprise (9), and you can extend this profile later if you like.
    "cisco": {
        "extra_include_roots": [],
        "lld_exact_names": [],
        "lld_exclude_roots": [],
        "vendor_regex": DEFAULT_VENDOR_REGEX,
    },
}


def detect_vendor_slug(query: str, canonical_name: str) -> str | None:
    """
    Very simple classifier to map a combination of user query + canonical IANA
    name to a vendor slug we have a profile for, e.g. "qnap" or "cisco".
    """
    q_tokens = set(tokenize_name(query))
    c_tokens = set(tokenize_name(canonical_name))

    all_tokens = q_tokens | c_tokens

    if "qnap" in all_tokens:
        return "qnap"
    if "cisco" in all_tokens:
        return "cisco"

    return None


# ---------------------------------------------------------------------------
# Filter YAML generator
# ---------------------------------------------------------------------------

def generate_vendor_filter_yaml(ent: int, canonical: str, vendor_slug: str | None) -> str:
    """
    Generate a *small* vendor filter extension that extends filters.yaml.

    We only specify:
      - lld.include_roots -> add the vendor enterprise root (+ any extras)
      - lld.exact_names   -> optional list of column names to always LLD
      - lld.exclude_roots -> vendor-specific junk
      - vendor.regex      -> vendor-specific or generic regex

    The merging is done by auto_oid_finder.py via merge_filter_cfg().
    """
    root = f".1.3.6.1.4.1.{ent}"

    profile = VENDOR_PROFILES.get(vendor_slug, {}) if vendor_slug else {}

    include_roots = [root] + profile.get("extra_include_roots", [])
    exact_names = profile.get("lld_exact_names", [])
    exclude_roots = profile.get("lld_exclude_roots", [])
    vendor_regex = profile.get("vendor_regex", DEFAULT_VENDOR_REGEX)

    # YAML generation – we keep it minimal and let filters.yaml do the rest
    yaml = [
        "Version: 1.0",
        "",
        f"# Vendor: {canonical}",
        f"# Enterprise ID: {ent}",
        f"# Vendor OID root: {root}",
        "",
        "# This file extends filters.yaml. Only vendor-specific parts need to be included.",
        "",
        "lld:",
        "  include_roots:",
    ]
    for r in include_roots:
        yaml.append(f'    - "{r}"')

    yaml.append("")
    yaml.append("  # Vendor-specific exact names (auto LLD favourites)")
    yaml.append("  exact_names:")
    if exact_names:
        for name in exact_names:
            yaml.append(f"    - {name}")
    else:
        yaml.append("    []")

    yaml.append("")
    yaml.append("  # Vendor-specific junk tables to exclude from LLD")
    yaml.append("  exclude_roots:")
    if exclude_roots:
        for r in exclude_roots:
            yaml.append(f'    - "{r}"')
    else:
        yaml.append("    []")

    yaml.append("")
    yaml.append("vendor:")
    yaml.append("  # Vendor-specific regex (can be extended in filters.yaml)")
    yaml.append(f'  regex: "{vendor_regex}"')

    return "\n".join(yaml).rstrip() + "\n"


def write_filter_file(
    canonical: str,
    ent: int,
    filters_dir: str,
    vendor_slug: str | None,
    force: bool = False,
) -> str:
    """
    Generate filters/filters-<slug>.yml for the given vendor.
    Returns the path to the written file.
    """
    os.makedirs(filters_dir, exist_ok=True)

    slug = slugify(canonical)
    filename = f"filters-{slug}.yml"
    path = os.path.join(filters_dir, filename)

    if os.path.exists(path) and not force:
        log_warn(f"Filter file already exists: {path}")
        print("       Use --force to overwrite.")
        return path

    content = generate_vendor_filter_yaml(ent, canonical, vendor_slug)

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
            "Map vendor name to IANA enterprise ID and optionally generate "
            "a filters/filters-<vendor>.yml file."
        )
    )
    parser.add_argument(
        "vendor_name",
        nargs="*",
        help="Vendor name (e.g. 'cisco', 'qnap', 'hpe nimble')",
    )
    parser.add_argument(
        "--write-filter",
        action="store_true",
        help="Generate a filters/filters-<vendor>.yml file for the best match.",
    )
    parser.add_argument(
        "--filters-dir",
        default="filters",
        help="Directory where filter files are stored (default: filters).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing filter file if it already exists.",
    )
    parser.add_argument(
        "--enterprise",
        type=int,
        help="Enterprise ID to use directly (bypass IANA search).",
    )
    parser.add_argument(
        "--name",
        help="Canonical vendor name to use with --enterprise.",
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

    # 1) Direct enterprise override path
    if args.enterprise is not None:
        if not args.name:
            log_error("When using --enterprise, you must also provide --name.")
            sys.exit(1)

        ent = args.enterprise
        canonical = args.name.strip()
        root = f".1.3.6.1.4.1.{ent}"

        vendor_slug = detect_vendor_slug("", canonical)

        print(f"Enterprise (forced): {ent}")
        print(f"Canonical name:     {canonical}")
        print(f"OID root:           {root}")
        print(f"Vendor profile:     {vendor_slug or 'generic'}")

        print()
        print("Suggested LLD include:")
        print(f'  - "{root}"')

        if args.write_filter:
            print()
            write_filter_file(canonical, ent, args.filters_dir, vendor_slug, force=args.force)

        sys.exit(0)

    # 2) Normal path: fuzzy match via IANA
    if not args.vendor_name:
        log_error("Either vendor_name or --enterprise/--name must be provided.")
        sys.exit(1)

    query = " ".join(args.vendor_name).strip()
    cache_path = ensure_iana_cache(DEFAULT_CACHE_PATH)
    if not cache_path:
        log_error("No IANA data available.")
        sys.exit(1)

    entries = load_iana_entries(cache_path)
    matches = fuzzy_find_iana(query, entries)
    if not matches:
        print(f"No matches found for: {query!r}")
        print("Check the IANA list manually:")
        print("  https://www.iana.org/assignments/enterprise-numbers/")
        sys.exit(1)

    best = choose_best_match(query, matches)
    ent = best["enterprise"]
    canonical = best["name"]
    root = f".1.3.6.1.4.1.{ent}"

    vendor_slug = detect_vendor_slug(query, canonical)

    print(f"Best match:   {canonical}")
    print(f"Enterprise:   {ent}")
    print(f"OID root:     {root}")
    print(f"Raw entry:    {canonical}")
    print(f"Vendor profile: {vendor_slug or 'generic'}")

    print()
    print("Suggested LLD include:")
    print(f'  - "{root}"')
    if vendor_slug == "qnap":
        # hint that we also include 55062 in the filter file
        print("  (filter file will also include .1.3.6.1.4.1.55062 for QNAP)")

    slug = slugify(canonical)
    filter_file = f"filters-{slug}.yml"
    print()
    print("Suggested filter filename:")
    print(f"  {args.filters_dir}/{filter_file}")

    if args.write_filter:
        print()
        write_filter_file(canonical, ent, args.filters_dir, vendor_slug, force=args.force)


if __name__ == "__main__":
    main()

