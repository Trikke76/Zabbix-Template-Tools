#!/usr/bin/env python3
"""
vendor2enterprise.py
====================

Version: 1.0.3

Helper tool to map vendor names to IANA enterprise numbers and optionally
generate a filters/filters-<vendor>.yml file suitable for auto_oid_finder.py.

Data source for enterprise numbers:
    https://www.iana.org/assignments/enterprise-numbers/

Features:
  - Uses a local cache file: data/iana_enterprise_numbers.txt
    (downloadable from the IANA page).
  - Normal fuzzy matching on IANA entries, BUT:
      * For certain vendors (nimble, qnap, cisco) we have
        hard-coded "profiles" that win over fuzzy IANA hits.
  - Prints enterprise ID and .1.3.6.1.4.1.<enterprise> root.
  - With --write-filter, generates a filter YAML in filters/ that
    extends the generic filters.yaml (only vendor bits).
"""

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

IANA_CACHE_PATH = "data/iana_enterprise_numbers.txt"

# ---------------------------------------------------------------------------
# Vendor profiles (override IANA behaviour for some vendors)
# ---------------------------------------------------------------------------

@dataclass
class VendorProfile:
    key: str                 # internal key, e.g. "qnap"
    display_name: str        # human name
    enterprise: int          # primary enterprise ID
    extra_enterprises: List[int] = field(default_factory=list)
    # LLD tuning
    lld_exact_names: List[str] = field(default_factory=list)
    lld_include_suffixes: List[str] = field(default_factory=list)  # appended to each vendor root
    lld_exclude_roots: List[str] = field(default_factory=list)
    # Vendor regex tweak
    vendor_regex: Optional[str] = None


PROFILES: Dict[str, VendorProfile] = {
    # HPE Nimble Storage
    "nimble": VendorProfile(
        key="nimble",
        display_name="HPE Nimble Storage",
        enterprise=37447,
        extra_enterprises=[],
        lld_exact_names=[
            "volName",
            "volSizeLow",
            "volSizeHigh",
            "volUsageLow",
            "volUsageHigh",
            "volReserveLow",
            "volReserveHigh",
            "volOnline",
            "volNumConnections",
        ],
        lld_include_suffixes=[
            ".1",   # nimble::variables (volTable + others)
        ],
        lld_exclude_roots=[
            # can be filled later with junk tables if needed
        ],
        vendor_regex=None,  # use generic storage-ish regex
    ),

    # QNAP NAS
    "qnap": VendorProfile(
        key="qnap",
        display_name="QNAP SYSTEMS, INC",
        enterprise=24681,
        extra_enterprises=[55062],   # second QNAP enterprise
        lld_exact_names=[
            "HdSmartInfo",
            "HdCapacity",
            "HdTemperature",
        ],
        lld_include_suffixes=[
            "",          # .1.3.6.1.4.1.<ent> root
        ],
        lld_exclude_roots=[
            # QNAP NAS-MIB junk / directory tables
            ".1.3.6.1.4.1.24681.1.3.9.1",
            ".1.3.6.1.4.1.24681.1.4.1.1.1",
            ".1.3.6.1.4.1.24681.1.4.1.1.2",
            ".1.3.6.1.4.1.24681.1.4.1.1.3",
            ".1.3.6.1.4.1.24681.1.4.1.1.4",
            ".1.3.6.1.4.1.24681.1.4.1.1.5",
            ".1.3.6.1.4.1.24681.1.2.17.1",
            # QNAP 55062 junk tables
            ".1.3.6.1.4.1.55062.1.10.5.1",
            ".1.3.6.1.4.1.55062.1.10.9.1",
            ".1.3.6.1.4.1.55062.1.10.34.1",
            ".1.3.6.1.4.1.55062.1.15.1.1",
            ".1.3.6.1.4.1.55062.1.10.2.1",
            ".1.3.6.1.4.1.55062.1.10.3.1",
        ],
        vendor_regex=None,  # generic storage regex is fine
    ),

    # Cisco – prefer the classic SNMP enterprise 9
    "cisco": VendorProfile(
        key="cisco",
        display_name="ciscoSystems",
        enterprise=9,
        extra_enterprises=[],
        lld_exact_names=[],
        lld_include_suffixes=[
            "",  # base .1.3.6.1.4.1.9
        ],
        lld_exclude_roots=[
            # You can extend this later with specific junk tables,
            # for now keep it empty.
        ],
        vendor_regex=(
            "(disk|hdd|ssd|raid|array|lun|volume|pool|storage|"
            "psu|power|watt|volt|voltage|current|amps?|"
            "temp|temperature|thermal|fan|rpm|"
            "status|state|health|error|fail|failed|fault|alarm|alert|critical)"
        ),
    ),
}


# ---------------------------------------------------------------------------
# IANA parsing / lookup
# ---------------------------------------------------------------------------

def load_iana_cache(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return f.read().splitlines()


@dataclass
class IanaEntry:
    enterprise: int
    name: str
    raw_lines: List[str]


def parse_iana_entries(lines: List[str]) -> List[IanaEntry]:
    """
    Very small parser:
      - An entry starts with "<number> <name>"
      - All following indented lines belong to that entry
    """
    entries: List[IanaEntry] = []
    current: Optional[IanaEntry] = None

    header_re = re.compile(r"^\s*(\d+)\s+(.+?)\s*$")

    for line in lines:
        m = header_re.match(line)
        if m:
            # start new entry
            if current:
                entries.append(current)
            ent = int(m.group(1))
            name = m.group(2).strip()
            current = IanaEntry(enterprise=ent, name=name, raw_lines=[line])
        else:
            if current:
                current.raw_lines.append(line)

    if current:
        entries.append(current)

    return entries


def find_iana_matches(entries: List[IanaEntry], query: str) -> List[IanaEntry]:
    q = query.lower().strip()
    scored: List[tuple[int, IanaEntry]] = []
    for e in entries:
        name = e.name.lower()
        score = 0
        if q == name:
            score = 4
        elif q in name:
            score = 3
        elif name in q:
            score = 2
        # very weak signal: word overlap
        elif any(tok and tok in name for tok in q.split()):
            score = 1

        if score > 0:
            scored.append((score, e))

    scored.sort(key=lambda x: (-x[0], x[1].enterprise))
    return [x[1] for x in scored]


def find_iana_by_enterprise(entries: List[IanaEntry], ent: int) -> Optional[IanaEntry]:
    for e in entries:
        if e.enterprise == ent:
            return e
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def slugify(name: str) -> str:
    s = name.lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "vendor"


def enterprise_root(ent: int) -> str:
    return f".1.3.6.1.4.1.{ent}"


# ---------------------------------------------------------------------------
# Filter YAML generators
# ---------------------------------------------------------------------------

GENERIC_VENDOR_REGEX = (
    "(disk|hdd|ssd|raid|array|lun|volume|pool|storage|"
    "psu|power|watt|volt|voltage|current|amps?|"
    "temp|temperature|thermal|fan|rpm|"
    "status|state|health|error|fail|failed|fault|alarm|alert|critical)"
)

def generate_profile_filter_yaml(profile: VendorProfile) -> str:
    """
    Generate a vendor filter that EXTENDS filters.yaml and focuses
    only on vendor-specific bits (lld + vendor regex).
    """
    roots: List[str] = []

    def add_roots_for_ent(ent: int):
        base = enterprise_root(ent)
        if not profile.lld_include_suffixes:
            roots.append(base)
        else:
            for suf in profile.lld_include_suffixes:
                roots.append(base + suf)

    # Primary enterprise
    add_roots_for_ent(profile.enterprise)
    # Extra enterprises
    for ent in profile.extra_enterprises:
        add_roots_for_ent(ent)

    # Dedup roots
    roots = sorted(set(roots))

    # Build YAML blocks
    lines: List[str] = []
    lines.append(f"Version: 1.0-{profile.key}\n")
    lines.append(f"# EXTENSION of filters.yaml for {profile.display_name}\n")
    lines.append("# This file only overrides vendor-specific parts.\n\n")

    # lld.include_roots
    lines.append("lld:\n")
    lines.append("  include_roots:\n")
    for r in roots:
        lines.append(f'    - "{r}"\n')

    # lld.exact_names
    if profile.lld_exact_names:
        lines.append("  exact_names:\n")
        for name in profile.lld_exact_names:
            lines.append(f"    - {name}\n")
    else:
        lines.append("  exact_names: []\n")

    # lld.exclude_roots
    if profile.lld_exclude_roots:
        lines.append("  exclude_roots:\n")
        for er in profile.lld_exclude_roots:
            lines.append(f'    - "{er}"\n')
    else:
        lines.append("  exclude_roots: []\n")

    # vendor.regex
    vendor_regex = profile.vendor_regex or GENERIC_VENDOR_REGEX
    lines.append("\nvendor:\n")
    lines.append("  # Vendor-specific regex (can be extended in filters.yaml)\n")
    lines.append(f'  regex: "{vendor_regex}"\n')

    return "".join(lines)


def generate_generic_filter_yaml(ent: int, name: str) -> str:
    """
    Very generic vendor extension: just include the vendor root and
    a broad hardware/health regex.
    """
    root = enterprise_root(ent)
    return (
        "Version: 1.0\n\n"
        f"# Vendor: {name}\n"
        f"# Enterprise ID: {ent}\n"
        f"# Vendor OID root: {root}\n\n"
        "# This file extends filters.yaml. Only vendor-specific parts need to be included.\n\n"
        "lld:\n"
        "  include_roots:\n"
        f"    - \"{root}\"\n\n"
        "  # Vendor-specific exact names (auto LLD favourites)\n"
        "  exact_names:\n"
        "    []\n\n"
        "  # Vendor-specific junk tables to exclude from LLD\n"
        "  exclude_roots:\n"
        "    []\n\n"
        "vendor:\n"
        "  # Vendor-specific regex (can be extended in filters.yaml)\n"
        f"  regex: \"{GENERIC_VENDOR_REGEX}\"\n"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def choose_profile(query: str) -> Optional[VendorProfile]:
    q = query.lower()
    if "nimble" in q:
        return PROFILES["nimble"]
    if "qnap" in q:
        return PROFILES["qnap"]
    if "cisco" in q:
        return PROFILES["cisco"]
    return None


def write_filter_file(
    vendor_name: str,
    ent: int,
    vendor_profile: Optional[VendorProfile],
    filters_dir: str,
    force: bool,
) -> str:
    os.makedirs(filters_dir, exist_ok=True)

    if vendor_profile:
        content = generate_profile_filter_yaml(vendor_profile)
        slug = vendor_profile.key
        filename = f"filters-{slug}.yml"
    else:
        content = generate_generic_filter_yaml(ent, vendor_name)
        slug = slugify(vendor_name)
        filename = f"filters-{slug}.yml"

    path = os.path.join(filters_dir, filename)
    if os.path.exists(path) and not force:
        print(f"[warn] Filter file already exists: {path}")
        print("       Use --force to overwrite.")
        return path

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"[info] Wrote vendor filter: {path}")
    return path


def main():
    parser = argparse.ArgumentParser(
        description="Map vendor name to enterprise ID and optionally generate a filters/*.yml file."
    )
    parser.add_argument(
        "vendor_name",
        nargs="+",
        help="Vendor name (e.g. 'nimble', 'qnap', 'cisco', 'hpe nimble')",
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

    args = parser.parse_args()
    query = " ".join(args.vendor_name).strip()

    # Load IANA cache
    lines = load_iana_cache(IANA_CACHE_PATH)
    if not lines:
        print(f"[error] No IANA cache found at: {IANA_CACHE_PATH}")
        print("        Download enterprise-numbers from IANA and store it there.")
        sys.exit(1)

    print(f"[info] Using existing IANA cache: {IANA_CACHE_PATH}")
    entries = parse_iana_entries(lines)

    # Check if a vendor profile should override
    profile = choose_profile(query)

    if profile:
        # For profile vendors, we trust the hard-coded enterprise ID
        ent = profile.enterprise
        root = enterprise_root(ent)
        iana_entry = find_iana_by_enterprise(entries, ent)
        print(f"Best match:   {profile.display_name}")
        print(f"Enterprise:   {ent}")
        print(f"OID root:     {root}")
        if iana_entry:
            print(f"Raw entry:    {iana_entry.name}")
        else:
            print("Raw entry:    <not found in IANA cache>")

        print(f"Vendor profile: {profile.key}")
    else:
        # Generic path – fuzzy match from IANA
        matches = find_iana_matches(entries, query)
        if not matches:
            print(f"No matches found for: {query!r}")
            print("Check the IANA list manually:")
            print("  https://www.iana.org/assignments/enterprise-numbers/")
            sys.exit(1)

        best = matches[0]
        ent = best.enterprise
        root = enterprise_root(ent)
        print(f"Best match:   {best.name}")
        print(f"Enterprise:   {ent}")
        print(f"OID root:     {root}")
        print(f"Raw entry:    {best.name}")

    print()
    print("Suggested LLD include:")
    print(f'  - "{enterprise_root(ent)}"')
    if profile and profile.extra_enterprises:
        for e in profile.extra_enterprises:
            print(f'  - "{enterprise_root(e)}"')

    print()
    slug = profile.key if profile else slugify(query)
    filter_file = f"filters-{slug}.yml"
    print("Suggested filter filename:")
    print(f"  {args.filters_dir}/{filter_file}")

    if args.write_filter:
        print()
        write_filter_file(
            vendor_name=(profile.display_name if profile else query),
            ent=ent,
            vendor_profile=profile,
            filters_dir=args.filters_dir,
            force=args.force,
        )


if __name__ == "__main__":
    main()

