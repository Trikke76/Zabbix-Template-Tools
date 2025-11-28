#!/usr/bin/env python3
"""
vendor2enterprise.py
====================

Version: 1.0.6

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
import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
from glob import glob
import urllib.request

IANA_CACHE_PATH = "data/iana_enterprise_numbers.txt"
IANA_ENTERPRISE_URL = (
    "https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers"
)

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

def download_iana_cache(path: str) -> bool:
    """
    Try to download the IANA enterprise-numbers file and save it to `path`.

    Returns True on success, False on failure.
    """
    try:
        print(f"[info] Downloading IANA enterprise list from:")
        print(f"       {IANA_ENTERPRISE_URL}")

        # Ensure directory exists (e.g. data/)
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        with urllib.request.urlopen(IANA_ENTERPRISE_URL, timeout=20) as resp:
            content = resp.read().decode("utf-8", errors="replace")

        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"[info] Saved IANA cache to: {path}")
        return True
    except Exception as e:
        print(f"[error] Failed to download IANA enterprise list: {e}")
        return False


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

    # Generieke "oninteressante" woorden in vendor-namen
    STOPWORDS = {
        "inc", "inc.", "ltd", "ltd.", "corp", "corp.",
        "co", "co.", "company", "companies",
        "systems", "system",
        "technologies", "technology", "tech",
        "international", "intl", "global",
        "group", "holding", "holdings",
        "sa", "ag", "gmbh", "sarl", "bv", "nv",
    }

    # Tokenizer helper
    def tokenize(s: str) -> set[str]:
        tokens = re.split(r"[^a-z0-9]+", s.lower())
        return {
            t for t in tokens
            if t and len(t) >= 3 and t not in STOPWORDS
        }

    q_tokens = tokenize(q)

    for e in entries:
        name = e.name.lower()
        score = 0

        # Sterkste signalen eerst
        if q == name:
            score = 4
        elif q in name:
            score = 3
        elif name in q:
            score = 2
        else:
            # Zwakke maar nuttige match: token-overlap (zonder stopwoorden)
            name_tokens = tokenize(name)
            if q_tokens and name_tokens:
                if q_tokens & name_tokens:
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
def classify_symbol_case(name: str) -> str:
    """
    Classify SNMP symbol names by typical MIB naming conventions.
    """
    if name.isupper():
        return "ALLCAPS"       # usually enums or constants → low value
    if "_" in name:
        return "SNAKE"         # often internal, sometimes useful → medium
    if re.match(r"^[a-z]+[A-Z][A-Za-z0-9]*$", name):
        return "CAMEL"         # classic table/column names → highest value
    return "OTHER"


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
    json_str = json.dumps(vendor_regex)
    lines.append("\nvendor:\n")
    lines.append("  # Vendor-specific regex (can be extended in filters.yaml)\n")
    lines.append(f"  regex: {json_str}\n")

    return "".join(lines)

def generate_generic_filter_yaml(
    ent: int,
    name: str,
    vendor_regex: Optional[str] = None,
) -> str:
    """
    Very generic vendor extension: just include the vendor root and
    a broad hardware/health regex.

    If vendor_regex is provided (e.g. built from MIBs), use that; otherwise
    fall back to GENERIC_VENDOR_REGEX.
    """
    root = enterprise_root(ent)
    regex = vendor_regex or GENERIC_VENDOR_REGEX

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
        f"  regex: \"{regex}\"\n"
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

def collect_mib_paths(mib_files: List[str], mib_dirs: List[str]) -> List[str]:
    """
    Resolve a combined list of MIB files from explicit --mib and --mib-dir
    arguments. Directories are scanned for case-insensitive *.mib and *.txt
    files (e.g. QNAP-NAS-MIB.MIB will be picked up).

    Returns a de-duplicated list of file paths.
    """
    paths: List[str] = []

    # Explicit files
    for p in mib_files:
        if not p:
            continue
        candidate = Path(p)
        if candidate.is_file():
            paths.append(str(candidate))
        else:
            print(f"[warn] MIB file not found: {p}")

    # Directories
    for d in mib_dirs:
        if not d:
            continue
        base = Path(d)
        if not base.is_dir():
            print(f"[warn] MIB dir not found: {d}")
            continue

        # Case-insensitive patterns for .mib / .txt
        for pattern in ("*.mib", "*.MIB", "*.txt", "*.TXT"):
            for f in base.glob(pattern):
                if f.is_file():
                    paths.append(str(f))

    # De-duplicate while preserving order
    seen: set[str] = set()
    uniq: List[str] = []
    for p in paths:
        if p in seen:
            continue
        seen.add(p)
        uniq.append(p)

    return uniq

def extract_mib_symbols(mib_paths: List[str]) -> Set[str]:
    """
    Very lightweight MIB "parser": we just scan for lines that look like

        someObjectName   OBJECT-TYPE

    and collect 'someObjectName' as a symbol.

    This is intentionally simple and robust: we don't depend on pysmi
    here, just text scanning.
    """
    symbols: Set[str] = set()
    for path in mib_paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"[warn] Failed to read MIB {path}: {e}")
            continue

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("--"):
                continue
            # crude: look for 'NAME OBJECT-TYPE'
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9_-]*)\s+OBJECT-TYPE\b", line)
            if m:
                symbols.add(m.group(1))

    return symbols


def build_vendor_regex_from_symbols(symbols: Set[str]) -> Optional[str]:
    """
    Build a vendor.regex string from a set of MIB symbol names.

    Strategy:
      - Start with a generic core of useful words.
      - Add symbol names that look interesting.
      - Keep it bounded so the regex doesn't explode.

    Returns a '(a|b|c)' style regex string, or None if nothing usable.
    """
    if not symbols:
        return None

    # Generic base words we always like to have
    generic_words = [
        "disk", "hdd", "ssd", "raid", "array", "lun", "volume", "pool",
        "storage", "psu", "power", "watt", "volt", "voltage", "current",
        "amp", "amps", "temp", "temperature", "thermal", "fan", "rpm",
        "status", "state", "health", "error", "fail", "failed", "fault",
        "alarm", "alert", "critical", "cpu", "mem", "memory", "cache",
        "latency", "iops"
    ]

    # Heuristic scoring: prefer symbols containing these fragments
    interesting_fragments = [
        "disk", "vol", "volume", "snap", "raid", "array", "pool",
        "fan", "temp", "temperature", "sensor", "psu", "power",
        "latency", "iops", "cache", "health", "status", "error"
    ]

    scored: list[tuple[int, str]] = []

    for sym in symbols:
        name = sym.strip()
        if not name:
            continue
        if len(name) > 50:
            continue

        lname = name.lower()

        score = 0

        # fragment scoring
        for frag in interesting_fragments:
            if frag in lname:
                score += 2

        # short names are often good table names
        if len(name) <= 12:
            score += 1

        # NEW: Case classification weight
        case = classify_symbol_case(name)
        if case == "CAMEL":
            score += 5
        elif case == "SNAKE":
            score += 2
        elif case == "ALLCAPS":
            score -= 3   # enums/constants → suppress
        # OTHER = neutral

        scored.append((score, name))

    scored.sort(key=lambda x: (-x[0], x[1].lower()))

    TOP_N = 80
    selected_symbols = [name for score, name in scored[:TOP_N] if score > 0]

    if not selected_symbols:
        selected_symbols = [name for score, name in scored[:20]]

    parts = set(generic_words)
    parts.update(selected_symbols)

    parts_sorted = sorted(parts)

    # escape regex parts
    safe_parts = [re.escape(p) for p in parts_sorted]

    return "(" + "|".join(safe_parts) + ")"

def write_filter_file(
    vendor_name: str,
    ent: int,
    vendor_profile: Optional[VendorProfile],
    filters_dir: str,
    force: bool,
    vendor_regex: Optional[str] = None,
) -> str:
    """
    Write the vendor filter file.

    - If vendor_profile is present, we optionally override its vendor_regex
      with the MIB-derived vendor_regex (if provided).
    - If no profile, we pass vendor_regex directly into the generic generator.
    """
    os.makedirs(filters_dir, exist_ok=True)

    if vendor_profile:
        # If we built a regex from MIBs, inject it into the profile
        if vendor_regex is not None:
            vendor_profile.vendor_regex = vendor_regex

        content = generate_profile_filter_yaml(vendor_profile)
        slug = vendor_profile.key
        filename = f"filters-{slug}.yml"
    else:
        content = generate_generic_filter_yaml(ent, vendor_name, vendor_regex=vendor_regex)
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
        "--mib",
        action="append",
        default=[],
        help="MIB file to mine for vendor-specific keywords (can be repeated)"
    )
    parser.add_argument(
        "--mib-dir",
        action="append",
        default=[],
        help="Directory containing MIB files (*.mib, *.txt) to mine for vendor-specific keywords (can be repeated)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing filter file if it already exists.",
    )

    args = parser.parse_args()
    query = " ".join(args.vendor_name).strip()

    # Load IANA cache (auto-download if missing/empty)
    lines = load_iana_cache(IANA_CACHE_PATH)
    if not lines:
        print(f"[warn] No IANA cache found or file is empty: {IANA_CACHE_PATH}")
        print("       Attempting to download enterprise-numbers from IANA...")
        if download_iana_cache(IANA_CACHE_PATH):
            lines = load_iana_cache(IANA_CACHE_PATH)

    if not lines:
        print(f"[error] Unable to load IANA enterprise list.")
        print(f"        Tried: {IANA_CACHE_PATH}")
        print("        You can also download it manually from:")
        print("          https://www.iana.org/assignments/enterprise-numbers/")
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

    # ------------------------------------------------------------------
    # Optional: mine MIBs for vendor-specific symbols to build vendor.regex
    # ------------------------------------------------------------------
    mib_paths = collect_mib_paths(args.mib, args.mib_dir)
    vendor_regex: Optional[str] = None

    if mib_paths:
        print("[info] Mining MIBs for vendor-specific keywords:")
        for p in mib_paths:
            print(f"       - {p}")

        symbols = extract_mib_symbols(mib_paths)
        if symbols:
            print(f"[info] Found {len(symbols)} MIB symbols")
            vr = build_vendor_regex_from_symbols(symbols)
            if vr:
                vendor_regex = vr
                print(f"[info] Built vendor.regex from MIBs (length {len(vr)})")
            else:
                print("[warn] No useful regex built from MIBs; using generic vendor.regex")
        else:
            print("[warn] No symbols found in MIBs; using generic vendor.regex")
    else:
        print("[info] No MIBs provided; using generic vendor.regex")

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
            vendor_regex=vendor_regex,
        )


if __name__ == "__main__":
    main()

