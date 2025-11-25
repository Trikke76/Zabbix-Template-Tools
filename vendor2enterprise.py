#!/usr/bin/env python3
"""
vendor2enterprise.py

Helper tool to map vendor names to IANA enterprise numbers and optionally
generate a filters/filters_<vendor>.yaml file suitable for auto_oid_finder.py.

Data source for enterprise numbers:
    https://www.iana.org/assignments/enterprise-numbers/

Features:
  - Fuzzy matching on vendor name (e.g. "nimble", "hpe nimble", "qnap").
  - Prints enterprise ID and .1.3.6.1.4.1.<enterprise> root.
  - With --write-filter, generates a filter YAML in filters/.
    * For Nimble Storage, writes a storage-optimized filter.
    * For other vendors, writes a generic boilerplate filter.
"""

import argparse
import os
import re
import sys
import textwrap
from typing import List, Dict, Any

# ---------------------------------------------------------------------------
# Vendor catalog
# ---------------------------------------------------------------------------

VENDORS: List[Dict[str, Any]] = [
    {
        "canonical": "QNAP (24681)",
        "enterprise": 24681,
        "aliases": ["qnap", "qnap 24681", "qnap nas"],
        "notes": "Classic QNAP NAS-MIB",
        "category": "storage",
    },
    {
        "canonical": "QNAP (55062)",
        "enterprise": 55062,
        "aliases": ["qnap 55062", "qnap qts", "qnap qts5"],
        "notes": "Newer QNAP QTS enterprise",
        "category": "storage",
    },
    {
        "canonical": "Nimble Storage",
        "enterprise": 37447,
        "aliases": ["nimble", "nimble storage", "hpe nimble"],
        "notes": "HPE Nimble Storage arrays",
        "category": "storage",
    },
    # You can add more vendors here:
    # {
    #     "canonical": "Cisco Systems",
    #     "enterprise": 9,
    #     "aliases": ["cisco"],
    #     "notes": "Cisco routers/switches",
    #     "category": "network",
    # },
]


# ---------------------------------------------------------------------------
# Fuzzy matching logic
# ---------------------------------------------------------------------------

def find_matches(query: str) -> List[Dict[str, Any]]:
    q = query.lower().strip()
    matches: List[tuple[int, Dict[str, Any]]] = []

    for v in VENDORS:
        all_names = [v["canonical"]] + v.get("aliases", [])
        score = 0

        for name in all_names:
            n = name.lower()
            if q == n:
                score = max(score, 3)
            elif q in n:
                score = max(score, 2)
            elif n in q:
                score = max(score, 1)

        if score > 0:
            matches.append((score, v))

    matches.sort(key=lambda x: (-x[0], x[1]["canonical"].lower()))
    return [m[1] for m in matches]


def slugify(name: str) -> str:
    # Convert to a safe filename slug: letters/numbers/underscore only.
    s = name.lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "vendor"


# ---------------------------------------------------------------------------
# Filter file content generators
# ---------------------------------------------------------------------------

def generate_nimble_filter_yaml(ent: int) -> str:
    """
    Generate a Nimble-specific filter YAML content
    based on your generic filters + storage tweaks.
    """
    root = f".1.3.6.1.4.1.{ent}"
    return textwrap.dedent(
        f"""\
        Version: 1.0

        # ---------------------------------------------------------------------------
        # Enterprise OIDs reference:
        # Official registry of all vendor enterprise numbers:
        # https://www.iana.org/assignments/enterprise-numbers/
        #
        # Nimble Storage enterprise ID:
        #   {ent}  =>  {root}
        #
        # Use this OID in lld.include_roots to walk Nimble's vendor subtree.
        # ---------------------------------------------------------------------------

        # ---------------------------------------------------------------------------
        # MIB-2 scalar filter:
        #   - generic, useful metrics for any SNMP device
        #   - system identity, CPU/memory, uptime, basic interface info
        # ---------------------------------------------------------------------------
        mib2:
          regex: >
            (
              # ---------- System Identification ----------
              sysDescr|sysObjectID|sysName|sysLocation|sysContact|
              contact|description|location|name|objectid|
              vendor|manufacturer|model|hardware|system|

              # ---------- CPU / Memory / Uptime ----------
              cpu|processor|
              mem|memory|hrMemorySize|
              sysUpTime|

              # ---------- Host Resources ----------
              hrProcessorLoad|
              hrStorageUsed|hrStorageSize|hrStorageDescr|

              # ---------- Interfaces (selected scalars only) ----------
              ifNumber|
              ifAdminStatus|ifOperStatus|
              ifSpeed|ifHighSpeed
            )

        # ---------------------------------------------------------------------------
        # Vendor scalar filter (Nimble / generic storage):
        #   - broader match for enterprise/vendor trees (.1.3.6.1.4.1.*)
        #   - resource usage, hardware state, temperatures, fans, power, disks, etc.
        # ---------------------------------------------------------------------------
        vendor:
          regex: >
            (
              # Hardware / platform
              model|system|hardware|
              chassis|board|

              # CPU / load
              cpu|processor|load|usage|util|

              # Memory
              mem|memory|ram|swap|cache|

              # Storage
              disk|hdd|ssd|raid|array|lun|volume|pool|storage|

              # Power / PSU
              psu|ps|power|watt|volt|voltage|current|amps|

              # Networking
              net|nic|link|throughput|bandwidth|speed|

              # Environmental
              temp|temperature|thermal|
              fan|rpm|
              humidity|

              # Health / status
              error|errors|fail|failed|fault|
              status|state|health|ok|
              alarm|alert|warning|critical|

              # UPS / battery (if present on platform)
              ups|battery|runtime|charge
            )

        # ---------------------------------------------------------------------------
        # LLD table filter:
        #   - which tables are interesting enough to become LLD
        #   - works on standard MIB-2 ifTable/ifXTable and Nimble/vendor tables
        # ---------------------------------------------------------------------------
        lld:
          regex: >
            (
              # Interface traffic + errors
              ifHCInOctets|ifHCOutOctets|
              ifInOctets|ifOutOctets|
              ifInDiscards|ifOutDiscards|
              ifInErrors|ifOutErrors|
              ifHighSpeed|ifSpeed|
              ifOperStatus|ifAdminStatus|
              ifType|

              # Storage-related tables (volumes, pools, disks)
              hrStorageUsed|hrStorageSize|hrStorageDescr|
              volume|volTable|pool|lun|disk|

              # Environmental / sensors
              temperature|temp|
              voltage|volt|
              fan|rpm|
              Status
            )

          # -------------------------------------------------------------------------
          # Tables we ALWAYS want to consider for LLD (if present)
          # -------------------------------------------------------------------------
          include_roots:
            # Standard MIB-2 interfaces
            - ".1.3.6.1.2.1.2.2"        # ifTable
            - ".1.3.6.1.2.1.31.1.1"     # ifXTable

            # Nimble Storage vendor subtree
            - "{root}"                  # Nimble Storage enterprise root

          # -------------------------------------------------------------------------
          # Tables we ALMOST NEVER want as LLD on ANY device:
          #   - routing tables
          #   - ARP
          #   - TCP connection tables
          #   - HR-MIB device / process directories
          #   - Net-SNMP cache tables
          # -------------------------------------------------------------------------
          exclude_roots:
            # --- IP / routing / ARP ---
            - ".1.3.6.1.2.1.4.21"           # ipRouteTable
            - ".1.3.6.1.2.1.4.24"           # ipCidrRouteTable
            - ".1.3.6.1.2.1.4.22"           # ipNetToMediaTable (ARP)

            # --- TCP connection table (massive, rarely useful in LLD) ---
            - ".1.3.6.1.2.1.6.13"           # tcpConnTable

            # --- Host Resources junk/directory tables ---
            - ".1.3.6.1.2.1.25.3.2.1"       # hrDeviceTable (index directory)
            - ".1.3.6.1.2.1.25.4.2.1"       # hrSWRunTable (process list)
            - ".1.3.6.1.2.1.25.5.1.1"       # hrSWRunPerfTable (per-process perf)

            # --- Net-SNMP cache tables (no useful metrics) ---
            - ".1.3.6.1.4.1.8072.1.5.3"     # nsCache* (NET-SNMP-AGENT-MIB)

            # -----------------------------------------------------------------------
            # Nimble-specific junk examples:
            # If you discover any 'directory-like' tables that are not useful for
            # monitoring, you can add them here later, e.g.:
            #
            # - "{root}.1.x.y.z"
            #
            # -----------------------------------------------------------------------
        """
    ).rstrip() + "\n"


def generate_generic_filter_yaml(ent: int, canonical: str) -> str:
    """
    Fallback template for vendors without a hand-tuned filter.
    """
    root = f".1.3.6.1.4.1.{ent}"
    return textwrap.dedent(
        f"""\
        Version: 1.0

        # ---------------------------------------------------------------------------
        # Enterprise OIDs reference:
        # Official registry of all vendor enterprise numbers:
        # https://www.iana.org/assignments/enterprise-numbers/
        #
        # Vendor:
        #   {canonical}
        # Enterprise ID:
        #   {ent}  =>  {root}
        #
        # Use this OID in lld.include_roots to walk the vendor subtree.
        # ---------------------------------------------------------------------------

        mib2:
          regex: "(sysUpTime|hrProcessorLoad|hrStorageUsed|ifHighSpeed)"

        vendor:
          regex: "(cpu|mem|temperature|fan|disk|volume|status|power)"

        lld:
          regex: "(ifHCInOctets|ifHCOutOctets|volume|disk|temperature|Status)"

          include_roots:
            - ".1.3.6.1.2.1.2.2"
            - ".1.3.6.1.2.1.31.1.1"
            - "{root}"

          exclude_roots:
            - ".1.3.6.1.2.1.4.21"
            - ".1.3.6.1.2.1.4.24"
            - ".1.3.6.1.2.1.4.22"
            - ".1.3.6.1.2.1.6.13"
            - ".1.3.6.1.2.1.25.3.2.1"
            - ".1.3.6.1.2.1.25.4.2.1"
            - ".1.3.6.1.2.1.25.5.1.1"
            - ".1.3.6.1.4.1.8072.1.5.3"
        """
    ).rstrip() + "\n"


def write_filter_file(
    vendor: Dict[str, Any],
    filters_dir: str,
    force: bool = False,
) -> str:
    """
    Generate a filters/filters_<slug>.yaml file for the given vendor.
    Returns the path to the written file.
    """
    os.makedirs(filters_dir, exist_ok=True)

    canonical = vendor["canonical"]
    ent = vendor["enterprise"]
    category = vendor.get("category", "generic")
    slug = slugify(canonical)

    filename = f"filters_{slug}.yaml"
    path = os.path.join(filters_dir, filename)

    if os.path.exists(path) and not force:
        print(f"[warn] Filter file already exists: {path}")
        print("       Use --force to overwrite.")
        return path

    if canonical.lower().startswith("nimble"):
        content = generate_nimble_filter_yaml(ent)
    else:
        # For now, Nimble has a tuned filter; everything else gets a generic one.
        content = generate_nimble_filter_yaml(ent) if canonical == "Nimble Storage" else generate_generic_filter_yaml(ent, canonical)  # just in case

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"[info] Wrote filter file: {path}")
    return path


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Map vendor name to enterprise ID and optionally generate a filters/*.yaml file."
    )
    parser.add_argument(
        "vendor_name",
        nargs="+",
        help="Vendor name (e.g. 'nimble', 'qnap', 'hpe nimble')",
    )
    parser.add_argument(
        "--write-filter",
        action="store_true",
        help="Generate a filters/filters_<vendor>.yaml file for the best match.",
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

    matches = find_matches(query)
    if not matches:
        print(f"No matches found for vendor name: {query!r}")
        print("Hint: check the IANA enterprise registry:")
        print("  https://www.iana.org/assignments/enterprise-numbers/")
        sys.exit(1)

    best = matches[0]
    ent = best["enterprise"]
    root = f".1.3.6.1.4.1.{ent}"

    print(f"Best match:   {best['canonical']}")
    if best.get("aliases"):
        print(f"Aliases:      {', '.join(best['aliases'])}")
    print(f"Enterprise:   {ent}")
    print(f"OID root:     {root}")
    if best.get("notes"):
        print(f"Notes:        {best['notes']}")

    print()
    print("Suggested lld.include_roots entry:")
    print(f'  - "{root}"')

    slug = slugify(best["canonical"])
    filter_file = f"filters_{slug}.yaml"
    print()
    print("Suggested filter filename:")
    print(f"  {args.filters_dir}/{filter_file}")

    if args.write_filter:
        print()
        write_filter_file(best, args.filters_dir, force=args.force)


if __name__ == "__main__":
    main()

