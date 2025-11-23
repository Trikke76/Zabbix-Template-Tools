#!/usr/bin/env python3
"""
auto_oid_finder.py
==================

Version: 1.0.3

Scan an SNMP device, discover scalar OIDs and table-like OID patterns,
enrich them (optionally) with MIB names/descriptions via snmptranslate
and Observium MIBs, and write a YAML "profile" that can be fed into
oid2zabbix-template.py to build a Zabbix 7.0 template.

Key ideas
---------

- Use one or more root OIDs (default: .1.3.6.1.2.1) and walk them via SNMP.
- Classify OIDs into:
    * scalars: OIDs ending in ".0"
    * tables:  clusters of OIDs that look like SNMP tables
- For each scalar:
    * store oid, sample type+value, value_class, module/name/description
    * keep *all* scalars in YAML, but add 'selected: true/false'
      based on a filter regex (unless --no-filter).
- For each table:
    * detect approximate row/column counts
    * pick example OIDs
    * detect columns and enrich via snmptranslate

Output YAML layout (simplified)
-------------------------------

target:
  host: 1.2.3.4
  community: public
  root_oids:
    - .1.3.6.1.2.1

scalars:
  - oid: ".1.3.6.1.4.1.24681.1.3.1.0"
    sample_type: "INTEGER"
    sample_value: 42
    value_class: "UNSIGNED"
    module: "QTS-MIB"
    name: "cpuUsageEX"
    description: "..."
    selected: true

tables:
  - root_oid: ".1.3.6.1.2.1.2.2.1"
    approx_rows: 4
    approx_columns: 6
    example_oids:
      - ".1.3.6.1.2.1.2.2.1.1.1"
      - ".1.3.6.1.2.1.2.2.1.1.2"
    columns:
      - prefix: ".1.3.6.1.2.1.2.2.1.2"
        module: "IF-MIB"
        name: "ifDescr"
        description: "..."
        sample_type: "OCTET STRING"
        value_class: "TEXT"

The resulting YAML is consumed by oid2zabbix-template.py.
"""

import argparse
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime

import yaml

VERSION = "1.0.3"

DEFAULT_ROOT = ".1.3.6.1.2.1"  # MIB-2
DEFAULT_COMMUNITY = "public"
DEFAULT_PORT = 161
DEFAULT_TIMEOUT = 2
DEFAULT_RETRIES = 1

# This is the same "signal words" filter we used everywhere.
DEFAULT_FILTER_REGEX = (
    r"(temp|temperature|thermal|fan|cool|psu|ps|power|volt|current|amps|"
    r"cpu|load|usage|util|mem|memory|swap|disk|hdd|ssd|raid|array|lun|"
    r"error|errors|fail|failed|status|state|health|alarm|alert|ups|"
    r"battery|runtime|charge|toner|ink|drum|tray|paper|jam)"
)

DEBUG = False


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def log_info(msg: str):
    print(f"[info] {msg}")


def log_warn(msg: str):
    print(f"[warn] {msg}")


def log_error(msg: str):
    print(f"[error] {msg}", file=sys.stderr)


def log_debug(msg: str):
    if DEBUG:
        print(f"[debug] {msg}")


# ---------------------------------------------------------------------------
# Observium MIBs helpers
# ---------------------------------------------------------------------------

def ensure_observium_mibs(base_dir: str, force_sync: bool, allow_prompt: bool) -> str | None:
    """
    Ensure Observium MIB repo exists at base_dir/observium_mibs.

    Returns the path to the MIB directory or None if not present and user
    opted out.
    """
    repo_dir = os.path.join(base_dir, "observium_mibs")
    if os.path.isdir(repo_dir):
        if force_sync:
            # Attempt git pull
            log_info(f"Updating Observium MIBs in {repo_dir} (git pull)...")
            try:
                subprocess.run(
                    ["git", "-C", repo_dir, "pull", "--ff-only"],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as e:
                log_warn(f"Failed to update Observium MIBs ({e}); using existing clone")
        return repo_dir

    # Not present
    if not allow_prompt and not force_sync:
        log_info("Observium MIBs not present and not syncing (no prompt).")
        return None

    # Ask user
    while True:
        ans = input(
            "[prompt] Sync/update Observium MIB library in ./observium_mibs "
            "(for name enrichment)? [Y/n]: "
        ).strip().lower()
        if ans in ("", "y", "yes"):
            log_info(f"Cloning Observium MIBs into {repo_dir}...")
            try:
                subprocess.run(
                    [
                        "git",
                        "clone",
                        "https://github.com/linuxmail/observium-mibs.git",
                        repo_dir,
                    ],
                    check=True,
                )
                return repo_dir
            except Exception as e:
                log_error(f"Failed to clone Observium MIBs: {e}")
                return None
        elif ans in ("n", "no"):
            log_info("User opted not to sync Observium MIBs.")
            return None
        else:
            print("Please answer Y or n.")


def snmptranslate_enrich(
    oid: str,
    observium_dir: str | None,
) -> tuple[str | None, str | None, str | None]:
    """
    Use snmptranslate to try to get (module, name, description) for a numeric OID.

    Returns (module, name, description) or (None, None, None) if not resolvable.
    """
    cmd = ["snmptranslate", "-m", "+ALL", "-Td", oid]
    env = os.environ.copy()

    if observium_dir:
        mibdirs = observium_dir
        if env.get("MIBDIRS"):
            mibdirs = observium_dir + os.pathsep + env["MIBDIRS"]
        env["MIBDIRS"] = mibdirs

    log_debug(f"snmptranslate cmd: {' '.join(cmd)}")
    try:
        out = subprocess.check_output(
            cmd, env=env, stderr=subprocess.DEVNULL, text=True
        )
    except Exception:
        return None, None, None

    module = None
    name = None
    desc = None

    for line in out.splitlines():
        line = line.strip()
        if "::" in line and "Object" in line and "OID" in line:
            # e.g. "QTS-MIB::cpuUsageEX OBJECT-TYPE"
            m = re.match(r"^([A-Za-z0-9\-]+)::([A-Za-z0-9_\-]+)\s+OBJECT-TYPE", line)
            if m:
                module, name = m.group(1), m.group(2)
        elif line.startswith("DESCRIPTION"):
            # Next lines until the closing quote
            desc_lines = []
            # The line may be 'DESCRIPTION "text...' or just 'DESCRIPTION "'
            first_quote = line.find('"')
            if first_quote != -1 and line.count('"') >= 2:
                # Single-line description
                inner = line[first_quote + 1 : line.rfind('"')]
                desc_lines.append(inner)
            else:
                # Multi-line, read subsequent lines
                # We'll just split on quotes in the total output later
                pass

    # Description parsing: coarse but safe
    # Extract between first DESCRIPTION " and the matching closing ".
    m_desc = re.search(r'DESCRIPTION\s+"([^"]*)"', out, re.DOTALL)
    if m_desc:
        desc = m_desc.group(1).replace("\n", " ").strip()

    return module, name, desc


# ---------------------------------------------------------------------------
# SNMP walk via net-snmp snmpwalk
# ---------------------------------------------------------------------------

def run_snmpwalk(
    host: str,
    community: str,
    root_oid: str,
    port: int,
    timeout: int,
    retries: int,
) -> list[tuple[str, str, str]]:
    """
    Run net-snmp snmpwalk and return a list of (oid, type, value).

    We always request numeric OIDs (-On).

    Example line:
      .1.3.6.1.2.1.1.3.0 = Timeticks: (1234) 0:00:12.34
    """
    cmd = [
        "snmpwalk",
        "-v2c",
        "-c",
        community,
        "-On",
        "-t",
        str(timeout),
        "-r",
        str(retries),
        f"{host}:{port}",
        root_oid,
    ]
    log_info(f"SNMP walk {root_oid} on {host}:{port}...")
    log_debug(" ".join(cmd))

    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        log_error(f"snmpwalk failed: {e}")
        return []
    except FileNotFoundError:
        log_error("snmpwalk not found in PATH. Install net-snmp tools.")
        return []

    results: list[tuple[str, str, str]] = []

    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("Timeout:"):
            continue

        # Expect: <oid> = <type>: <value...>
        # or sometimes: <oid> = Hex-STRING: ...
        # We'll parse minimally.
        if " = " not in line:
            continue
        oid_part, rest = line.split(" = ", 1)
        oid_part = oid_part.strip()
        rest = rest.strip()

        # rest is usually "<TYPE>: <VALUE>" or "No Such Object ..." etc.
        if ":" in rest:
            type_part, value_part = rest.split(":", 1)
            type_part = type_part.strip()
            value_part = value_part.strip()
        else:
            type_part = rest
            value_part = ""

        results.append((oid_part, type_part, value_part))

    log_info(f"SNMP walk {root_oid} returned {len(results)} OIDs")
    return results


def classify_value_class(snmp_type: str, value: str) -> str:
    """
    Map SNMP type to a coarse value class for Zabbix: UNSIGNED, FLOAT, TEXT.
    """
    t = snmp_type.upper()
    if any(
        s in t
        for s in ("INTEGER", "COUNTER", "GAUGE", "UNSIGNED", "TIMETICKS")
    ):
        return "UNSIGNED"
    # We could try to detect floats, but that's rare in SNMP data.
    return "TEXT"


# ---------------------------------------------------------------------------
# Scalar selection logic
# ---------------------------------------------------------------------------

def decide_scalar_selected(
    oid: str,
    name: str | None,
    description: str | None,
    filter_re: re.Pattern | None,
    no_filter: bool = False,
) -> bool:
    """
    Decide whether a scalar should be marked as 'selected' in the profile.

    Rules:
      - If --no-filter: always True.
      - If filter_re is None: always True.
      - Else: selected if filter matches ANY of:
          * name (from MIB / Observium)
          * description
          * a key-like variant of the name
          * the OID string itself
      - Bonus: standard SNMP scalars under .1.3.6.1.2.1.*.0 are always selected.
    """
    if no_filter:
        return True

    if filter_re is None:
        return True

    oid = oid or ""
    name = (name or "").strip()
    description = (description or "").strip()

    # Standard MIB-2 scalar fallback:
    # .1.3.6.1.2.1.<X>.0  (sysUpTime, etc.)
    if oid.startswith(".1.3.6.1.2.1.") and oid.endswith(".0"):
        return True

    # Build key candidate (sanitized name)
    key_candidate = name.replace("::", "_").replace(" ", "_")

    fields = [
        name,
        description,
        key_candidate,
        oid,
    ]

    for f in fields:
        if f and filter_re.search(f):
            return True

    return False


# ---------------------------------------------------------------------------
# Table detection (coarse but effective)
# ---------------------------------------------------------------------------

def split_oid(oid: str) -> list[int]:
    return [int(x) for x in oid.lstrip(".").split(".") if x.isdigit()]


def detect_tables(oid_list: list[str]) -> list[dict]:
    """
    Very coarse SNMP "table" detection:

    - Group all non-scalar OIDs by a prefix of N components (default: len-2).
    - For each prefix, count distinct row indexes and columns.
    - Only keep groups that look like a table: rows >= 2 and columns >= 2.

    Result is a list of:
      {
        "root_oid": ".1.3.6.1.2.1.2.2.1",
        "approx_rows": N,
        "approx_columns": M,
        "example_oids": [...],
      }
    """
    # Filter out scalars (ending in .0)
    non_scalars = [o for o in oid_list if not o.endswith(".0")]

    # Map: root_prefix -> list of oids
    clusters: dict[str, list[str]] = defaultdict(list)

    for oid in non_scalars:
        parts = split_oid(oid)
        if len(parts) < 3:
            continue
        # Take all but last component as a candidate root
        root = "." + ".".join(str(x) for x in parts[:-1])
        clusters[root].append(oid)

    tables: list[dict] = []

    for root, oids in clusters.items():
        if len(oids) < 4:
            continue

        row_indices = set()
        col_indices = set()

        for o in oids:
            parts = split_oid(o)
            root_parts = split_oid(root)
            tail = parts[len(root_parts):]
            if len(tail) == 0:
                continue
            # Last component is usually index
            idx = tail[-1]
            row_indices.add(idx)

            # The "column" is often the one before last, but SNMP tables vary.
            if len(tail) >= 2:
                col = tail[-2]
                col_indices.add(col)

        approx_rows = len(row_indices)
        approx_cols = len(col_indices)

        if approx_rows >= 2 and approx_cols >= 2:
            tables.append(
                {
                    "root_oid": root,
                    "approx_rows": approx_rows,
                    "approx_columns": approx_cols,
                    "example_oids": sorted(oids)[:5],
                }
            )

    return tables


def derive_table_columns(
    table: dict,
    all_oids: dict[str, dict],
    observium_dir: str | None,
) -> list[dict]:
    """
    Given a table root and all discovered OIDs (with sample data), approximate
    column prefixes and enrich them via snmptranslate.

    all_oids[oid] = { "type": ..., "value": ... }
    """
    root = table["root_oid"]
    root_parts = split_oid(root)
    columns_map: dict[str, list[str]] = defaultdict(list)

    # Find all OIDs under this root
    for oid in all_oids.keys():
        if not oid.startswith(root + "."):
            continue
        parts = split_oid(oid)
        tail = parts[len(root_parts):]
        if len(tail) < 1:
            continue
        # Column prefix is everything except the last index component
        col_prefix_parts = parts[:-1]
        col_prefix = "." + ".".join(str(x) for x in col_prefix_parts)
        columns_map[col_prefix].append(oid)

    columns: list[dict] = []

    for col_prefix, col_oids in columns_map.items():
        # Pick an example OID
        example_oid = col_oids[0]
        entry = all_oids.get(example_oid, {})
        snmp_type = entry.get("type", "")
        value = entry.get("value", "")

        value_class = classify_value_class(snmp_type, value)

        module, name, desc = snmptranslate_enrich(example_oid, observium_dir)

        columns.append(
            {
                "prefix": col_prefix,
                "module": module,
                "name": name,
                "description": desc,
                "sample_type": snmp_type,
                "value_class": value_class,
            }
        )

    return columns


# ---------------------------------------------------------------------------
# Main profile builder
# ---------------------------------------------------------------------------

def make_output_path(host: str, explicit_output: str | None) -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(script_dir, "export_yaml")
    os.makedirs(out_dir, exist_ok=True)

    if explicit_output:
        # If user gave a path with dir, honor it. Otherwise, place in export_yaml.
        if os.path.dirname(explicit_output):
            os.makedirs(os.path.dirname(explicit_output), exist_ok=True)
            return explicit_output
        return os.path.join(out_dir, explicit_output)

    ts = datetime.now().strftime("%Y%m%d%H%M")
    fname = f"auto_oid_{host}_{ts}.yaml"
    return os.path.join(out_dir, fname)


def build_profile(
    host: str,
    community: str,
    roots: list[str],
    port: int,
    timeout: int,
    retries: int,
    observium_dir: str | None,
    filter_re: re.Pattern | None,
    no_filter: bool,
) -> tuple[dict, dict]:
    """
    Walk the given roots, collect OIDs, figure out scalars and tables,
    enrich with MIB names, and return (profile, stats).
    """
    all_results: list[tuple[str, str, str]] = []
    for root in roots:
        res = run_snmpwalk(host, community, root, port, timeout, retries)
        all_results.extend(res)

    # Map OID -> info
    all_oids: dict[str, dict] = {}
    for oid, t, v in all_results:
        all_oids[oid] = {
            "type": t,
            "value": v,
        }

    # Classify scalars
    scalars: list[dict] = []
    scalar_oids = [o for o in all_oids.keys() if o.endswith(".0")]
    for oid in sorted(scalar_oids):
        entry = all_oids[oid]
        snmp_type = entry.get("type", "")
        value = entry.get("value", "")
        value_class = classify_value_class(snmp_type, value)

        module, name, desc = snmptranslate_enrich(oid, observium_dir)

        scalar_entry = {
            "oid": oid,
            "sample_type": snmp_type,
            "sample_value": value,
            "value_class": value_class,
            "module": module,
            "name": name,
            "description": desc,
        }

        scalar_entry["selected"] = decide_scalar_selected(
            oid=oid,
            name=name,
            description=desc,
            filter_re=filter_re,
            no_filter=no_filter,
        )

        scalars.append(scalar_entry)

    # Detect tables
    tables_meta = detect_tables(list(all_oids.keys()))

    tables: list[dict] = []
    for t in tables_meta:
        cols = derive_table_columns(t, all_oids, observium_dir)
        t_with_cols = dict(t)
        t_with_cols["columns"] = cols
        tables.append(t_with_cols)

    profile = {
        "version": "auto_oid_profile_v1",
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "target": {
            "host": host,
            "community": community,
            "port": port,
            "roots": roots,
        },
        "scalars": scalars,
        "tables": tables,
    }

    stats = {
        "scalar_total": len(scalars),
        "scalar_selected": sum(1 for s in scalars if s.get("selected", True)),
        "tables": len(tables),
        "oids_total": len(all_oids),
    }

    return profile, stats


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------

def main():
    global DEBUG

    parser = argparse.ArgumentParser(
        description=(
            "Discover interesting scalar and table-like SNMP OIDs on a device "
            "and write a YAML profile suitable for oid2zabbix-template.py."
        )
    )
    parser.add_argument(
        "--host",
        help="SNMP target host/IP",
    )
    parser.add_argument(
        "--community",
        default=DEFAULT_COMMUNITY,
        help=f"SNMP community (default: {DEFAULT_COMMUNITY})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"SNMP port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--root",
        action="append",
        help=(
            "Root OID to walk (numeric). Can be used multiple times. "
            f"Default: {DEFAULT_ROOT}"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"SNMP timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=f"SNMP retries (default: {DEFAULT_RETRIES})",
    )
    parser.add_argument(
        "--output",
        help="Output YAML file (default: export_yaml/auto_oid_<host>_<ts>.yaml)",
    )
    parser.add_argument(
        "--filter",
        help="Regex to decide which OIDs are 'interesting' (default: built-in)",
    )
    parser.add_argument(
        "--no-filter",
        action="store_true",
        help="Disable filter; mark all scalars as selected",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--observium-sync",
        action="store_true",
        help="Force (re)sync of Observium MIBs into ./observium_mibs",
    )
    parser.add_argument(
        "--no-observium",
        action="store_true",
        help="Do not use or prompt for Observium MIBs",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show script version and exit",
    )

    # Pre-parse for --version so we don't require --host in that case
    pre_args, _ = parser.parse_known_args()
    if pre_args.version:
        print(f"auto_oid_finder.py version {VERSION}")
        sys.exit(0)

    args = parser.parse_args()
    if not args.host:
        parser.error("the following arguments are required: --host")

    DEBUG = args.debug
    log_info(f"auto_oid_finder.py version: {VERSION}")

    roots = args.root or [DEFAULT_ROOT]

    # Filter regex
    filter_pattern: re.Pattern | None = None
    if args.no_filter:
        log_info("Filter disabled (--no-filter). All scalars will be marked selected.")
    else:
        pattern = args.filter or DEFAULT_FILTER_REGEX
        filter_pattern = re.compile(pattern, re.IGNORECASE)
        log_info(f"Using filter regex: '{pattern}'")

    # Observium MIBs
    observium_dir = None
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if args.no_observium:
        log_info("Observium MIBs disabled by --no-observium")
    else:
        observium_dir = ensure_observium_mibs(
            script_dir,
            force_sync=args.observium_sync,
            allow_prompt=True,
        )
        if observium_dir:
            log_info(f"Observium MIBs will be used from: {observium_dir}")
        else:
            log_info("Observium MIBs not available; enrichment will be limited.")

    out_path = make_output_path(args.host, args.output)

    t0 = time.time()
    profile, stats = build_profile(
        host=args.host,
        community=args.community,
        roots=roots,
        port=args.port,
        timeout=args.timeout,
        retries=args.retries,
        observium_dir=observium_dir,
        filter_re=filter_pattern,
        no_filter=args.no_filter,
    )
    elapsed = time.time() - t0

    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            profile,
            f,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )

    print()
    print("[summary]")
    print(f"  Host:             {args.host}")
    print(f"  Roots walked:     {', '.join(roots)}")
    print(f"  OIDs discovered:  {stats['oids_total']}")
    print(
        f"  Scalars:          {stats['scalar_total']} (selected: "
        f"{stats['scalar_selected']})"
    )
    print(f"  Tables detected:  {stats['tables']}")
    print(f"  Output file:      {out_path}")
    print(
        f"  Observium MIBs:    "
        f"{'used for enrichment' if observium_dir else 'not used'}"
    )
    print(f"  Elapsed time:     {elapsed:.1f}s")
    print("[info] auto_oid_finder profile ready.")


if __name__ == "__main__":
    main()

