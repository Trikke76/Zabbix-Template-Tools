#!/usr/bin/env python3
"""
auto_oid_finder.py
==================

Version: 1.0.7

Scan an SNMP device, discover scalar OIDs and table-like OID patterns,
enrich them (optionally) with MIB names/descriptions via snmptranslate
and Observium MIBs, and write a YAML "profile" that can be fed into
oid2zabbix-template.py to build a Zabbix 7.0 template.
"""

import argparse
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

import yaml

VERSION = "1.0.7"

# Default roots: vendor (enterprise) + MIB-2
DEFAULT_ROOTS = [".1.3.6.1.4.1", ".1.3.6.1.2.1"]
DEFAULT_COMMUNITY = "public"
DEFAULT_PORT = 161
DEFAULT_TIMEOUT = 2
DEFAULT_RETRIES = 1

# Legacy single-filter default (used when no --filter-file is provided)
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
# Dedup helpers for item keys
# ---------------------------------------------------------------------------

def append_unique_item(target_list, item_dict, used_keys: set, context: str = "item"):
    """
    Append an item dict to target_list, but only if its key is not already used.

    - target_list: the list (items or item_prototypes) to append to
    - item_dict: the Zabbix item dict (must have 'key' or 'key_')
    - used_keys: a set() tracking keys we've already emitted
    - context: 'item' or 'prototype' (for warning messages only)
    """
    key = item_dict.get("key") or item_dict.get("key_")
    if not key:
        # No key? Just append, nothing to dedup on.
        target_list.append(item_dict)
        return

    if key in used_keys:
        print(f"[warn] Skipping duplicate {context} key: {key}", file=sys.stderr)
        return

    used_keys.add(key)
    target_list.append(item_dict)


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
    # -Td : dump full OBJECT-TYPE definition
    # -OS : show module::symbolicName in output
    cmd = ["snmptranslate", "-m", "+ALL", "-Td", "-OS", oid]
    env = os.environ.copy()

    if observium_dir:
        mibdirs = observium_dir
        if env.get("MIBDIRS"):
            mibdirs = observium_dir + os.pathsep + env["MIBDIRS"]
        env["MIBDIRS"] = mibdirs

    log_debug(f"snmptranslate cmd: {' '.join(cmd)}")
    try:
        # Capture raw bytes and decode manually so we don't crash on non-UTF-8
        out_bytes = subprocess.check_output(
            cmd, env=env, stderr=subprocess.DEVNULL
        )
        out = out_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None, None, None

    module: str | None = None
    name: str | None = None
    desc: str | None = None

    # First non-empty line normally looks like:
    #   SNMPv2-MIB::sysDescr
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9\-]+)::([A-Za-z0-9_\-]+)\b", line)
        if m:
            module, name = m.group(1), m.group(2)
            break

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
        # Capture raw bytes; decode ourselves to avoid UnicodeDecodeError
        out_bytes = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        out = out_bytes.decode("utf-8", errors="replace")
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
# Table detection (coarse but effective)
# ---------------------------------------------------------------------------

def split_oid(oid: str) -> list[int]:
    return [int(x) for x in oid.lstrip(".").split(".") if x.isdigit()]

def detect_tables(oid_list: list[str]) -> list[dict]:
    """
    Very coarse SNMP "table" detection:

    We assume typical table OIDs look like:

        <base>.<table>.<entry>.<column>.<index>

    e.g. IF-MIB::ifDescr.1 =
         .1.3.6.1.2.1.2.2.1.2.1
         [1,3,6,1,2,1,2,2,1,2,1]
          <--------root------><c><i>

    Heuristic:
      - For each non-scalar OID with at least 4 components, take all but the
        last TWO components as a candidate "table root".
      - The remaining tail is at least [column, index].
      - The last component in tail is treated as row index, the one before it
        as column id.
      - We keep groups that have at least 2 distinct rows and 2 distinct
        columns.
    """
    # Filter out scalars (ending in .0)
    non_scalars = [o for o in oid_list if not o.endswith(".0")]

    clusters: dict[str, list[str]] = defaultdict(list)

    for oid in non_scalars:
        parts = split_oid(oid)
        # Need at least: ....<col>.<idx>
        if len(parts) < 4:
            continue
        # Candidate table root = everything except the last *two* components
        root_parts = parts[:-2]
        root = "." + ".".join(str(x) for x in root_parts)
        clusters[root].append(oid)

    tables: list[dict] = []

    for root, oids in clusters.items():
        if len(oids) < 4:
            continue

        row_indices = set()
        col_indices = set()

        root_parts = split_oid(root)

        for o in oids:
            parts = split_oid(o)
            if len(parts) <= len(root_parts):
                continue
            tail = parts[len(root_parts):]
            if len(tail) == 0:
                continue

            # Last component is usually index
            idx = tail[-1]
            row_indices.add(idx)

            # The "column" is the component before the index
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
    mib2_filter_re: re.Pattern | None,
    vendor_filter_re: re.Pattern | None,
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

        # Decide which filter to use based on OID tree
        if oid.startswith(".1.3.6.1.2.1."):          # MIB-2
            active_re = mib2_filter_re
        elif oid.startswith(".1.3.6.1.4.1."):       # vendor / enterprise
            active_re = vendor_filter_re
        else:
            # fallback: use vendor filter, or mib2 filter, or None
            active_re = vendor_filter_re or mib2_filter_re

        # Apply selection filter
        if no_filter:
            selected = True
        elif active_re is None:
            # No regex configured for this tree => default to not selected
            selected = False
        else:
            text = " ".join([
                oid,
                module or "",
                name or "",
                desc or "",
                str(value or ""),
            ])
            selected = bool(active_re.search(text))

        scalar_entry["selected"] = selected
        scalars.append(scalar_entry)

    # Detect tables
    tables_meta = detect_tables(list(all_oids.keys()))

    tables: list[dict] = []
    for t in tables_meta:
        cols = derive_table_columns(t, all_oids, observium_dir)

        # Table-level filtering:
        # Keep only columns whose name/description matches the active filter
        # (MIB-2 vs vendor). If no columns survive, we drop the table entirely.
        interesting_cols: list[dict] = []

        for col in cols:
            prefix = col.get("prefix") or ""
            module = col.get("module") or ""
            name = col.get("name") or ""
            desc = col.get("description") or ""

            # Decide which filter to use based on column OID tree
            if prefix.startswith(".1.3.6.1.2.1."):          # MIB-2
                active_re = mib2_filter_re
            elif prefix.startswith(".1.3.6.1.4.1."):       # vendor / enterprise
                active_re = vendor_filter_re
            else:
                active_re = vendor_filter_re or mib2_filter_re

            if no_filter or active_re is None:
                # No filtering -> keep everything
                interesting_cols.append(col)
            else:
                text = " ".join([prefix, module, name, desc])
                if active_re.search(text):
                    interesting_cols.append(col)

        # Drop tables that have no interesting columns at all
        if not interesting_cols:
            continue

        t_with_cols = dict(t)
        t_with_cols["columns"] = interesting_cols
        tables.append(t_with_cols)

    profile = {
        "version": "auto_oid_profile_v1",
        "generated_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
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
            f"Default: {', '.join(DEFAULT_ROOTS)}"
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
        help="Legacy single regex for 'interesting' OIDs (used if no --filter-file is provided)",
    )
    parser.add_argument(
        "--filter-file",
        help="YAML file defining separate filters for MIB-2 and vendor trees",
    )
    parser.add_argument(
        "--no-filter",
        action="store_true",
        help="Disable filters; mark all scalars as selected",
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

    # Determine roots
    roots = args.root or DEFAULT_ROOTS

    # Filter regexes
    mib2_filter_re: re.Pattern | None = None
    vendor_filter_re: re.Pattern | None = None

    if args.filter_file:
        # Load from external YAML
        try:
            with open(args.filter_file, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception as e:
            log_error(f"Failed to load filter file '{args.filter_file}': {e}")
            cfg = {}

        mib2_cfg = cfg.get("mib2") or {}
        vendor_cfg = cfg.get("vendor") or {}

        if "regex" in mib2_cfg:
            try:
                mib2_filter_re = re.compile(
                    mib2_cfg["regex"],
                    re.IGNORECASE | re.VERBOSE,
                )
                log_info(f"MIB-2 filter regex: '{mib2_cfg['regex']}'")
            except re.error as e:
                log_error(f"Invalid MIB-2 filter regex: {e}")
        
        if "regex" in vendor_cfg:
            try:
                vendor_filter_re = re.compile(
                    vendor_cfg["regex"],
                    re.IGNORECASE | re.VERBOSE,
                )
                log_info(f"Vendor filter regex: '{vendor_cfg['regex']}'")
            except re.error as e:
                log_error(f"Invalid vendor filter regex: {e}")

    if not args.filter_file:
        if args.no_filter:
            log_info("Filter disabled (--no-filter). All scalars will be marked selected.")
        else:
            pattern = args.filter or DEFAULT_FILTER_REGEX
            try:
                vendor_filter_re = re.compile(pattern, re.IGNORECASE)
                mib2_filter_re = vendor_filter_re
                log_info(f"Using single filter regex: '{pattern}'")
            except re.error as e:
                log_error(f"Invalid filter regex '{pattern}': {e}")
                vendor_filter_re = None
                mib2_filter_re = None

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
        mib2_filter_re=mib2_filter_re,
        vendor_filter_re=vendor_filter_re,
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

