#!/usr/bin/env python3
"""
auto_oid_finder.py
==================

Scan a device via SNMP and discover:

  * Interesting TABLES (for LLD)
  * Interesting SCALARS (for regular items)

No MIBs are required for discovery. We only use numeric OIDs and sample values.

Optionally, we can:
  * Sync/update the Observium MIB collection (github.com/linuxmail/observium-mibs)
    under ./observium_mibs/
  * Use snmptranslate + those MIBs to enrich OIDs with:
      - module (MIB module)
      - name (symbolic object name)
      - description (OBJECT-TYPE DESCRIPTION)

Output: a YAML file with:
  - target: connection metadata
  - scan: basic scan info
  - scalars: list of scalar OIDs (ending in .0)
  - tables: list of table roots with column prefixes

Intended to be consumed later by:
  - oid2zabbix-template.py
  - zbx_lld_builder.py
"""

import argparse
import os
import sys
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional

import subprocess
import shutil
import yaml

from pysnmp.proto.rfc1902 import (
    OctetString,
    Integer,
    Integer32,
    Gauge32,
    Counter32,
    Counter64,
    TimeTicks,
)

DEBUG = False

# Observium MIB repo – we sync this into ./observium_mibs
OBSERVIUM_MIB_REPO = "https://github.com/linuxmail/observium-mibs.git"


# ---------------------------------------------------------------------------
# Logging
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
# SNMP walk – works with PySNMP <= 6 and PySNMP 7
# ---------------------------------------------------------------------------

def snmp_walk(
    host: str,
    port: int,
    community: str,
    root_oid: str,
    timeout: float = 1.0,
    retries: int = 1,
) -> List[Tuple[str, object]]:
    """
    Do an SNMP walk starting at root_oid and return list of (oid_str, value_obj).

    oid_str is always a dotted numeric OID starting with '.'.
    value_obj is the pysnmp value object (OctetString, Integer, etc.).

    This function is compatible with:
      - PySNMP <= 6 (sync HLAPI in pysnmp.hlapi)
      - PySNMP 7 (async HLAPI + pysnmp-sync-adapter)
    """
    results: List[Tuple[str, object]] = []

    # Try legacy synchronous HLAPI first (PySNMP <= 6)
    try:
        from pysnmp.hlapi import (  # type: ignore[import]
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
            nextCmd,
        )

        log_debug("Using legacy pysnmp.hlapi.nextCmd() for SNMP walk")

        engine = SnmpEngine()
        target = UdpTransportTarget((host, port), timeout=timeout, retries=retries)
        community_data = CommunityData(community, mpModel=1)  # v2c
        ctx = ContextData()

        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            engine,
            community_data,
            target,
            ctx,
            ObjectType(ObjectIdentity(root_oid)),
            lexicographicMode=False,
        ):
            if errorIndication:
                log_error(f"SNMP error: {errorIndication}")
                break
            if errorStatus:
                log_error(
                    f"SNMP error at {errorIndex}: {errorStatus.prettyPrint()}"
                )
                break

            for oid, val in varBinds:
                oid_str = "." + ".".join(str(x) for x in oid)
                results.append((oid_str, val))

        log_info(f"SNMP walk {root_oid} returned {len(results)} OIDs")
        return results

    except ImportError:
        # New PySNMP 7: only async HLAPI is available, use sync adapter
        log_debug(
            "pysnmp.hlapi sync API not available; using PySNMP 7 async HLAPI "
            "+ pysnmp-sync-adapter"
        )

    # PySNMP 7 path
    try:
        from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore[import]
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
        )
        from pysnmp_sync_adapter import (  # type: ignore[import]
            walk_cmd_sync,
            create_transport,
        )
    except ImportError as e:
        log_error(
            "PySNMP >= 7 detected, but either asyncio HLAPI or "
            "pysnmp-sync-adapter is missing.\n"
            "Install the sync adapter in this venv:\n"
            "    pip install pysnmp-sync-adapter\n"
            f"Details: {e}"
        )
        sys.exit(1)

    log_debug("Using pysnmp.hlapi.v3arch.asyncio + pysnmp-sync-adapter for SNMP walk")

    engine = SnmpEngine()
    community_data = CommunityData(community, mpModel=1)  # v2c
    ctx = ContextData()

    transport = create_transport(
        UdpTransportTarget,
        (host, port),
        timeout=timeout,
        retries=retries,
    )

    for (errorIndication, errorStatus, errorIndex, varBinds) in walk_cmd_sync(
        engine,
        community_data,
        transport,
        ctx,
        ObjectType(ObjectIdentity(root_oid)),
    ):
        if errorIndication:
            log_error(f"SNMP error: {errorIndication}")
            break
        if errorStatus:
            log_error(
                f"SNMP error at {errorIndex}: {errorStatus.prettyPrint()}"
            )
            break

        for oid, val in varBinds:
            oid_str = "." + ".".join(str(x) for x in oid)
            results.append((oid_str, val))

    log_info(f"SNMP walk {root_oid} returned {len(results)} OIDs")
    return results


# ---------------------------------------------------------------------------
# Value classification helpers
# ---------------------------------------------------------------------------

def guess_value_class(val: object) -> str:
    """
    Map pysnmp value type to a coarse class for Zabbix:
      - UNSIGNED
      - FLOAT
      - TEXT
    """
    if isinstance(val, (Integer, Integer32, Gauge32, Counter32, Counter64, TimeTicks)):
        return "UNSIGNED"
    if isinstance(val, OctetString):
        return "TEXT"
    # Future: add Float/Double types if needed
    return "TEXT"


def get_type_name(val: object) -> str:
    """Return the underlying pysnmp type name for informational purposes."""
    return val.__class__.__name__


# ---------------------------------------------------------------------------
# Table detection heuristics
# ---------------------------------------------------------------------------

def classify_oids_as_tables(
    non_scalar_oids: List[Tuple[str, object]],
    min_rows: int = 2,
    min_columns: int = 2,
) -> List[dict]:
    """
    Heuristic table detection:

    For each non-scalar OID:
      - We derive a "table root" by chopping off the last *two* subids.
        Example:
          .1.3.6.1.4.1.24681.1.3.11.1.2.1
          -> root: .1.3.6.1.4.1.24681.1.3.11.1

    We group by this root. For each root:
      - We derive candidate columns (prefix before the last index).
      - We count distinct rows.
    If root has >= min_rows rows and >= min_columns columns, we treat it as a table.

    Return a list of dicts with:
      {
        "root_oid": str,
        "approx_rows": int,
        "approx_columns": int,
        "example_oids": [str, ...],
        "columns": [
          {
            "prefix": str,
            "sample_type": str,
            "value_class": str,
          },
          ...
        ],
      }
    """
    # root -> list of (oid_str, value_obj)
    table_groups: Dict[str, List[Tuple[str, object]]] = {}

    for oid_str, val in non_scalar_oids:
        parts = oid_str.strip(".").split(".")
        if len(parts) < 3:
            continue
        # Derive a table root by chopping last 2 subids
        table_root = "." + ".".join(parts[:-2])
        table_groups.setdefault(table_root, []).append((oid_str, val))

    tables: List[dict] = []

    for root_oid, entries in table_groups.items():
        # Derive rows and columns from entries
        row_ids = set()
        col_prefixes: Dict[str, object] = {}  # prefix -> sample value

        example_oids: List[str] = []

        for oid_str, val in entries:
            parts = oid_str.strip(".").split(".")
            if len(parts) < 3:
                continue
            col_prefix = "." + ".".join(parts[:-1])
            row_idx = parts[-1]

            row_ids.add(row_idx)
            if col_prefix not in col_prefixes:
                col_prefixes[col_prefix] = val

            if len(example_oids) < 5:
                example_oids.append(oid_str)

        approx_rows = len(row_ids)
        approx_cols = len(col_prefixes)

        if approx_rows < min_rows or approx_cols < min_columns:
            # too small to be interesting as a table
            continue

        columns_list = []
        for prefix, sample_val in col_prefixes.items():
            columns_list.append(
                {
                    "prefix": prefix,
                    "sample_type": get_type_name(sample_val),
                    "value_class": guess_value_class(sample_val),
                }
            )

        tables.append(
            {
                "root_oid": root_oid,
                "approx_rows": approx_rows,
                "approx_columns": approx_cols,
                "example_oids": example_oids,
                "columns": sorted(
                    columns_list, key=lambda c: c["prefix"]
                ),
            }
        )

    return sorted(tables, key=lambda t: t["root_oid"])


# ---------------------------------------------------------------------------
# Scalar detection
# ---------------------------------------------------------------------------

def classify_scalars(
    all_results: List[Tuple[str, object]],
    filter_regex: Optional[re.Pattern] = None,
) -> List[dict]:
    """
    Extract scalar OIDs from the full SNMP result set.

    A scalar is:
      - OID ending in ".0"

    Optionally apply a regex filter on OID string or sample value string.
    """
    scalars: List[dict] = []

    for oid_str, val in all_results:
        if not oid_str.endswith(".0"):
            continue

        oid_lower = oid_str.lower()
        value_repr = (
            val.prettyPrint() if hasattr(val, "prettyPrint") else str(val)
        )

        if filter_regex:
            haystack = oid_lower + "\n" + value_repr.lower()
            if not filter_regex.search(haystack):
                continue

        scalars.append(
            {
                "oid": oid_str,
                "sample_type": get_type_name(val),
                "sample_value": value_repr,
                "value_class": guess_value_class(val),
            }
        )

    # Sort by OID for determinism
    scalars.sort(key=lambda s: s["oid"])
    return scalars


# ---------------------------------------------------------------------------
# Observium MIB sync (git clone/pull)
# ---------------------------------------------------------------------------

def sync_observium_mibs(obs_dir: str) -> bool:
    """
    Clone or update the Observium MIB collection under obs_dir.

    Returns True on success, False on failure.
    """
    if shutil.which("git") is None:
        log_warn(
            "git is not available; cannot sync Observium MIBs. "
            "Skipping MIB-based enrichment."
        )
        return False

    obs_dir = os.path.abspath(obs_dir)

    if os.path.isdir(obs_dir) and os.path.isdir(os.path.join(obs_dir, ".git")):
        log_info(f"Updating Observium MIBs in {obs_dir} (git pull)...")
        cmd = ["git", "-C", obs_dir, "pull", "--ff-only"]
        log_debug(" ".join(cmd))
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if proc.returncode != 0:
            log_warn("git pull failed; keeping existing MIBs.")
            log_debug(proc.stderr.strip())
            return False
        return True

    if os.path.exists(obs_dir) and not os.path.isdir(os.path.join(obs_dir, ".git")):
        log_warn(
            f"{obs_dir} exists but is not a git repo. Using it as-is, "
            "but automatic updates are disabled."
        )
        return True

    # Fresh clone
    log_info(f"Cloning Observium MIBs into {obs_dir}...")
    os.makedirs(os.path.dirname(obs_dir), exist_ok=True)
    cmd = ["git", "clone", OBSERVIUM_MIB_REPO, obs_dir]
    log_debug(" ".join(cmd))
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if proc.returncode != 0:
        log_warn("git clone of Observium MIBs failed.")
        log_debug(proc.stderr.strip())
        return False

    return True


def snmptranslate_available() -> bool:
    return shutil.which("snmptranslate") is not None


# ---------------------------------------------------------------------------
# snmptranslate-based MIB enrichment
# ---------------------------------------------------------------------------

def snmptranslate_td_for_oid(oid: str, mib_dir: str) -> Optional[str]:
    """
    Call snmptranslate to get a detailed OBJECT-TYPE dump for a numeric OID.

      snmptranslate -M <mib_dir> -m +ALL -Td <oid>

    Returns stdout on success, or None on failure.
    """
    env = os.environ.copy()
    # Ensure we use Observium MIB dir in addition to whatever the user has
    existing = env.get("MIBDIRS", "")
    if existing:
        env["MIBDIRS"] = f"{mib_dir}:{existing}"
    else:
        env["MIBDIRS"] = mib_dir
    env.setdefault("MIBS", "+ALL")

    cmd = ["snmptranslate", "-m", "+ALL", "-Td", oid]
    log_debug(f"snmptranslate cmd: {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
    except Exception as e:
        log_debug(f"snmptranslate failed: {e}")
        return None

    if proc.returncode != 0 or not proc.stdout.strip():
        log_debug(
            f"snmptranslate error for {oid}: rc={proc.returncode}, stderr={proc.stderr.strip()}"
        )
        return None

    return proc.stdout


def parse_td_header_and_description(td_text: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Given snmptranslate -Td output, try to extract:

      - module name
      - object name
      - DESCRIPTION text (if any)

    Returns (module, name, description)
    """
    lines = [ln.rstrip() for ln in td_text.splitlines() if ln.strip()]
    if not lines:
        return (None, None, None)

    # Header usually like: SNMPv2-MIB::sysName.0
    header = lines[0]
    m = re.match(r"^\s*([A-Za-z0-9_-]+)::([A-Za-z0-9_-]+)", header)
    module = m.group(1) if m else None
    name = m.group(2) if m else None

    # DESCRIPTION block
    desc_lines: List[str] = []
    in_desc = False

    for ln in lines:
        stripped = ln.lstrip()
        if stripped.upper().startswith("DESCRIPTION"):
            in_desc = True
            # Grab everything after the first quote, if present
            idx = stripped.find('"')
            if idx >= 0:
                after = stripped[idx + 1 :]
                desc_lines.append(after)
                # Check if closing quote is on same line
                if after.rstrip().endswith('"') and not after.rstrip().endswith('\\"'):
                    in_desc = False
            continue

        if in_desc:
            if '"' in stripped:
                qpos = stripped.find('"')
                desc_lines.append(stripped[:qpos])
                in_desc = False
            else:
                desc_lines.append(stripped)

    description = None
    if desc_lines:
        description = "\n".join(desc_lines).rstrip()

    return (module, name, description)


def enrich_scalars_with_mibs(
    scalars: List[dict],
    obs_mib_dir: str,
) -> None:
    """
    For each scalar (numeric OID ending in .0), use Observium MIBs to
    populate:
      - module
      - name
      - description

    Modifies the scalars list in-place.
    """
    log_info("Enriching scalar OIDs with Observium MIBs (if resolvable)...")

    for entry in scalars:
        oid = entry.get("oid")
        if not oid:
            continue

        td = snmptranslate_td_for_oid(oid, obs_mib_dir)
        if not td:
            continue

        module, name, desc = parse_td_header_and_description(td)
        if module:
            entry["module"] = module
        if name:
            entry["name"] = name
        if desc:
            entry["description"] = desc


def enrich_tables_with_mibs(
    tables: List[dict],
    obs_mib_dir: str,
) -> None:
    """
    For each table column prefix, pick an example OID, ask snmptranslate
    about that OID, and use the result to set:
      - module
      - name
      - description (on the column object)

    Modifies the tables list in-place.
    """
    log_info("Enriching table columns with Observium MIBs (if resolvable)...")

    for table in tables:
        example_oids = table.get("example_oids") or []
        columns = table.get("columns") or []
        if not example_oids or not columns:
            continue

        for col in columns:
            prefix = col.get("prefix")
            if not prefix:
                continue

            # Find an example OID under this column prefix
            example_oid = None
            for eo in example_oids:
                if eo.startswith(prefix + "."):
                    example_oid = eo
                    break
            if not example_oid:
                continue

            td = snmptranslate_td_for_oid(example_oid, obs_mib_dir)
            if not td:
                continue

            module, name, desc = parse_td_header_and_description(td)
            if module:
                col["module"] = module
            if name:
                col["name"] = name
            if desc:
                col["description"] = desc


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

DEFAULT_FILTER_PATTERN = (
    r"(temp|temperature|thermal|fan|cool|psu|ps|power|volt|current|amps|"
    r"cpu|load|usage|util|mem|memory|swap|disk|hdd|ssd|raid|array|lun|"
    r"error|errors|fail|failed|status|state|health|alarm|alert|"
    r"ups|battery|runtime|charge|"
    r"toner|ink|drum|tray|paper|jam)"
)


def main():
    global DEBUG

    parser = argparse.ArgumentParser(
        description=(
            "Auto-discover SNMP tables (for LLD) and scalars (for regular items)\n"
            "from a live device, without using MIB files. Optionally, sync and\n"
            "use Observium MIBs to enrich OIDs with names/descriptions."
        )
    )
    parser.add_argument("--host", required=True, help="Target host/IP")
    parser.add_argument(
        "--community",
        default="public",
        help="SNMP community (v2c, default: public)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=161,
        help="SNMP port (default: 161)",
    )
    parser.add_argument(
        "--root",
        action="append",
        help="Root OID to walk (can be repeated). Default: .1.3.6.1.2.1",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="SNMP timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="SNMP retries (default: 1)",
    )
    parser.add_argument(
        "--output",
        help="Output YAML file (default: auto_oid_<host>_<timestamp>.yaml)",
    )
    parser.add_argument(
        "--filter",
        help=(
            "Regex for selecting interesting OIDs by OID/value. "
            f"Default: {DEFAULT_FILTER_PATTERN!r}"
        ),
    )
    parser.add_argument(
        "--no-filter",
        action="store_true",
        help="Disable filtering (keep all scalars, all tables).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--observium-sync",
        action="store_true",
        help="Force sync/update of Observium MIBs without prompting.",
    )
    parser.add_argument(
        "--no-observium",
        action="store_true",
        help="Disable Observium MIB enrichment (no sync, no snmptranslate lookups).",
    )

    args = parser.parse_args()
    DEBUG = args.debug

    host = args.host
    community = args.community
    port = args.port
    timeout = args.timeout
    retries = args.retries

    roots = args.root or [".1.3.6.1.2.1"]

    # Filter regex
    if args.no_filter:
        filter_regex = None
        log_info("Filtering disabled (--no-filter). All scalars/tables will be kept.")
    else:
        pattern = args.filter or DEFAULT_FILTER_PATTERN
        try:
            filter_regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            log_error(f"Invalid --filter regex: {e}")
            sys.exit(1)
        log_info(f"Using filter regex: {pattern!r}")

    # Output file
    if args.output:
        output_path = args.output
    else:
        ts = datetime.now().strftime("%Y%m%d%H%M")
        safe_host = host.replace(":", "_").replace("/", "_")
        output_path = f"auto_oid_{safe_host}_{ts}.yaml"

    # Observium MIB directory (under this script's directory)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    obs_mib_dir = os.path.join(script_dir, "observium_mibs")
    use_observium = False

    if args.no_observium:
        log_info("Observium MIB enrichment disabled (--no-observium).")
    else:
        # Decide whether to sync Observium MIBs
        if args.observium_sync:
            log_info("Forcing Observium MIB sync (--observium-sync).")
            if sync_observium_mibs(obs_mib_dir):
                use_observium = True
        else:
            # Interactive prompt if we are in a TTY
            if sys.stdin.isatty():
                try:
                    ans = input(
                        "[prompt] Sync/update Observium MIB library in ./observium_mibs "
                        "(for name enrichment)? [Y/n]: "
                    ).strip().lower()
                except EOFError:
                    ans = "n"

                if ans in ("", "y", "yes"):
                    if sync_observium_mibs(obs_mib_dir):
                        use_observium = True
                else:
                    log_info("Skipping Observium MIB sync (user choice).")
            else:
                log_debug("Non-interactive stdin; skipping Observium MIB sync prompt.")

        if use_observium and not snmptranslate_available():
            log_warn(
                "snmptranslate is not available; Observium MIB enrichment will be skipped."
            )
            use_observium = False

    # SNMP scan
    all_results: List[Tuple[str, object]] = []

    for root in roots:
        res = snmp_walk(
            host=host,
            port=port,
            community=community,
            root_oid=root,
            timeout=timeout,
            retries=retries,
        )
        all_results.extend(res)

    if not all_results:
        log_warn("No OIDs discovered from the device. Nothing to write.")
        sys.exit(1)

    # Scalars: OIDs ending in .0
    scalars = classify_scalars(all_results, filter_regex=filter_regex)
    log_info(f"Scalar OIDs detected (after filter): {len(scalars)}")

    # Non-scalars: candidates for table detection
    non_scalars = [(oid, val) for (oid, val) in all_results if not oid.endswith(".0")]
    tables = classify_oids_as_tables(non_scalars)
    log_info(f"Tables detected: {len(tables)}")

    # Optional Observium-based enrichment
    if use_observium and os.path.isdir(obs_mib_dir):
        enrich_scalars_with_mibs(scalars, obs_mib_dir)
        enrich_tables_with_mibs(tables, obs_mib_dir)
    elif use_observium:
        log_warn(
            f"Observium MIB directory {obs_mib_dir} does not exist. "
            "Skipping MIB enrichment."
        )

    data = {
        "target": {
            "host": host,
            "port": port,
            "version": "2c",
            "community": community,
        },
        "scan": {
            "started_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "roots": roots,
        },
        "scalars": scalars,
        "tables": tables,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            data,
            f,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )

    print("\n[summary]")
    print(f"  Host:            {host}")
    print(f"  Roots walked:    {', '.join(roots)}")
    print(f"  OIDs discovered: {len(all_results)}")
    print(f"  Scalars kept:    {len(scalars)}")
    print(f"  Tables kept:     {len(tables)}")
    print(f"  Output file:     {output_path}")
    if use_observium:
        print("  Observium MIBs:   used for enrichment")
    else:
        print("  Observium MIBs:   not used")
    print("[info] auto_oid_finder profile ready.")


if __name__ == "__main__":
    main()

