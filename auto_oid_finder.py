#!/usr/bin/env python3
"""
auto_oid_finder.py
==================

Version: 1.0.15

Changelog (short)
-----------------
1.0.0 : Initial SNMP scanner, basic scalar detection and YAML export.
1.0.1 : Minor robustness fixes around snmpwalk parsing.
1.0.2 : Added optional Observium MIB support (snmptranslate enrichment).
1.0.3 : Improved scalar classification and basic table detection heuristics.
1.0.4 : Fixed Unicode decoding issues from snmpwalk output.
1.0.5 : Introduced separation of MIB-2 vs vendor OID handling.
1.0.6 : Added support for filter-file based selection (mib2/vendor).
1.0.7 : First pass at LLD table detection and filtering.
1.0.8 : Introduced snmptranslate caching and more reliable name extraction.
1.0.9 : The lost version (never made it out of the lab).
1.0.10: Cleaned up legacy filters, made --filter-file mandatory and strict.
1.0.11: Always walk .1.3.6.1.2.1 and .1.3.6.1.4.1, improved snmptranslate
         enrichment with a fallback call for MODULE::name.
1.0.12: Added forced LLD table building for all lld.include_roots (only if
         there are at least 2 rows), and unified column detection logic.
1.0.13: If walking .1.3.6.1.4.1 fails, automatically walk each lld.include_roots
         subtree under .1.3.6.1.4.1 individually so vendor tables (QNAP, etc.)
         are still discovered.
1.0.14: Stop walking .1.3.6.1.4.1 by default; you can add it or specific vendor
         subtrees (e.g. .1.3.6.1.4.1.24681) via --root.
1.0.15: Keep partial data when a walk gives timeout.

Purpose
-------

Scan an SNMP device, discover scalar OIDs and table-like OID patterns,
enrich them (optionally) with MIB names/descriptions via snmptranslate
and Observium MIBs, and write a YAML "profile" that can be fed into
oid2zabbix-template.py to build a Zabbix 7.0 template.

Key ideas
---------

- Always walk:
    * .1.3.6.1.2.1   (MIB-2)
  plus any vendor roots derived from the profile (lld.include_roots) and
  any extra roots passed via --root.
- If .1.3.6.1.4.1 is explicitly added as a root and that walk fails, we fall
  back to walking each lld.include_roots subtree under .1.3.6.1.4.1
  individually.
- Classify OIDs into:
    * scalars: OIDs ending in ".0"
    * tables:  clusters of OIDs that look like SNMP tables
- For each scalar:
    * store oid, sample type+value, value_class, module/name/description
    * keep *all* scalars in YAML, but add 'selected: true/false'
      based on filters (unless --no-filter).
- For each table:
    * detect approximate row/column counts
    * detect columns and enrich via snmptranslate
    * also **force-create tables** for each lld.include_roots that has at
      least 2 rows of data.
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

VERSION = "1.0.15"

MIB2_ROOT = ".1.3.6.1.2.1"
VENDOR_ROOT = ".1.3.6.1.4.1"

DEFAULT_COMMUNITY = "public"
DEFAULT_PORT = 161
DEFAULT_TIMEOUT = 2
DEFAULT_RETRIES = 1

DEBUG = False

# Simple cache to avoid calling snmptranslate repeatedly for the same OID
SNMPTRANSLATE_CACHE: dict[str, tuple[str | None, str | None, str | None]] = {}


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

    Strategy:
      - First call: snmptranslate -m +ALL -Td <oid>   (for DESCRIPTION, maybe name)
      - If module/name still missing: snmptranslate -m +ALL <oid>  (MODULE::name)
      - Cache the final (module, name, desc) in SNMPTRANSLATE_CACHE.
    """
    if not oid:
        return None, None, None

    cached = SNMPTRANSLATE_CACHE.get(oid)
    if cached is not None:
        return cached

    env = os.environ.copy()
    if observium_dir:
        mibdirs = observium_dir
        if env.get("MIBDIRS"):
            mibdirs = observium_dir + os.pathsep + env["MIBDIRS"]
        env["MIBDIRS"] = mibdirs

    module = None
    name = None
    desc = None

    # First pass: -Td (detailed)
    cmd_td = ["snmptranslate", "-m", "+ALL", "-Td", oid]
    log_debug(f"snmptranslate (Td) cmd: {' '.join(cmd_td)}")
    try:
        out_td = subprocess.check_output(
            cmd_td,
            env=env,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except Exception:
        out_td = ""

    if out_td:
        # Typical line: "SNMPv2-MIB::sysDescr OBJECT-TYPE"
        for line in out_td.splitlines():
            line = line.strip()
            if "::" in line and "OBJECT-TYPE" in line:
                m = re.match(r"^([A-Za-z0-9\-]+)::([A-Za-z0-9_\-]+)\s+OBJECT-TYPE", line)
                if m:
                    module, name = m.group(1), m.group(2)
                    break

        m_desc = re.search(r'DESCRIPTION\s+"([^"]*)"', out_td, re.DOTALL)
        if m_desc:
            desc = m_desc.group(1).replace("\n", " ").strip()

    # Second pass: simple translate if module/name still missing
    if module is None or name is None:
        cmd_simple = ["snmptranslate", "-m", "+ALL", oid]
        log_debug(f"snmptranslate (simple) cmd: {' '.join(cmd_simple)}")
        try:
            out_simple = subprocess.check_output(
                cmd_simple,
                env=env,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            first = out_simple.strip().splitlines()[0].strip()
            if "::" in first:
                m2 = re.match(r"^([A-Za-z0-9\-]+)::([A-Za-z0-9_\-]+)", first)
                if m2:
                    if module is None:
                        module = m2.group(1)
                    if name is None:
                        name = m2.group(2)
        except Exception:
            pass

    result = (module, name, desc)
    SNMPTRANSLATE_CACHE[oid] = result
    return result


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
    suppress_errors: bool = False,
) -> list[tuple[str, str, str]]:
    """
    Run net-snmp snmpwalk and return a list of (oid, type, value).

    We always request numeric OIDs (-On).

    If suppress_errors=True, non-zero exit codes are logged as [warn]
    and we still keep any partial data that was returned (if any).
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
        # Do NOT raise on non-zero exit codes; we want partial data.
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        log_error("snmpwalk not found in PATH. Install net-snmp tools.")
        return []

    out = proc.stdout.decode("utf-8", errors="replace")
    err = proc.stderr.decode("utf-8", errors="replace").strip()

    results: list[tuple[str, str, str]] = []

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # Drop timeout / end-of-view messages from output
        if line.startswith("Timeout:"):
            continue
        if "No more variables left in this MIB View" in line:
            continue

        if " = " not in line:
            continue
        oid_part, rest = line.split(" = ", 1)
        oid_part = oid_part.strip()
        rest = rest.strip()

        if ":" in rest:
            type_part, value_part = rest.split(":", 1)
            type_part = type_part.strip()
            value_part = value_part.strip()
        else:
            type_part = rest
            value_part = ""

        results.append((oid_part, type_part, value_part))

    if proc.returncode != 0:
        if results:
            # Partial success: we got some useful data
            msg = (
                f"snmpwalk for {root_oid} on {host}:{port} "
                f"returned exit code {proc.returncode} but produced "
                f"{len(results)} OIDs; using partial data."
            )
            if suppress_errors:
                log_warn(msg + (f" stderr={err}" if err else ""))
            else:
                log_warn(msg + (f" stderr={err}" if err else ""))
        else:
            # Real failure: nothing usable
            msg = (
                f"snmpwalk failed for {root_oid} on {host}:{port} "
                f"with exit code {proc.returncode}: {err}"
            )
            if suppress_errors:
                log_warn(msg)
            else:
                log_error(msg)
            return []

    log_info(f"SNMP walk {root_oid} returned {len(results)} OIDs")
    return results


    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("Timeout:"):
            continue

        if " = " not in line:
            continue
        oid_part, rest = line.split(" = ", 1)
        oid_part = oid_part.strip()
        rest = rest.strip()

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
      - Else if filter_re is None: False (strict mode).
      - Else: selected if filter matches ANY of:
          * name (from MIB / Observium)
          * description
          * a key-like variant of the name
          * the OID string itself
    """
    if no_filter:
        return True

    if filter_re is None:
        return False

    oid = oid or ""
    name = (name or "").strip()
    description = (description or "").strip()

    key_candidate = name.replace("::", "_").replace(" ", "_") if name else ""

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
    Detect SNMP "tables" heuristically.

    We assume typical table OIDs look like:

        <root>.<col>.<index>

    Heuristic:
      - For each non-scalar OID with at least 4 components, take all but the
        last TWO components as a candidate "table root".
      - The remaining tail is at least [column, index].
      - Keep groups with at least 2 distinct rows and 2 distinct columns.
    """
    non_scalars = [o for o in oid_list if not o.endswith(".0")]

    clusters: dict[str, list[str]] = defaultdict(list)

    for oid in non_scalars:
        parts = split_oid(oid)
        if len(parts) < 4:
            continue
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

            idx = tail[-1]
            row_indices.add(idx)

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

    Column detection rule:
      - For each OID under root, column prefix is everything except the last
        index component:
          <root>.<...column...>.<index>
        => prefix = <root>.<...column...>
    """
    root = table["root_oid"]
    root_parts = split_oid(root)
    columns_map: dict[str, list[str]] = defaultdict(list)

    for oid in all_oids.keys():
        if not oid.startswith(root + "."):
            continue
        parts = split_oid(oid)
        tail = parts[len(root_parts):]
        if len(tail) < 1:
            continue
        col_prefix_parts = parts[:-1]
        col_prefix = "." + ".".join(str(x) for x in col_prefix_parts)
        columns_map[col_prefix].append(oid)

    columns: list[dict] = []

    for col_prefix, col_oids in columns_map.items():
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


def table_is_interesting(
    table: dict,
    columns: list[dict],
    lld_filter_re: re.Pattern | None,
    lld_include_roots: list[str],
    lld_exclude_roots: list[str],
    no_filter: bool,
) -> bool:
    """
    Decide if a detected table should be kept for LLD.

    Rules:
      - If --no-filter: always True.
      - If root starts with any exclude_roots: False.
      - If root starts with any include_roots: True.
      - If no lld_filter_re: False (strict mode).
      - Else: keep only if at least one column's (prefix/module/name/desc)
        matches lld_filter_re.
    """
    root = table.get("root_oid") or ""

    if no_filter:
        log_debug(f"Keeping table {root} because --no-filter is active")
        return True

    for p in lld_exclude_roots:
        if root.startswith(p):
            log_debug(f"Dropping table {root} due to lld.exclude_roots")
            return False

    for p in lld_include_roots:
        if root.startswith(p):
            log_debug(f"Keeping table {root} due to lld.include_roots")
            return True

    if lld_filter_re is None:
        log_debug(f"Dropping table {root} because no LLD regex is defined (strict mode)")
        return False

    for col in columns:
        prefix = col.get("prefix") or ""
        module = col.get("module") or ""
        name = col.get("name") or ""
        desc = col.get("description") or ""
        text = " ".join([prefix, module, name, desc])
        if lld_filter_re.search(text):
            log_debug(f"Keeping table {root} because column '{name or prefix}' matched LLD regex")
            return True

    log_debug(f"Dropping table {root} because no columns matched LLD regex")
    return False


def build_forced_table_for_root(
    root: str,
    all_oids: dict[str, dict],
    observium_dir: str | None,
    min_rows: int = 2,
) -> dict | None:
    """
    Build a table entry "forced" for a given root (lld.include_roots).

    - Anchors directly at 'root' (e.g. .1.3.6.1.4.1.24681.1.2.11).
    - Only returns a table if there are at least 'min_rows' distinct indexes.
    - Column detection uses the same "immediate prefix before index" rule.
    """
    oids_under_root = [
        oid for oid in all_oids.keys()
        if oid == root or oid.startswith(root + ".")
    ]
    if not oids_under_root:
        log_debug(f"Forced LLD root {root}: no OIDs found under this subtree")
        return None

    root_parts = split_oid(root)
    row_indices = set()

    for oid in oids_under_root:
        parts = split_oid(oid)
        if len(parts) <= len(root_parts):
            continue
        tail = parts[len(root_parts):]
        if not tail:
            continue
        idx = tail[-1]
        row_indices.add(idx)

    approx_rows = len(row_indices)
    if approx_rows < min_rows:
        log_debug(
            f"Forced LLD root {root}: only {approx_rows} rows found; "
            f"min_rows={min_rows}, skipping"
        )
        return None

    # Use the same column detection/enrichment as normal tables
    base_table = {
        "root_oid": root,
        "approx_rows": approx_rows,
        "approx_columns": 0,
        "example_oids": sorted(oids_under_root)[:5],
    }
    columns = derive_table_columns(base_table, all_oids, observium_dir)
    if not columns:
        log_debug(f"Forced LLD root {root}: no columns derived, skipping")
        return None

    base_table["approx_columns"] = len(columns)
    base_table["columns"] = columns
    log_debug(
        f"Forced LLD root {root}: rows={approx_rows}, columns={len(columns)}, "
        f"examples={len(base_table['example_oids'])}"
    )
    return base_table


# ---------------------------------------------------------------------------
# Main profile builder
# ---------------------------------------------------------------------------

def make_output_path(host: str, explicit_output: str | None) -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(script_dir, "export_yaml")
    os.makedirs(out_dir, exist_ok=True)

    if explicit_output:
        if os.path.dirname(explicit_output):
            os.makedirs(os.path.dirname(explicit_output), exist_ok=True)
            return explicit_output
        return os.path.join(out_dir, explicit_output)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
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
    mib2_filter_re: re.Pattern,
    vendor_filter_re: re.Pattern,
    lld_filter_re: re.Pattern,
    lld_include_roots: list[str],
    lld_exclude_roots: list[str],
    no_filter: bool,
) -> tuple[dict, dict]:
    """
    Walk the given roots, collect OIDs, figure out scalars and tables,
    enrich with MIB names, and return (profile, stats).

    Tables come from two sources:
      - heuristic detection (detect_tables + LLD filters)
      - forced tables for every lld.include_roots (if rows >= 2)
    """
    all_results: list[tuple[str, str, str]] = []
    vendor_root_failed = False

    # First, walk the main roots (.1.3.6.1.2.1 and .1.3.6.1.4.1 plus extras)
    for root in roots:
        # Only the vendor root can be "soft-failed" but we still want to
        # detect that failure so we can later try narrower include_roots.
        suppress = (root == VENDOR_ROOT)
        res = run_snmpwalk(
            host,
            community,
            root,
            port,
            timeout,
            retries,
            suppress_errors=suppress,
        )
        if not res and root == VENDOR_ROOT:
            vendor_root_failed = True
            log_warn(
                "Vendor root walk (.1.3.6.1.4.1) returned no data; "
                "will attempt dedicated walks for each lld.include_roots "
                "subtree under .1.3.6.1.4.1."
            )
        all_results.extend(res)

    # If vendor root walk failed, try each include_roots subtree under .1.3.6.1.4.1
    if vendor_root_failed:
        for inc_root in lld_include_roots:
            if not inc_root.startswith(VENDOR_ROOT + "."):
                continue
            # Only walk if we don't already have data under this subtree
            already_have = any(
                oid == inc_root or oid.startswith(inc_root + ".")
                for oid, _, _ in all_results
            )
            if already_have:
                continue
            log_info(
                f"Attempting dedicated vendor walk for LLD include root {inc_root} "
                "because .1.3.6.1.4.1 walk failed."
            )
            sub_res = run_snmpwalk(
                host,
                community,
                inc_root,
                port,
                timeout,
                retries,
                suppress_errors=True,
            )
            all_results.extend(sub_res)

    # Build final map of all OIDs
    all_oids: dict[str, dict] = {}
    for oid, t, v in all_results:
        all_oids[oid] = {
            "type": t,
            "value": v,
        }

    # Scalars
    scalars: list[dict] = []
    scalar_oids = [o for o in all_oids.keys() if o.endswith(".0")]

    for oid in sorted(scalar_oids):
        entry = all_oids[oid]
        snmp_type = entry.get("type", "")
        value = entry.get("value", "")
        value_class = classify_value_class(snmp_type, value)

        module, name, desc = snmptranslate_enrich(oid, observium_dir)

        if oid.startswith(MIB2_ROOT + "."):
            active_re = mib2_filter_re
        elif oid.startswith(VENDOR_ROOT + "."):
            active_re = vendor_filter_re
        else:
            active_re = vendor_filter_re or mib2_filter_re

        selected = decide_scalar_selected(
            oid=oid,
            name=name,
            description=desc,
            filter_re=active_re,
            no_filter=no_filter,
        )

        scalars.append(
            {
                "oid": oid,
                "sample_type": snmp_type,
                "sample_value": value,
                "value_class": value_class,
                "module": module,
                "name": name,
                "description": desc,
                "selected": selected,
            }
        )

    # Tables: first from heuristic detection + filtering
    tables_meta = detect_tables(list(all_oids.keys()))
    tables_by_root: dict[str, dict] = {}

    for t in tables_meta:
        cols = derive_table_columns(t, all_oids, observium_dir)
        if not cols:
            continue

        if not table_is_interesting(
            table=t,
            columns=cols,
            lld_filter_re=lld_filter_re,
            lld_include_roots=lld_include_roots,
            lld_exclude_roots=lld_exclude_roots,
            no_filter=no_filter,
        ):
            continue

        t_with_cols = dict(t)
        t_with_cols["columns"] = cols
        tables_by_root[t["root_oid"]] = t_with_cols

    # Forced tables for every lld.include_roots (only if rows >= 2)
    for forced_root in lld_include_roots:
        if forced_root in tables_by_root:
            continue
        forced_table = build_forced_table_for_root(
            forced_root,
            all_oids,
            observium_dir,
            min_rows=2,
        )
        if forced_table is not None:
            log_debug(f"Forced LLD table added for root {forced_root}")
            tables_by_root[forced_root] = forced_table

    tables = list(tables_by_root.values())

    profile = {
        "version": "auto_oid_profile_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
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
            "and write a YAML profile suitable for oid2zabbix-template.py.\n"
            "Filtering is entirely driven by --filter-file (mib2/vendor/lld).\n"
            "Always walks .1.3.6.1.2.1 plus vendor roots derived from the profile "
            "(lld.include_roots) and any extra --root.\n"
            "If the .1.3.6.1.4.1 is added via --root and that walk fails, each "
            "lld.include_roots subtree under .1.3.6.1.4.1 is walked individually."
        )
    )
    parser.add_argument("--host", help="SNMP target host/IP")
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
            "Additional root OID to walk (numeric). "
            "Script always walks .1.3.6.1.2.1 by default and also vendor roots "
            "found in lld.include_roots."
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
        "--filter-file",
        default="filters/filters.yaml",
        help="Path to filters YAML file  (default: filters/filters.yaml).",
    )
    parser.add_argument(
        "--no-filter",
        action="store_true",
        help="Disable filters; mark all scalars as selected and keep all tables (except explicit lld.excludes).",
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

    pre_args, _ = parser.parse_known_args()
    if pre_args.version:
        print(f"auto_oid_finder.py version {VERSION}")
        sys.exit(0)

    args = parser.parse_args()
    if not args.host:
        parser.error("the following arguments are required: --host")

    DEBUG = args.debug
    log_info(f"auto_oid_finder.py version: {VERSION}")

    # ------------------------------------------------------------------
    # Load and validate filters.yaml (STRICT)
    # ------------------------------------------------------------------
    filter_path = args.filter_file
    if not os.path.exists(filter_path):
        log_error(f"Filter file '{filter_path}' does not exist.")
        sys.exit(1)

    with open(filter_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    errors: list[str] = []

    # Required top-level sections
    for section in ("mib2", "vendor", "lld"):
        if section not in cfg:
            errors.append(f"Missing required section '{section}' in filter file.")

    if errors:
        for e in errors:
            log_error(e)
        sys.exit(1)

    mib2_cfg = cfg.get("mib2") or {}
    vendor_cfg = cfg.get("vendor") or {}
    lld_cfg = cfg.get("lld") or {}

    # Required keys inside sections
    if "regex" not in mib2_cfg:
        errors.append("mib2.regex is required in filter file.")
    if "regex" not in vendor_cfg:
        errors.append("vendor.regex is required in filter file.")
    if "regex" not in lld_cfg:
        errors.append("lld.regex is required in filter file.")
    if "include_roots" not in lld_cfg:
        errors.append("lld.include_roots is required in filter file (can be empty list).")
    if "exclude_roots" not in lld_cfg:
        errors.append("lld.exclude_roots is required in filter file (can be empty list).")

    if errors:
        for e in errors:
            log_error(e)
        sys.exit(1)

    # Compile regexes
    try:
        mib2_filter_re = re.compile(mib2_cfg["regex"], re.IGNORECASE | re.VERBOSE)
        log_info(f"MIB-2 filter regex: '{mib2_cfg['regex']}'")
    except re.error as e:
        log_error(f"Invalid MIB-2 filter regex: {e}")
        sys.exit(1)

    try:
        vendor_filter_re = re.compile(vendor_cfg["regex"], re.IGNORECASE | re.VERBOSE)
        log_info(f"Vendor filter regex: '{vendor_cfg['regex']}'")
    except re.error as e:
        log_error(f"Invalid Vendor filter regex: {e}")
        sys.exit(1)

    try:
        lld_filter_re = re.compile(lld_cfg["regex"], re.IGNORECASE | re.VERBOSE)
        log_info(f"LLD table filter regex: '{lld_cfg['regex']}'")
    except re.error as e:
        log_error(f"Invalid LLD filter regex: {e}")
        sys.exit(1)

    lld_include_roots = list(lld_cfg.get("include_roots") or [])
    lld_exclude_roots = list(lld_cfg.get("exclude_roots") or [])

    log_info(f"LLD include_roots: {', '.join(lld_include_roots) if lld_include_roots else '(none)'}")
    log_info(f"LLD exclude_roots: {', '.join(lld_exclude_roots) if lld_exclude_roots else '(none)'}")

    # ------------------------------------------------------------------
    # Decide which OID roots to walk (profile-driven)
    # ------------------------------------------------------------------
    # Always walk MIB-2
    roots = [MIB2_ROOT]

    # Add vendor roots from LLD profile: anything under .1.3.6.1.4.1.
    for r in lld_include_roots:
        if r.startswith(VENDOR_ROOT + ".") and r not in roots:
            roots.append(r)

    # Also allow explicit --root overrides/additions
    extra_roots = args.root or []
    for r in extra_roots:
        # allow user to specify without leading dot
        if not r.startswith("."):
            r = "." + r
        if r not in roots:
            roots.append(r)

    log_info(f"Effective roots to walk: {', '.join(roots)}")



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
        lld_filter_re=lld_filter_re,
        lld_include_roots=lld_include_roots,
        lld_exclude_roots=lld_exclude_roots,
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

