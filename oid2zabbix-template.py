#!/usr/bin/env python3
"""
oid2zabbix-template.py
======================

Version: 1.0.16

Take an auto_oid_finder profile YAML and turn it into a Zabbix 7.0 template.

Scalars:
  - stored in profile with:
        oid: ".1.3.6.1..."
        name: "..."
        description: "..."
        value_class: "UNSIGNED|TEXT|..."
        selected: true/false      # <-- from auto_oid_finder
  - by default, we only export scalars where selected == true
  - use --all-scalars to export every scalar regardless of 'selected'

Tables:
  - treated as LLD only
  - master item:
      key:      snmp.raw.walk[<root_oid_compact>]
      snmp_oid: walk[.root_oid]
      name:     RAW SNMP walk for <friendly table label>
  - discovery rule:
      key:      auto.discovery[<root_oid_compact>]
      preprocessing:
        1) JAVASCRIPT: parses raw snmpwalk text and produces JSON:
             { "data": [ { "{#SNMPINDEX}": "...", "{#SOMENAME}": "..." }, ... ] }
        2) DISCARD_UNCHANGED_HEARTBEAT
  - item prototypes:
      key:      <MIB-name>_<oid_tail>[{#SNMPINDEX}]
      name:     <MIB-name or column name> [optional {#SOMENAME}]
      snmp_oid: get[.prefix.{#SNMPINDEX}]

Additional:
  - Global dedup guard on Zabbix keys so we never emit two items or
    prototypes with the same key (scalar vs LLD, or cross-tables).
  - LLD JavaScript is generated per-table and:
      * always extracts {#SNMPINDEX} (last OID segment)
      * optionally extracts a name macro from one TEXT column
"""

import argparse
import os
import re
import sys
import uuid

import yaml

VERSION = "1.0.16"

ZABBIX_EXPORT_VERSION = "7.0"

DEFAULT_VENDOR = "OICTS"
DEFAULT_TEMPLATE_VERSION = "7.0-1"

DEFAULT_HISTORY = "7d"
DEFAULT_TRENDS = "30d"
DEFAULT_DELAY = "5m"
DEFAULT_DISCOVERY_DELAY = "1m"

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
# Helpers
# ---------------------------------------------------------------------------

def normalize_value_type(value_class: str) -> str:
    """
    Map our coarse class (UNSIGNED, TEXT, FLOAT) into Zabbix value_type.
    """
    vc = (value_class or "").upper()
    if vc in ("UNSIGNED", "COUNTER", "GAUGE"):
        return "UNSIGNED"
    if vc in ("FLOAT", "DOUBLE"):
        return "FLOAT"
    if vc in ("CHAR", "STR"):
        return "CHAR"
    return "TEXT"


def safe_template_filename(template_name: str) -> str:
    """
    Turn template name into a filesystem-safe filename.
    """
    base = re.sub(r"[^A-Za-z0-9_.-]+", "_", template_name).strip("_")
    if not base:
        base = "template"
    return f"{base}.yaml"


def make_output_path(template_name: str, explicit_output: str | None) -> str:
    """
    Decide final output file path.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_dir = os.path.join(script_dir, "export_template")
    os.makedirs(default_dir, exist_ok=True)

    if explicit_output:
        if os.path.dirname(explicit_output):
            out_dir = os.path.dirname(explicit_output)
            os.makedirs(out_dir, exist_ok=True)
            return explicit_output
        return os.path.join(default_dir, explicit_output)

    return os.path.join(default_dir, safe_template_filename(template_name))


def build_scalar_key(entry: dict) -> str:
    """
    Build a Zabbix key for a scalar item, preferring the MIB 'name'.
    """
    name = entry.get("name")
    oid = entry.get("oid", "")
    module = entry.get("module")

    if name:
        base = name
    elif module and oid:
        base = f"{module}_{oid.lstrip('.').replace('.', '_')}"
    elif oid:
        base = oid.lstrip(".").replace(".", "_")
    else:
        base = "snmp_scalar"

    if "::" in base:
        base = base.split("::")[-1]

    base = re.sub(r"[^A-Za-z0-9_.-]", "_", base).strip("_")
    if not base:
        base = "snmp_scalar"
    return base


def _oid_tail(prefix: str, max_segments: int = 4) -> str:
    """
    Take a numeric OID prefix and return a compact tail like '4_34_1_3'.
    """
    if not prefix:
        return ""
    parts = prefix.lstrip(".").split(".")
    if not parts:
        return ""
    tail_parts = parts[-max_segments:]
    return "_".join(tail_parts)


def build_column_key(col: dict, root_oid: str) -> str:
    """
    Build a Zabbix key for a table column item prototype.

    To avoid duplicate keys like ipAddressRowStatus[{#SNMPINDEX}] coming
    from different OID trees, we always append a short tail derived from
    the column prefix OID.

    Example:
      name:   ipAddressRowStatus
      prefix: .1.3.6.1.2.1.4.34.1.3

      => key: ipAddressRowStatus_4_34_1_3[{#SNMPINDEX}]
    """
    name = col.get("name")
    prefix = col.get("prefix", "")
    module = col.get("module")

    tail = _oid_tail(prefix) or _oid_tail(root_oid)
    tail_suffix = f"_{tail}" if tail else ""

    if name:
        base = f"{name}{tail_suffix}"
    elif module and prefix:
        base = f"{module}_{prefix.lstrip('.').replace('.', '_')}"
    elif prefix:
        base = prefix.lstrip(".").replace(".", "_")
    else:
        base = root_oid.lstrip(".").replace(".", "_")

    if "::" in base:
        base = base.split("::")[-1]

    base = re.sub(r"[^A-Za-z0-9_.-]", "_", base).strip("_")
    if not base:
        base = "snmp_column"

    return f"{base}[{{#SNMPINDEX}}]"


def make_scalar_item(entry: dict) -> dict:
    """
    Build a Zabbix item from a scalar spec.

    Zabbix async SNMP 7.0 pattern:
      key:      <MIB-name or derived>
      snmp_oid: get[.OID]
    """
    oid = entry.get("oid")
    if not oid:
        raise ValueError("Scalar entry without 'oid' field")

    module = entry.get("module")
    name = entry.get("name")
    desc = entry.get("description")
    value_class = entry.get("value_class") or "TEXT"

    sample_type = entry.get("sample_type")
    sample_value = entry.get("sample_value")

    # Item name (UI)
    if module and name:
        item_name = f"{module}::{name}"
    elif name:
        item_name = name
    else:
        item_name = oid

    # Zabbix item key (internal identifier)
    key = build_scalar_key(entry)

    full_desc = desc or ""
    extra = []
    if sample_type:
        extra.append(f"Sample type: {sample_type}")
    if sample_value is not None:
        extra.append(f"Sample value: {sample_value}")
    if extra:
        block = "Sample info:\n  " + "\n  ".join(extra)
        if full_desc:
            full_desc = full_desc.rstrip() + "\n\n" + block
        else:
            full_desc = block

    item = {
        "uuid": uuid.uuid4().hex,
        "name": item_name,
        "type": "SNMP_AGENT",
        "snmp_oid": f"get[{oid}]",
        "key": key,
        "delay": DEFAULT_DELAY,
        "history": DEFAULT_HISTORY,
        "trends": DEFAULT_TRENDS,
        "value_type": normalize_value_type(value_class),
    }

    if full_desc:
        item["description"] = full_desc

    return item


def _friendly_table_label(root_oid: str, columns: list[dict]) -> str:
    """
    Build a human-friendly label for a table from its columns.

    Preference:
      1) First column with module+name -> "MODULE::name table (OID)"
      2) First column with name        -> "name table (OID)"
      3) Fallback                      -> "SNMP table OID"
    """
    label = None
    for col in columns:
        module = col.get("module")
        name = col.get("name")
        if module and name:
            label = f"{module}::{name} table"
            break
        if name:
            label = f"{name} table"
            break

    if label:
        return f"{label} ({root_oid})"
    return f"SNMP table {root_oid}"


# ---------------------------------------------------------------------------
# LLD JavaScript generator
# ---------------------------------------------------------------------------

def _build_lld_js(name_col_prefix: str | None, macro_key: str | None) -> str:
    """
    Build the per-table LLD JavaScript.

    This version is more forgiving:
      - does NOT rely on a strict regex for the OID
      - works with raw numeric output like:
          .1.3.6.1.2.1.2.2.1.2.2 = STRING: "eth0"
      - still:
          * always extracts {#SNMPINDEX}
          * optionally extracts a name macro (e.g. {#IFDESCR})
    """
    lines: list[str] = []

    # Boilerplate
    lines.append(
        "var lines = value.split('\\n');\n"
        "var indexMap = {};\n"
        "var nameMap = {};\n"
    )

    if name_col_prefix:
        lines.append(f'var NAME_COL_PREFIX = "{name_col_prefix}";\n')
    else:
        lines.append("var NAME_COL_PREFIX = null;\n")

    if macro_key:
        lines.append(f'var MACRO_KEY = "{macro_key}";\n')
    else:
        lines.append("var MACRO_KEY = null;\n")

    # Main parsing loop
    lines.append(
        """
for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (!line) {
        continue;
    }

    // We expect something like:
    //   .1.3.6.1.2.1.2.2.1.2.2 = STRING: "eth0"
    var eqPos = line.indexOf(" = ");
    if (eqPos === -1) {
        continue;
    }

    var oidPart = line.substring(0, eqPos).trim();
    var rest = line.substring(eqPos + 3).trim(); // after " = "

    // Normalize OID: if it ever has a MIB name, strip it, but
    // in your case it's already numeric (.1.3.6....)
    var oidNorm = oidPart;
    var dbl = oidNorm.indexOf("::");
    if (dbl !== -1) {
        oidNorm = oidNorm.substring(dbl + 2);
    }

    // Split on '.' and take the last numeric segment as index
    var parts = oidNorm.split(".").filter(function(p) { return p.length > 0; });
    if (parts.length < 1) {
        continue;
    }

    var index = parts[parts.length - 1];
    if (!/^\\d+$/.test(index)) {
        continue;
    }

    // Record that we saw this index
    indexMap[index] = true;

    // Parse value, strip "TYPE: " and quotes
    var rawVal = rest;
    var mt = rest.match(/^[A-Z0-9\\-]+:\\s*(.*)$/);
    if (mt) {
        rawVal = mt[1];
    }
    rawVal = rawVal.replace(/^"(.*)"$/, "$1");

    // If this OID belongs to the chosen "name" column, store name
    if (NAME_COL_PREFIX) {
        // NAME_COL_PREFIX is numeric (e.g. ".1.3.6.1.2.1.2.2.1.2")
        if (oidPart.indexOf(NAME_COL_PREFIX + ".") === 0 ||
            oidPart === NAME_COL_PREFIX) {
            nameMap[index] = rawVal;
        }
    }
}
"""
    )

    # Build final LLD JSON: [{"{#SNMPINDEX}": "1", "{#IFDESCR}": "eth0"}, ...]
    lines.append(
        """
var data = [];
for (var idx in indexMap) {
    if (!indexMap.hasOwnProperty(idx)) {
        continue;
    }
    var row = { "{#SNMPINDEX}": idx };
    if (MACRO_KEY && Object.prototype.hasOwnProperty.call(nameMap, idx)) {
        row[MACRO_KEY] = nameMap[idx];
    }
    data.push(row);
}

return JSON.stringify({ "data": data });
"""
    )

    return "".join(lines)

# ---------------------------------------------------------------------------
# Table → LLD builder
# ---------------------------------------------------------------------------

def _pick_name_column(columns: list[dict]) -> tuple[str | None, str | None]:
    """
    Heuristic to pick a "name" column for LLD macro enrichment.

    Returns (name_col_prefix, macro_key) where:
      - name_col_prefix is the numeric OID prefix for that column
      - macro_key is something like "{#IFDESCR}" or "{#NAME}"

    If no suitable column is found, returns (None, None).
    """
    # Candidate keywords in column name/description
    KEYWORDS_PRIMARY = [
        "name", "descr", "description", "label",
        "mount", "volume", "disk", "filesystem", "fs",
        "interface", "ifname", "port", "slot",
    ]
    KEYWORDS_SECONDARY = [
        "index", "id", "entry",
    ]

    best_col = None
    best_score = -1

    for col in columns:
        prefix = col.get("prefix")
        if not prefix:
            continue

        value_class = (col.get("value_class") or "").upper()
        sample_type = (col.get("sample_type") or "").upper()
        name = (col.get("name") or "").lower()
        desc = (col.get("description") or "").lower()

        # Only consider TEXTish columns
        if not (
            value_class == "TEXT"
            or "OCTET STRING" in sample_type
        ):
            continue

        score = 0
        for kw in KEYWORDS_PRIMARY:
            if kw in name or kw in desc:
                score += 5
        for kw in KEYWORDS_SECONDARY:
            if kw in name or kw in desc:
                score += 1

        # Light bonus if column name ends with "Name" or "Descr"
        if name.endswith("name") or name.endswith("descr"):
            score += 3

        if score > best_score:
            best_score = score
            best_col = col

    if not best_col or best_score <= 0:
        return None, None

    prefix = best_col.get("prefix")
    raw_name = best_col.get("name") or "NAME"
    macro_id = re.sub(r"[^A-Za-z0-9]", "_", raw_name.upper()) or "NAME"
    macro_key = f"{{#{macro_id}}}"

    log_debug(
        f"Chosen name column for LLD: prefix={prefix}, "
        f"name={best_col.get('name')}, macro={macro_key}"
    )

    return prefix, macro_key


def make_table_lld(table: dict) -> tuple[list[dict], dict]:
    """
    Build master SNMP walk item + discovery rule for a given table entry.

    Returns (master_items, discovery_rule).

    Zabbix async SNMP pattern for master:
      key:      snmp.raw.walk[1_3_6_1_2_1_25_3_3_1]
      snmp_oid: walk[.1.3.6.1.2.1.25.3.3.1]

    We only put the table root OID in walk[] to avoid snmp_oid being too long.
    """
    root_oid = table.get("root_oid")
    if not root_oid:
        raise ValueError("Table entry missing 'root_oid'")

    approx_rows = table.get("approx_rows", 0)
    approx_cols = table.get("approx_columns", 0)
    example_oids = table.get("example_oids") or []
    columns = table.get("columns") or []

    # Build a friendly label for UI names
    table_label = _friendly_table_label(root_oid, columns)

    # Try to pick a "name" column for macros
    name_col_prefix, macro_key = _pick_name_column(columns)
    js_script = _build_lld_js(name_col_prefix, macro_key)

    # Safe root ID for discovery key
    safe_root = root_oid.lstrip(".").replace(".", "_")
    discovery_key = f"auto.discovery[{safe_root}]"

    master_key = f"snmp.raw.walk[{safe_root}]"
    walk_expr = f"walk[{root_oid}]"

    desc_lines = [
        f"Auto-discovered SNMP table rooted at {root_oid}.",
        f"Approx rows: {approx_rows}, approx columns: {approx_cols}.",
    ]
    if example_oids:
        desc_lines.append("Example OIDs:")
        for eo in example_oids[:5]:
            desc_lines.append(f"  - {eo}")

    if name_col_prefix and macro_key:
        desc_lines.append(
            f"LLD name macro {macro_key} derived from column prefix {name_col_prefix}."
        )

    desc = "\n".join(desc_lines)

    master_item = {
        "uuid": uuid.uuid4().hex,
        "name": f"RAW SNMP walk for {table_label}",
        "type": "SNMP_AGENT",
        "snmp_oid": walk_expr,
        "key": master_key,
        "delay": DEFAULT_DELAY,
        "history": "0d",
        "trends": "0",
        "value_type": "TEXT",
        "description": desc,
        "tags": [
            {"tag": "component", "value": "RAW"},
        ],
    }

    dr = {
        "uuid": uuid.uuid4().hex,
        "name": f"Auto LLD for {table_label}",
        "type": "DEPENDENT",
        "key": discovery_key,
        "delay": DEFAULT_DISCOVERY_DELAY,
        "master_item": {"key": master_key},
        "description": desc,
        "preprocessing": [
            {
                "type": "JAVASCRIPT",
                "parameters": [js_script],
            },
            {
                "type": "DISCARD_UNCHANGED_HEARTBEAT",
                "parameters": ["1h"],
            },
        ],
        "item_prototypes": [],
        "trigger_prototypes": [],
    }

    for col in columns:
        prefix = col.get("prefix")
        if not prefix:
            continue

        module = col.get("module")
        name = col.get("name")
        col_desc = col.get("description")
        sample_type = col.get("sample_type")
        value_class = col.get("value_class") or "TEXT"

        # Base name from MIB/module
        if module and name:
            base_name = f"{module}::{name}"
        elif name:
            base_name = name
        else:
            base_name = prefix

        # Clean prototype name:
        # - If we have a name macro: IF-MIB::ifInOctets [eth0]
        # - Otherwise: IF-MIB::ifInOctets [{#SNMPINDEX}]
        if macro_key:
            proto_name = f"{base_name} [{macro_key}]"
        else:
            proto_name = f"{base_name} [{{#SNMPINDEX}}]"


        col_snmp_oid = f"{prefix}.{{#SNMPINDEX}}"
        proto_key = build_column_key(col, root_oid)

        full_desc = col_desc or ""
        extra = []
        if sample_type:
            extra.append(f"Sample type: {sample_type}")
        if extra:
            block = "Sample info:\n" + "\n".join(f"  {line}" for line in extra)
            if full_desc:
                full_desc = full_desc.rstrip() + "\n\n" + block
            else:
                full_desc = block

        proto = {
            "uuid": uuid.uuid4().hex,
            "name": proto_name,
            "type": "SNMP_AGENT",
            "snmp_oid": f"get[{col_snmp_oid}]",
            "key": proto_key,
            "delay": DEFAULT_DELAY,
            "history": DEFAULT_HISTORY,
            "trends": DEFAULT_TRENDS,
            "value_type": normalize_value_type(value_class),
        }

        if full_desc:
            proto["description"] = full_desc

        dr["item_prototypes"].append(proto)

    return [master_item], dr


def _norm_oid(oid: str) -> str:
    if not oid:
        return ""
    return oid if oid.startswith(".") else "." + oid


def build_zabbix_template(
    profile: dict,
    template_name: str,
    group_name: str,
    vendor: str,
    template_version: str,
    include_scalars: bool = True,
    include_tables: bool = True,
    min_rows: int = 2,
    min_cols: int = 2,
    all_scalars: bool = False,
) -> tuple[dict, dict]:
    """
    Build the full Zabbix export structure from an auto_oid_finder profile.

    IMPORTANT:
      - Any scalar whose OID lives under a table root is SKIPPED as a
        regular item, to avoid having both a normal item and an LLD
        item for the same data.
      - By default, we only export scalars where entry['selected'] is True.
        Use all_scalars=True to ignore that flag and export everything.
      - We enforce global uniqueness of item keys across:
          * scalar items
          * table master items
          * LLD item prototypes
    """
    scalars = profile.get("scalars") or []
    tables = profile.get("tables") or []

    items: list[dict] = []
    discovery_rules: list[dict] = []

    # Global set of used Zabbix keys
    used_keys: set[str] = set()

    # Collect table roots (normalized)
    table_roots = []
    for t in tables:
        r = t.get("root_oid")
        if r:
            table_roots.append(_norm_oid(r))
    log_debug(f"Table roots for scalar filtering: {table_roots}")

    def scalar_belongs_to_table(oid: str) -> bool:
        if not oid:
            return False
        n = _norm_oid(oid)
        for r in table_roots:
            if not r:
                continue
            # if scalar OID is equal to or under the table root subtree
            if n == r or n.startswith(r + "."):
                return True
        return False

    scalar_count = 0
    total_scalars = len(scalars)

    if include_scalars:
        for s in scalars:
            oid = s.get("oid")
            if not oid:
                continue

            # skip scalars that belong to table subtrees
            if scalar_belongs_to_table(oid):
                log_debug(
                    f"Skipping scalar {oid} because it is under table root subtree"
                )
                continue

            if not all_scalars:
                # honor 'selected' from profile (default True for legacy profiles)
                if not s.get("selected", True):
                    log_debug(f"Skipping scalar {oid} because selected=False")
                    continue

            try:
                item = make_scalar_item(s)
            except Exception as e:
                log_warn(f"Skipping scalar {s.get('oid')}: {e}")
                continue

            k = item.get("key")
            if k and k in used_keys:
                log_warn(
                    f"Skipping scalar {oid} because key '{k}' "
                    f"is already used by another item"
                )
                continue

            if k:
                used_keys.add(k)
            items.append(item)
            scalar_count += 1

    table_count = 0
    lld_count = 0
    if include_tables:
        for t in tables:
            root_oid = t.get("root_oid") or ""

            # Skip generic enterprise roots like .1.3.6.1.4.1.X (no real table)
            parts = root_oid.lstrip(".").split(".") if root_oid else []
            if (
                len(parts) == 7
                and parts[:6] == ["1", "3", "6", "1", "4", "1"]
            ):
                log_debug(f"Skipping generic enterprise root table {root_oid}")
                continue

            rows = t.get("approx_rows", 0)
            cols = t.get("approx_columns", 0)
            if rows < min_rows or cols < min_cols:
                continue

            try:
                masters, dr = make_table_lld(t)
            except Exception as e:
                log_warn(f"Skipping table at {t.get('root_oid')}: {e}")
                continue

            # Dedup for master items
            real_masters: list[dict] = []
            for m in masters:
                mk = m.get("key")
                if mk and mk in used_keys:
                    log_warn(
                        f"Skipping master item for table {t.get('root_oid')}: "
                        f"duplicate key '{mk}'"
                    )
                    continue
                if mk:
                    used_keys.add(mk)
                real_masters.append(m)

            items.extend(real_masters)

            # Dedup for item prototypes
            prototypes = dr.get("item_prototypes") or []
            real_protos: list[dict] = []
            for p in prototypes:
                pk = p.get("key")
                if pk and pk in used_keys:
                    log_warn(
                        f"Skipping item prototype for table {t.get('root_oid')}: "
                        f"duplicate key '{pk}'"
                    )
                    continue
                if pk:
                    used_keys.add(pk)
                real_protos.append(p)

            dr["item_prototypes"] = real_protos

            discovery_rules.append(dr)
            if real_protos:
                lld_count += 1

        # Drop discovery rules that ended up with zero item prototypes
        discovery_rules = [dr for dr in discovery_rules if dr.get("item_prototypes")]
        table_count = len(discovery_rules)
        lld_count = table_count

    macros = [
        {
            "macro": "{$SNMP_COMMUNITY}",
            "value": profile.get("target", {}).get("community", "public"),
        }
    ]

    tmpl_group = {
        "uuid": uuid.uuid4().hex,
        "name": group_name,
    }

    template = {
        "uuid": uuid.uuid4().hex,
        "template": template_name,
        "name": template_name,
        "vendor": {
            "name": vendor,
            "version": template_version,
        },
        "groups": [{"name": group_name}],
        "items": items,
        "macros": macros,
    }

    if discovery_rules:
        template["discovery_rules"] = discovery_rules

    data = {
        "zabbix_export": {
            "version": ZABBIX_EXPORT_VERSION,
            "template_groups": [tmpl_group],
            "templates": [template],
        }
    }

    stats = {
        "scalar_items": scalar_count,
        "scalar_total": total_scalars,
        "tables_used": table_count,
        "discovery_rules": lld_count,
        "items_total": len(items),
    }

    return data, stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global DEBUG

    parser = argparse.ArgumentParser(
        description=(
            "Build a Zabbix 7.0 template from an auto_oid_finder profile YAML.\n"
            "Scalars: key = MIB name, snmp_oid = get[OID].\n"
            "Tables: master item snmp_oid = walk[root], item prototypes\n"
            "snmp_oid = get[prefix.{#SNMPINDEX}], key = MIBname_OIDtail[{#SNMPINDEX}].\n"
            "Scalars under table roots are NOT exported as regular items.\n"
            "By default, only scalars with selected=true are exported; use "
            "--all-scalars to include every scalar.\n"
            "LLD JavaScript is generated per-table and always extracts {#SNMPINDEX}; "
            "it also optionally adds a name macro like {#IFDESCR} when a suitable "
            "TEXT column is available."
        )
    )
    parser.add_argument(
        "profile",
        nargs="?",
        help="auto_oid_finder YAML profile",
    )
    parser.add_argument(
        "-n",
        "--name",
        help="Template name (default: auto from profile target.host)",
    )
    parser.add_argument(
        "-g",
        "--group",
        default="Templates/Auto",
        help="Template group name (default: Templates/Auto)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help=(
            "Output YAML file. If just a filename, it will be placed under "
            "./export_template/ by default."
        ),
    )
    parser.add_argument(
        "--vendor",
        help=f"Vendor name (default: {DEFAULT_VENDOR})",
    )
    parser.add_argument(
        "--template-version",
        help=f"Template version string (default: {DEFAULT_TEMPLATE_VERSION})",
    )
    parser.add_argument(
        "--no-scalars",
        action="store_true",
        help="Do not include scalar OIDs as items",
    )
    parser.add_argument(
        "--no-tables",
        action="store_true",
        help="Do not include LLD tables",
    )
    parser.add_argument(
        "--min-rows",
        type=int,
        default=2,
        help="Minimum approx_rows for a table to be included (default: 2)",
    )
    parser.add_argument(
        "--min-cols",
        type=int,
        default=2,
        help="Minimum approx_columns for a table to be included (default: 2)",
    )
    parser.add_argument(
        "--all-scalars",
        action="store_true",
        help="Include ALL scalar OIDs (ignore 'selected' flag in profile)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show script version and exit",
    )

    pre_args, _ = parser.parse_known_args()
    if pre_args.version:
        print(f"oid2zabbix-template.py version: {VERSION}")
        sys.exit(0)

    args = parser.parse_args()
    if not args.profile:
        parser.error("the following arguments are required: profile")

    DEBUG = args.debug
    log_info(f"oid2zabbix-template.py version: {VERSION}")

    profile_path = args.profile
    if not os.path.exists(profile_path):
        log_error(f"Profile file '{profile_path}' does not exist.")
        sys.exit(1)

    with open(profile_path, "r", encoding="utf-8") as f:
        profile = yaml.safe_load(f) or {}

    target = profile.get("target", {})
    host = target.get("host", "unknown-host")

    template_name = args.name or f"Template SNMP Auto {host}"
    group_name = args.group

    vendor = args.vendor or DEFAULT_VENDOR
    template_version = args.template_version or DEFAULT_TEMPLATE_VERSION

    out_path = make_output_path(template_name, args.output)

    log_info(f"Profile file:      {profile_path}")
    log_info(f"Template name:     {template_name}")
    log_info(f"Template group:    {group_name}")
    log_info(f"Vendor:            {vendor}")
    log_info(f"Template version:  {template_version}")
    log_info(f"Output file:       {out_path}")
    log_info(f"Include scalars:   {not args.no_scalars}")
    log_info(f"Include tables:    {not args.no_tables}")
    log_info(f"All scalars:       {args.all_scalars}")
    log_info(f"Min table rows:    {args.min_rows}")
    log_info(f"Min table columns: {args.min_cols}")

    zbx_yaml, stats = build_zabbix_template(
        profile=profile,
        template_name=template_name,
        group_name=group_name,
        vendor=vendor,
        template_version=template_version,
        include_scalars=not args.no_scalars,
        include_tables=not args.no_tables,
        min_rows=args.min_rows,
        min_cols=args.min_cols,
        all_scalars=args.all_scalars,
    )

    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            zbx_yaml,
            f,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )

    print("\n[summary]")
    print(f"  Template name:      {template_name}")
    print(f"  Template group:     {group_name}")
    print(f"  Vendor:             {vendor}")
    print(f"  Template version:   {template_version}")
    print(f"  Output file:        {out_path}")
    print(f"  Scalar items:       {stats['scalar_items']} / {stats['scalar_total']} in profile")
    print(f"  Tables used:        {stats['tables_used']}")
    print(f"  Discovery rules:    {stats['discovery_rules']}")
    print(f"  Total items:        {stats['items_total']}")
    print("[info] Zabbix template YAML ready for import into Zabbix 7.0.")


if __name__ == "__main__":
    main()

