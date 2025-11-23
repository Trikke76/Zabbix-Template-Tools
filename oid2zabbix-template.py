#!/usr/bin/env python3
"""
oid2zabbix-template.py
======================

Version: 1.0.6

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
  - discovery rule:
      key: auto.discovery[<root_oid_compact>]
  - item prototypes:
      key:      <MIB-name>_<oid_tail>[{#SNMPINDEX}]
      snmp_oid: get[.prefix.{#SNMPINDEX}]
"""

import argparse
import os
import re
import sys
import uuid

import yaml

VERSION = "1.0.6"

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

    desc = "\n".join(desc_lines)

    master_item = {
        "uuid": uuid.uuid4().hex,
        "name": f"RAW SNMP walk {root_oid}",
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
        "name": f"Auto LLD for {root_oid}",
        "type": "DEPENDENT",
        "key": discovery_key,
        "delay": DEFAULT_DISCOVERY_DELAY,
        "master_item": {"key": master_key},
        "description": desc,
        "preprocessing": [
            {
                "type": "DISCARD_UNCHANGED_HEARTBEAT",
                "parameters": ["1h"],
            }
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

        if module and name:
            proto_name = f"{module}::{name}"
        elif name:
            proto_name = name
        else:
            proto_name = prefix

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
    """
    scalars = profile.get("scalars") or []
    tables = profile.get("tables") or []

    items: list[dict] = []
    discovery_rules: list[dict] = []

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
            items.append(item)
            scalar_count += 1

    table_count = 0
    lld_count = 0
    if include_tables:
        for t in tables:
            rows = t.get("approx_rows", 0)
            cols = t.get("approx_columns", 0)
            if rows < min_rows or cols < min_cols:
                continue

            try:
                masters, dr = make_table_lld(t)
            except Exception as e:
                log_warn(f"Skipping table at {t.get('root_oid')}: {e}")
                continue

            items.extend(masters)
            discovery_rules.append(dr)
            table_count += 1
            lld_count += 1

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
            "--all-scalars to include every scalar."
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
        print(f"oid2zabbix-template.py version {VERSION}")
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

