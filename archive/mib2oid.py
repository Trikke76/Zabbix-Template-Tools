#!/usr/bin/env python3
"""
mib2oid.py
==========

Extract interesting scalar OIDs from a MIB file using net-snmp's snmptranslate
and write them to a YAML "OID catalog" for later consumption by
oid2zabbix-template.py and auto_oid_finder.py.

VERSION = "1.0.0"

Backend flow:

  1) Pre-flight: check core MIB support
     - Uses snmptranslate to resolve sysUpTime.0 from SNMPv2-MIB.
     - If this fails, we bail out with a clear error message and
       suggest running mib2oid.py on a Linux host with full net-snmp.

  2) Primary: net-snmp snmptranslate
     - Uses MIBDIRS to add the MIB directory (or known system dirs) without
       losing system MIBs, subject to net-snmp behavior.

  3) Fallback (optional, interactive): Perl SNMP::MIB::Compiler
     - If snmptranslate cannot load the module:
       * If Perl or SNMP::MIB::Compiler is missing → skip Perl step.
       * Otherwise ask:
           "Try Perl SNMP::MIB::Compiler fallback first? [y/N]: "
       * We only use this as a compile test (no OID extraction via Perl yet).

  4) Final fallback (optional, interactive): fixmymib.py
     - Ask:
         "Try to auto-repair this MIB with fixmymib.py and retry? [y/N]: "
     - If yes:
         * Run fixmymib.py <orig_mib_file> (unless the file is already in fixed_mibs/).
         * Expect fixed_mibs/<MODULE>.mib.
         * Retry snmptranslate against the fixed MIB.
     - If that still fails OR user says no:
         * Print a clear message suggesting auto_oid_finder.py or manual fixmymib.py.

Output:

  YAML file in oid_catalogs/:
    oid_catalogs/oids_<MIBNAME>_<YYYYmmddHHMM>.yaml

"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Optional

import yaml

DEBUG = False

DEFAULT_OUTPUT_DIR = "oid_catalogs"

DEFAULT_FILTER_PATTERN = (
    r"(temp|temperature|thermal|fan|cool|psu|ps|power|volt|current|amps|"
    r"cpu|load|usage|util|mem|memory|swap|disk|hdd|ssd|raid|array|lun|"
    r"error|errors|fail|failed|status|state|health|alarm|alert|"
    r"ups|battery|runtime|charge|"
    r"toner|ink|drum|tray|paper|jam)"
)


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
# Environment sanity check (MIB support)
# ---------------------------------------------------------------------------

def check_mib_support() -> bool:
    """
    Quick sanity check for working MIB loading via snmptranslate.

    We test the ability to resolve sysUpTime.0 from SNMPv2-MIB.
    If this fails, MIB parsing will never work reliably on this system.
    """
    import shutil as _shutil
    import os as _os

    if _shutil.which("snmptranslate") is None:
        log_error("snmptranslate not found in PATH. Install net-snmp-utils.")
        return False

    env = _os.environ.copy()

    # Force MIB loading
    env.setdefault("MIBS", "+ALL")

    # Prepend common MIB directories (Linux, MacPorts, Homebrew, macOS)
    known_dirs = [
        "/usr/share/snmp/mibs",
        "/usr/local/share/snmp/mibs",
        "/opt/local/share/snmp/mibs",
        "/opt/homebrew/share/snmp/mibs",
    ]
    existing = env.get("MIBDIRS", "")

    dirs = [d for d in known_dirs if _os.path.isdir(d)]
    if existing:
        dirs.append(existing)
    if dirs:
        env["MIBDIRS"] = ":".join(dirs)

    cmd = ["snmptranslate", "-m", "+SNMPv2-MIB", "-On", "sysUpTime.0"]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
    except Exception as e:
        log_error(f"Failed to run snmptranslate for MIB check: {e}")
        return False

    out = proc.stdout.strip()
    err = proc.stderr.strip()

    # Success looks like: .1.3.6.1.2.1.1.3.0
    if out.startswith(".1.3.6.1.2.1.1.3"):
        log_debug("MIB support check passed: sysUpTime.0 resolved correctly.")
        return True

    log_error("Your net-snmp installation cannot load core MIBs.")
    log_error("snmptranslate could NOT resolve sysUpTime.0 from SNMPv2-MIB.")
    log_error("This usually means:")
    log_error("  - net-snmp was compiled without MIB support, or")
    log_error("  - MIBDIRS does not point to valid MIB directories, or")
    log_error("  - on macOS, the SNMP stack is crippled and ignores MIBs.")
    log_error("")
    log_error("Run mib2oid.py on a Linux system with full MIB support.")
    log_error("On such a system, this command should work:")
    log_error("  snmptranslate -m +SNMPv2-MIB -On sysUpTime.0")
    log_error("  → .1.3.6.1.2.1.1.3.0")

    if err:
        print("\n[snmptranslate stderr]")
        print(err)

    return False


# ---------------------------------------------------------------------------
# Module detection & OBJECT-TYPE scanning
# ---------------------------------------------------------------------------

def detect_module_name(mib_path: str) -> Optional[str]:
    """
    Try to detect the MIB module name from 'DEFINITIONS ::= BEGIN' line.
    """
    try:
        with open(mib_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception as e:
        log_error(f"Failed to read MIB file {mib_path}: {e}")
        return None

    m = re.search(
        r"^\s*([A-Za-z0-9_-]+)\s+DEFINITIONS\s+::=\s+BEGIN",
        text,
        re.MULTILINE | re.IGNORECASE,
    )
    if not m:
        return None
    return m.group(1)


def scan_object_type_names(mib_path: str) -> list[str]:
    """
    Scan the MIB text for lines like:
      fooScalar OBJECT-TYPE
    Returns a de-duplicated list of names.
    """
    try:
        with open(mib_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception as e:
        log_error(f"Failed to read MIB file {mib_path}: {e}")
        return []

    names: list[str] = []
    seen = set()

    pattern = re.compile(
        r"^\s*([A-Za-z0-9_-]+)\s+OBJECT-TYPE\b", re.MULTILINE | re.IGNORECASE
    )

    for m in pattern.finditer(text):
        name = m.group(1)
        if name not in seen:
            seen.add(name)
            names.append(name)

    return names


# ---------------------------------------------------------------------------
# snmptranslate wrapper
# ---------------------------------------------------------------------------

def check_snmptranslate() -> Optional[str]:
    path = shutil.which("snmptranslate")
    if not path:
        log_error(
            "snmptranslate not found in PATH. Please install net-snmp tools.\n"
            "On RHEL/CentOS:   yum install net-snmp net-snmp-utils\n"
            "On Debian/Ubuntu: apt install snmp\n"
        )
        return None
    return path


def run_snmptranslate(args: list[str], mib_dir: Optional[str] = None) -> tuple[int, str, str]:
    """
    Run snmptranslate with given args.

    IMPORTANT:
      - We DO NOT use -M to override the MIB search path.
      - Instead, if mib_dir is given, we set MIBDIRS to that directory
        (possibly in addition to whatever the user already has).
    """
    cmd = ["snmptranslate"] + args
    log_debug(f"snmptranslate cmd: {' '.join(cmd)}")

    env = os.environ.copy()
    if mib_dir:
        existing = env.get("MIBDIRS", "")
        if existing:
            env["MIBDIRS"] = f"{mib_dir}:{existing}"
        else:
            env["MIBDIRS"] = mib_dir

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
    except Exception as e:
        log_error(f"Failed to run snmptranslate: {e}")
        return (1, "", str(e))
    return (proc.returncode, proc.stdout, proc.stderr)


def get_object_details(module: str, name: str, mib_dir: str) -> Optional[str]:
    """
    Use 'snmptranslate -Td -OS' to get a detailed OBJECT-TYPE dump.
    """
    args = [
        "-m",
        f"+{module}",
        "-P",
        "e",
        "-Td",
        "-OS",
        f"{module}::{name}",
    ]
    rc, out, err = run_snmptranslate(args, mib_dir=mib_dir)
    if rc != 0 or not out.strip():
        log_debug(
            f"snmptranslate -Td failed for {module}::{name}, rc={rc}, stderr={err.strip()}"
        )
        return None
    return out


def get_scalar_numeric_oid(module: str, name: str, mib_dir: str) -> Optional[str]:
    """
    Resolve numeric OID for a scalar: MODULE::name.0
    """
    oid_text = f"{module}::{name}.0"
    args = [
        "-m",
        f"+{module}",
        "-P",
        "e",
        "-On",
        oid_text,
    ]
    rc, out, err = run_snmptranslate(args, mib_dir=mib_dir)
    if rc != 0 or not out.strip():
        log_debug(
            f"snmptranslate -On failed for {oid_text}, rc={rc}, stderr={err.strip()}"
        )
        return None
    return out.strip().splitlines()[0].strip()


# ---------------------------------------------------------------------------
# Parse snmptranslate -Td output
# ---------------------------------------------------------------------------

def parse_td_block(td_text: str) -> dict:
    """
    Parse the output of `snmptranslate -Td -OS MODULE::name`.

    Returns a dict with keys:
      - name, module, syntax, enums{}, description, access, status,
        parent, index, is_table, is_column
    """
    lines = [ln.rstrip() for ln in td_text.splitlines() if ln.strip()]

    result = {
        "name": None,
        "module": None,
        "syntax": None,
        "enums": {},
        "description": None,
        "access": None,
        "status": None,
        "parent": None,
        "index": None,
        "is_table": False,
        "is_column": False,
    }

    if not lines:
        return result

    header = lines[0].strip()
    m = re.match(r"^\s*([A-Za-z0-9_-]+)::([A-Za-z0-9_-]+)", header)
    if m:
        result["module"] = m.group(1)
        result["name"] = m.group(2)

    syntax_lines: list[str] = []
    in_syntax = False

    desc_lines: list[str] = []
    in_desc = False

    for ln in lines[1:]:
        stripped = ln.lstrip()

        # SYNTAX block
        if stripped.upper().startswith("SYNTAX "):
            in_syntax = True
            syntax_lines = [stripped]
            continue

        if in_syntax:
            if re.match(
                r"^(MAX-ACCESS|ACCESS|STATUS|DESCRIPTION|INDEX|UNITS|REFERENCE|DEFVAL|\S*::=)",
                stripped,
                re.IGNORECASE,
            ):
                in_syntax = False
            else:
                syntax_lines.append(stripped)
                continue

        # ACCESS / MAX-ACCESS
        if stripped.upper().startswith("MAX-ACCESS"):
            parts = stripped.split()
            if len(parts) >= 2:
                result["access"] = " ".join(parts[1:])
            continue
        if stripped.upper().startswith("ACCESS"):
            parts = stripped.split()
            if len(parts) >= 2:
                result["access"] = " ".join(parts[1:])
            continue

        # STATUS
        if stripped.upper().startswith("STATUS"):
            parts = stripped.split()
            if len(parts) >= 2:
                result["status"] = " ".join(parts[1:])
            continue

        # DESCRIPTION
        if stripped.upper().startswith("DESCRIPTION"):
            in_desc = True
            desc_lines = []
            idx = stripped.find('"')
            if idx >= 0:
                after = stripped[idx + 1 :]
                desc_lines.append(after)
                if after.rstrip().endswith('"') and not after.rstrip().endswith('\\"'):
                    in_desc = False
            continue

        if in_desc:
            if '"' in stripped:
                quote_pos = stripped.find('"')
                desc_lines.append(stripped[:quote_pos])
                in_desc = False
            else:
                desc_lines.append(stripped)
            continue

    # SYNTAX / enums
    if syntax_lines:
        syntax_text = " ".join(syntax_lines)
        if syntax_text.upper().startswith("SYNTAX "):
            syntax_text = syntax_text[7:].strip()
        result["syntax"] = syntax_text

        if re.search(r"\bSEQUENCE\s+OF\b", syntax_text, re.IGNORECASE):
            result["is_table"] = True

        enum_block_match = re.search(r"\{(.+?)\}", syntax_text)
        if enum_block_match:
            enum_block = enum_block_match.group(1)
            enum_map: dict[str, str] = {}
            for label, val in re.findall(
                r"([A-Za-z0-9_-]+)\s*\(\s*(-?\d+)\s*\)", enum_block
            ):
                v_str = str(int(val))
                if v_str not in enum_map:
                    enum_map[v_str] = label
            result["enums"] = enum_map

    # DESCRIPTION
    if desc_lines:
        desc = "\n".join(desc_lines).rstrip()
        result["description"] = desc

    # Parent / index from ::= { parent idx }
    parent = None
    idx_val = None
    for ln in lines:
        stripped = ln.lstrip()
        m = re.search(
            r"::=\s*\{\s*([A-Za-z0-9_.-]+)\s+(\d+)\s*\}", stripped
        )
        if m:
            parent = m.group(1)
            idx_val = int(m.group(2))
            break

    result["parent"] = parent
    result["index"] = idx_val
    if parent and parent.endswith("Entry"):
        result["is_column"] = True

    return result


# ---------------------------------------------------------------------------
# SYNTAX -> Zabbix value type
# ---------------------------------------------------------------------------

def guess_zabbix_value_type(syntax: Optional[str]) -> str:
    """
    Rough heuristic mapping of SNMP SYNTAX to a Zabbix value_type hint.

    Returns:
        "UNSIGNED", "FLOAT", or "TEXT"
    """
    if not syntax:
        return "TEXT"
    s = syntax.upper()
    if any(
        kw in s
        for kw in [
            "INTEGER",
            "INTEGER32",
            "UNSIGNED",
            "UNSIGNED32",
            "GAUGE",
            "GAUGE32",
            "COUNTER",
            "COUNTER32",
            "COUNTER64",
            "TIMETICKS",
        ]
    ):
        return "UNSIGNED"
    if "FLOAT" in s or "DOUBLE" in s:
        return "FLOAT"
    if any(
        kw in s
        for kw in [
            "OCTET STRING",
            "DISPLAYSTRING",
            "BITS",
            "IPADDRESS",
            "NETWORKADDRESS",
            "PHYSADDRESS",
            "MACADDRESS",
        ]
    ):
        return "TEXT"
    return "TEXT"


# ---------------------------------------------------------------------------
# Main worker: build OID catalog
# ---------------------------------------------------------------------------

def build_oid_catalog(
    mib_file: str,
    module: str,
    mib_dir: str,
    output_path: str,
    filter_regex: Optional[re.Pattern],
) -> None:
    """
    Core logic: scan OBJECT-TYPEs, query snmptranslate, build YAML catalog.
    """
    all_names = scan_object_type_names(mib_file)
    log_info(f"OBJECT-TYPE definitions found: {len(all_names)}")

    if not all_names:
        log_warn("No OBJECT-TYPEs found. OID catalog will be empty.")
        data = {
            "mib": module,
            "source_file": os.path.basename(mib_file),
            "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "filter": filter_regex.pattern if filter_regex else None,
            "oids": [],
            "tool": "mib2oid",
            "tool_version": VERSION,
        }
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
        return

    total_objects = 0
    scalar_candidates = 0
    selected_scalars = 0

    oids: list[dict] = []

    for name in all_names:
        total_objects += 1

        td_text = get_object_details(module, name, mib_dir)
        if not td_text:
            log_debug(f"Skipping {module}::{name} (no -Td data)")
            continue

        info = parse_td_block(td_text)

        # Skip tables and columnar objects
        if info["is_table"]:
            log_debug(f"Skipping {module}::{name} (table / SEQUENCE OF)")
            continue
        if info["is_column"]:
            log_debug(f"Skipping {module}::{name} (column in table {info['parent']})")
            continue

        scalar_candidates += 1

        full_name = f"{module}::{name}"
        desc = info.get("description") or ""

        # Optional filter on name/description
        if filter_regex:
            haystack = (full_name + "\n" + desc).lower()
            if not filter_regex.search(haystack):
                log_debug(f"Filter excludes {full_name}")
                continue

        # Resolve numeric scalar OID
        numeric_oid = get_scalar_numeric_oid(module, name, mib_dir)
        if not numeric_oid:
            log_debug(f"Skipping {full_name} (could not resolve numeric OID)")
            continue

        selected_scalars += 1

        value_type_hint = guess_zabbix_value_type(info.get("syntax"))
        obj = {
            "module": module,
            "name": name,
            "full_name": full_name,
            "oid": numeric_oid,
            "syntax": info.get("syntax"),
            "zabbix_value_type": value_type_hint,
            "access": info.get("access"),
            "status": info.get("status"),
            "parent": info.get("parent"),
            "index": info.get("index"),
        }

        if info.get("description"):
            obj["description"] = info["description"]
        if info.get("enums"):
            obj["enums"] = info["enums"]

        oids.append(obj)

    data = {
        "mib": module,
        "source_file": os.path.basename(mib_file),
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "filter": filter_regex.pattern if filter_regex else None,
        "stats": {
            "object_types": total_objects,
            "scalar_candidates": scalar_candidates,
            "selected_scalars": selected_scalars,
        },
        "oids": oids,
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            data,
            f,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )

    print("\n[summary]")
    print(f"  OBJECT-TYPE definitions: {total_objects}")
    print(f"  Scalar candidates:       {scalar_candidates}")
    print(f"  Selected scalars:        {selected_scalars}")
    print(f"  Output file:             {output_path}")


# ---------------------------------------------------------------------------
# Perl fallback (SNMP::MIB::Compiler) – compile test only
# ---------------------------------------------------------------------------

def check_perl_mib_compiler() -> bool:
    """
    Check if Perl and SNMP::MIB::Compiler are available.
    """
    perl = shutil.which("perl")
    if not perl:
        log_info("Perl is not installed or not in PATH; skipping Perl fallback.")
        return False

    cmd = [perl, "-MSNMP::MIB::Compiler", "-e", "exit 0;"]
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
    except Exception as e:
        log_info(f"Perl is present but SNMP::MIB::Compiler check failed: {e}")
        return False

    if proc.returncode != 0:
        log_info(
            "Perl is present but SNMP::MIB::Compiler is not available.\n"
            "Install it with e.g.: perl -MCPAN -e 'install Bundle::SNMP::MIB::Compiler'"
        )
        return False

    return True


def perl_compile_test(mib_file: str, module: str) -> bool:
    """
    Use SNMP::MIB::Compiler to try compiling the MIB.
    This is a *test only* – we don't yet extract OIDs via Perl, just
    see if the Perl compiler can handle the MIB at all.
    """
    perl = shutil.which("perl")
    if not perl:
        return False

    mib_dir = os.path.abspath(os.path.dirname(mib_file))
    script = (
        "use SNMP::MIB::Compiler; "
        "my ($dir,$mod) = @ARGV; "
        "my $m = new SNMP::MIB::Compiler; "
        "$m->add_path($dir); "
        "$m->add_extension('', '.mib'); "
        "$m->repository($dir); "
        "$m->{'do_imports'} = 1; "
        "my $ok = eval { $m->compile($mod); 1 }; "
        "if (!$ok) { my $e = $@ || 'compile failed'; die $e; } "
        "print \"OK\\n\";"
    )

    cmd = [perl, "-MSNMP::MIB::Compiler", "-e", script, mib_dir, module]
    log_debug(f"Perl compile test cmd: {' '.join(cmd)}")
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    if proc.returncode == 0 and "OK" in proc.stdout:
        log_info("Perl SNMP::MIB::Compiler successfully compiled this MIB.")
        return True

    log_warn(
        "Perl SNMP::MIB::Compiler could not compile this MIB.\n"
        f"stderr:\n{proc.stderr.strip()}"
    )
    return False


# ---------------------------------------------------------------------------
# Fallback: run fixmymib.py optionally, then retry
# ---------------------------------------------------------------------------

def try_fix_and_retry(
    orig_mib_file: str,
    module: str,
    output_path: str,
    filter_regex: Optional[re.Pattern],
) -> None:
    """
    Optional fallback path:
      - If orig_mib_file is NOT under fixed_mibs/, call fixmymib.py on it.
      - Expect fixed_mibs/<MODULE>.mib.
      - Retry snmptranslate against the fixed MIB.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    fixed_dir = os.path.join(script_dir, "fixed_mibs")
    fix_script = os.path.join(script_dir, "fixmymib.py")

    if not os.path.exists(fix_script):
        log_warn(
            "fixmymib.py was not found in the same directory.\n"
            "You can run it manually or use auto_oid_finder.py instead."
        )
        sys.exit(1)

    abs_orig = os.path.abspath(orig_mib_file)
    abs_fixed_dir = os.path.abspath(fixed_dir)
    orig_dir = os.path.abspath(os.path.dirname(orig_mib_file))

    if orig_dir.startswith(abs_fixed_dir):
        # Already in fixed_mibs -> don't run fixmymib again
        log_info(
            "MIB file is already in fixed_mibs/. Skipping fixmymib.py and "
            "just validating with snmptranslate."
        )
    else:
        log_info(
            f"Running fixmymib.py on {orig_mib_file} (module {module}) "
            f"to create a fixed copy under fixed_mibs/."
        )
        cmd = [sys.executable, fix_script, orig_mib_file]
        log_debug(f"Running fixmymib.py: {' '.join(cmd)}")
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if proc.returncode != 0:
            log_error("fixmymib.py failed to repair the MIB.")
            log_error(proc.stderr.strip())
            log_warn("Use auto_oid_finder.py to discover OIDs directly from the device.")
            sys.exit(1)

    fixed_mib = os.path.join(fixed_dir, f"{module}.mib")
    if not os.path.exists(fixed_mib):
        log_error(
            f"Expected fixed MIB '{fixed_mib}' does not exist.\n"
            "Check fixmymib.py output or run it manually with --output/-o."
        )
        sys.exit(1)

    log_info(f"Using fixed MIB: {fixed_mib}")

    # Test again if snmptranslate can load the module from fixed_mibs
    mib_dir = os.path.abspath(os.path.dirname(fixed_mib))
    test_rc, _, test_err = run_snmptranslate(
        ["-m", f"+{module}", module], mib_dir=mib_dir
    )
    if test_rc != 0:
        log_error(
            f"Even after fixmymib.py, snmptranslate could not load module '{module}'.\n"
            "This MIB is likely too broken for net-snmp.\n"
            "You can still monitor this device by using auto_oid_finder.py to\n"
            "discover OIDs directly from the live device.\n"
            f"snmptranslate error:\n{test_err.strip()}"
        )
        sys.exit(1)

    # If we get here, we can build catalog from the fixed MIB
    build_oid_catalog(
        mib_file=fixed_mib,
        module=module,
        mib_dir=mib_dir,
        output_path=output_path,
        filter_regex=filter_regex,
    )

    log_info("OID catalog built from fixed MIB.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    global DEBUG

    parser = argparse.ArgumentParser(
        description=(
            "Extract interesting scalar OIDs from a MIB file using snmptranslate\n"
            "and write them to a YAML OID catalog.\n\n"
            "Flow:\n"
            "  1) Pre-flight: check core MIB support (sysUpTime.0 from SNMPv2-MIB).\n"
            "  2) Use net-snmp snmptranslate (primary backend).\n"
            "  3) Optional: Perl SNMP::MIB::Compiler compile test.\n"
            "  4) Optional: fixmymib.py auto-repair and retry.\n"
            "  5) If all fails, fall back to auto_oid_finder.py.\n"
        )
    )

    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"mib2oid.py version {VERSION}",
        help="Show version and exit",
    )

    parser.add_argument("mib_file", help="Path to MIB file (e.g. QTS-MIB.mib)")
    parser.add_argument(
        "--module",
        help="Explicit MIB module name (default: derived from DEFINITIONS ::= BEGIN)",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to write OID catalog YAML (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--no-timestamp",
        action="store_true",
        help="Do not append timestamp to output filename",
    )
    parser.add_argument(
        "--filter",
        help=(
            "Regex for selecting interesting OIDs based on name/description. "
            f"Default: {DEFAULT_FILTER_PATTERN!r}"
        ),
    )
    parser.add_argument(
        "--no-filter",
        action="store_true",
        help="Disable filtering (include all scalar OBJECT-TYPEs)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging",
    )

    args = parser.parse_args()
    DEBUG = args.debug

    # Pre-flight: ensure MIB loading works at all
    if not check_mib_support():
        sys.exit(1)

    mib_file = args.mib_file
    if not os.path.exists(mib_file):
        log_error(f"MIB file '{mib_file}' does not exist.")
        sys.exit(1)

    if not check_snmptranslate():
        sys.exit(1)

    module = args.module or detect_module_name(mib_file)
    if not module:
        log_error(
            "Could not detect MIB module name from file. "
            "Use --module to specify it explicitly."
        )
        sys.exit(1)

    mib_dir = os.path.abspath(os.path.dirname(mib_file))

    log_info(f"Detected MIB module name from file: {module}")
    log_info(f"MIB file:    {mib_file}")
    log_info(f"Module:      {module}")

    base_name = os.path.splitext(os.path.basename(mib_file))[0]
    if args.no_timestamp:
        out_name = f"oids_{base_name}.yaml"
    else:
        ts = datetime.now().strftime("%Y%m%d%H%M")
        out_name = f"oids_{base_name}_{ts}.yaml"

    output_dir = os.path.abspath(args.output_dir)
    output_path = os.path.join(output_dir, out_name)
    log_info(f"Output file: {output_path}")

    # Compile filter regex
    if args.no_filter:
        filter_regex = None
        log_info("Filtering disabled (--no-filter). All scalar OBJECT-TYPEs will be kept.")
    else:
        pattern = args.filter or DEFAULT_FILTER_PATTERN
        try:
            filter_regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            log_error(f"Invalid --filter regex: {e}")
            sys.exit(1)
        log_info(f"Using filter regex: {pattern!r}")

    # Primary test: can snmptranslate see the module at all with the original MIB?
    test_rc, _, test_err = run_snmptranslate(
        ["-m", f"+{module}", module], mib_dir=mib_dir
    )
    if test_rc != 0:
        log_warn(
            f"snmptranslate could not load module '{module}' from {mib_dir}.\n"
            "This might be due to ugly vendor MIB syntax or missing imports."
        )

        # --- Perl fallback (interactive) ---
        if check_perl_mib_compiler():
            try:
                ans = input(
                    "[prompt] Try Perl SNMP::MIB::Compiler fallback first? [y/N]: "
                ).strip().lower()
            except EOFError:
                ans = ""

            if ans.startswith("y"):
                if perl_compile_test(mib_file, module):
                    log_info(
                        "Perl successfully compiled this MIB.\n"
                        "This tool still uses snmptranslate for OID extraction, "
                        "so next we can try to auto-fix the MIB and retry "
                        "snmptranslate via fixmymib.py."
                    )
                else:
                    log_warn(
                        "Perl could not compile this MIB either. "
                        "You can still try fixmymib.py, but the MIB may be hopeless."
                    )
            else:
                log_info("User chose not to use Perl fallback.")
        else:
            log_info("Perl fallback not available (no Perl or no SNMP::MIB::Compiler).")

        # --- fixmymib.py fallback (interactive) ---
        script_dir = os.path.dirname(os.path.abspath(__file__))
        fix_script = os.path.join(script_dir, "fixmymib.py")

        if os.path.exists(fix_script):
            try:
                ans2 = input(
                    "[prompt] Try to auto-repair this MIB with fixmymib.py and retry? [y/N]: "
                ).strip().lower()
            except EOFError:
                ans2 = ""

            if ans2.startswith("y"):
                try_fix_and_retry(
                    orig_mib_file=mib_file,
                    module=module,
                    output_path=output_path,
                    filter_regex=filter_regex,
                )
                return
            else:
                log_info(
                    "User chose not to run fixmymib.py from mib2oid.py.\n"
                    "You can run fixmymib.py manually or rely on auto_oid_finder.py\n"
                    "to discover OIDs directly from the live device."
                )
                sys.exit(1)
        else:
            log_warn(
                "fixmymib.py not found in the same directory.\n"
                "Either put fixmymib.py next to mib2oid.py or use auto_oid_finder.py."
            )
            sys.exit(1)

    # Primary path: original MIB is loadable by snmptranslate
    build_oid_catalog(
        mib_file=mib_file,
        module=module,
        mib_dir=mib_dir,
        output_path=output_path,
        filter_regex=filter_regex,
    )

    log_info("OID catalog ready.")


if __name__ == "__main__":
    main()

