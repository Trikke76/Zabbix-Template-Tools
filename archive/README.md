## 🛠️ fixmymib.py — MIB Repair Tool

fixmymib.py is a helper for repairing and normalizing vendor MIB files so they can be loaded by net-snmp tools like snmptranslate.

Typical problems it can help with:

- Missing or broken "::= { parent X }" lines
- Invalid or malformed OBJECT-TYPE definitions
- Extra or missing braces
- Non-standard tokens or formatting issues

Example usage:

    fixmymib.py some_vendor.mib
    fixmymib.py some_vendor.mib --backup
    fixmymib.py some_vendor.mib --output fixed_vendor.mib --normalize

Typical options (may vary slightly depending on your current version):

- --backup          Keep a .bak copy of the original file
- --output <file>   Save the fixed MIB to a custom path
- --strip-comments  Remove comments/garbage that break parsing
- --normalize       Apply consistent formatting/indentation
- --strict          Abort on unfixable syntax instead of guessing
- --debug           Show detailed repair operations

Use this when a vendor MIB refuses to load with snmptranslate or snmpwalk.

---

## 🔎 mib2oid.py — MIB → OID Extractor

mib2oid.py parses a MIB file and prints the numeric OIDs for all defined objects, helping you quickly identify:

- The enterprise root OID (e.g. .1.3.6.1.4.1.24681)
- All OBJECT-TYPE, NOTIFICATION-TYPE, MODULE-IDENTITY OIDs
- Subtrees relevant for filters or profiles

Example usage:

    mib2oid.py QNAP-NAS-MIB.mib
    mib2oid.py QNAP-NAS-MIB.mib --numeric
    mib2oid.py QNAP-NAS-MIB.mib --filter disk

Typical options (may vary slightly):

- --tree            Print a hierarchical view of the OID tree
- --numeric         Output numeric OIDs only
- --filter <regex>  Filter objects by name using a regex
- --output <file>   Save results to a file
- --debug           Verbose debug mode

This is particularly useful when building:

- filters/*.yaml (to know which roots to include)
- profiles/*.yaml (to map OIDs into semantic groups like disk/fan/temp)

