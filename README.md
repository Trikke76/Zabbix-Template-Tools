# SNMP Auto OID Finder & Zabbix Template Builder
Smart, automated SNMP discovery and Zabbix 7.0 template generation.

This project consists of two tightly-coupled tools:

• auto_oid_finder.py  
  Scans a device via SNMP, discovers useful scalar OIDs and table structures,
  enriches them with MIB names, applies filters, and outputs a compact YAML
  profile.

• oid2zabbix-template.py  
  Converts the profile into a clean, deduplicated Zabbix 7.0 template with:
  - Scalar items
  - LLD discovery rules
  - Item prototypes
  - Proper async-SNMP keys (get[] / walk[])
  - Preprocessing
  - Clean naming and vendor metadata

Together, these tools automate SNMP monitoring for NAS devices, switches,
routers, UPS units, servers, firewalls, printers, and more.

---------------------------------------------------------------------

## WHY THIS PROJECT EXISTS

Manual SNMP template building is:
- slow
- inconsistent
- vendor-specific
- missing metrics
- full of useless tables

This toolkit provides:
- automatic scalar + table discovery
- MIB-aware naming via snmptranslate
- vendor subtree detection
- table filtering and LLD generation
- Observium MIB enrichment
- safe deduplication
- repeatable Zabbix templates

---------------------------------------------------------------------

## QUICKSTART

1) Install dependencies:
   - Python 3.10+
   - snmpwalk + snmptranslate (net-snmp)
   - Optional: Observium MIBs

2) Create filters.yaml:

      mib2:
        regex: "(sysUpTime|ifHCInOctets|ifHCOutOctets)"
      vendor:
        regex: "(temp|fan|voltage)"
      lld:
        regex: "(ifHCInOctets|temperature|voltage)"
        include_roots:
          - ".1.3.6.1.2.1.2.2"
          - ".1.3.6.1.2.1.31.1.1"
          - ".1.3.6.1.4.1.24681"
        exclude_roots:
          - ".1.3.6.1.2.1.4.21"
          - ".1.3.6.1.2.1.25.3.2.1"

3) Run the OID Finder:

      ./auto_oid_finder.py --host 192.168.0.107 --community public --filter-file filters.yaml

   Output is stored under export_yaml/

4) Generate a Zabbix Template:

      ./oid2zabbix-template.py export_yaml/auto_oid_192.168.0.107_*.yaml --name "Template SNMP Auto"

   Final template appears in export_template/

---------------------------------------------------------------------

## HOW IT WORKS

### 1. Smart SNMP Scanner
Walks:
- .1.3.6.1.2.1  (MIB-2)
- .1.3.6.1.4.1  (vendor)
- any extra --root

If the vendor walk fails, it automatically walks the vendor LLD include_roots.

It extracts:
- Scalars (ending .0)
- Tables (multi-index structures)
- MIB names + descriptions
- Value classes
- Filters via filters.yaml
- Skips useless tables (ARP, routing, HR-MIB indexes, TCP, etc.)

Produces a clean YAML profile.

### 2. LLD Table Engine
For each table:
- Creates master item:    snmp.raw.walk[…]
- Creates discovery rule: auto.discovery[…]
- Creates item prototypes for every column

Column names come from MIBs if available.

Supports:
- Forced tables (lld.include_roots)
- Exclusions (lld.exclude_roots)
- Regex-based table filtering
- Vendor-specific trees (QNAP, Synology, APC, Cisco…)

### 3. Template Builder
- Builds async-SNMP items (get[] / walk[])
- Handles deduplication
- Adds preprocessing
- Uses module::name when possible
- Avoids scalar/LLD overlaps
- Adds vendor + version metadata

Output is a Zabbix 7 template ready to import.

---------------------------------------------------------------------

## PROJECT STRUCTURE

  auto_oid_finder.py       # SNMP scanner + profile generator
  oid2zabbix-template.py   # Zabbix template generator
  filters.yaml             # Filtering rules
  export_yaml/             # Finder output
  export_template/         # Final Zabbix templates
  profiles/                # (Optional) Saved profile snapshots for comparison/tests
  observium_mibs/          # Optional MIB repository

---------------------------------------------------------------------

## SUPPORTED DEVICES

NAS: QNAP, Synology, TrueNAS, Netgear  
Switches: Cisco, Juniper, HP, Aruba, Mikrotik  
UPS/PDU: APC, Eaton  
Servers: Linux, BSD, Windows SNMP  
Printers: HP, Brother, Xerox  
Sensors, firewalls, routers… anything with SNMP.

---------------------------------------------------------------------


## CONTRIBUTIONS

Device-specific improvements, regex refinements, new blocklists and LLD
patterns are welcome. The goal is the best SNMP automation toolkit for Zabbix.


![auto-oid-finder.png](auto-oid-finder.png)
