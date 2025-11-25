# SNMP Auto OID Finder & Zabbix Template Builder
Smart, automated SNMP discovery and Zabbix 7.0 template generation.

This project consists of two tightly-coupled tools:

• **auto_oid_finder.py**  
  Scans a device via SNMP, discovers useful scalar OIDs and table structures,  
  enriches them with MIB names, applies filters, and outputs a compact YAML profile.

• **oid2zabbix-template.py**  
  Converts the YAML profile into a clean, deduplicated Zabbix 7.0 template with:  
  - Scalar items  
  - LLD discovery rules  
  - Item prototypes  
  - Proper async-SNMP keys (get[] / walk[])  
  - Preprocessing  
  - Clean naming and vendor metadata

Together, these tools automate SNMP monitoring for NAS devices, switches, routers, UPS units, servers, firewalls, printers, and more.

---

## REQUIRED PYTHON PACKAGES

Install via pip:

```
pip install pysnmp pyyaml rich lxml
```

Optional (recommended for MIB enrichment):

```
pip install pysmi
```

Required system tools:
- `snmpwalk`, `snmptranslate` from **net-snmp**
- (Optional) Observium MIB repository

---

## COMMAND-LINE OPTIONS

### auto_oid_finder.py — SNMP Scanner + Profile Generator

```
usage: auto_oid_finder.py [options]

Options:
  --host <IP/FQDN>            Target device
  --community <string>        SNMP community (v2c)
  --version <1|2c|3>          SNMP version (default: 2c)

SNMPv3:
  --v3-user <name>
  --v3-auth-proto <MD5|SHA|SHA256|SHA512>
  --v3-auth-pass <password>
  --v3-priv-proto <DES|AES|AES192|AES256>
  --v3-priv-pass <password>

Discovery:
  --root <OID>                Additional OID roots to walk (repeatable)
  --filter-file <file>        YAML filtering rules
  --timeout <seconds>         SNMP timeout (default: 2)
  --retries <n>               SNMP retries (default: 2)

Output:
  --output-dir <dir>          Directory for YAML profiles (default: export_yaml/)
  --tag <string>              Add metadata tag to output filename

Misc:
  --disable-mib               Skip MIB name resolution
  --debug                     Enable verbose debugging
```

---

### oid2zabbix-template.py — Zabbix 7 Template Builder

```
usage: oid2zabbix-template.py <yaml-profile> [options]

Options:
  --name <template name>      Name of the Zabbix template
  --vendor <string>           Vendor override
  --output-dir <dir>          Output directory (default: export_template/)
  --prefix <string>           Prefix all item names
  --tag <string>              Add template tag to all items

Advanced:
  --max-depth <n>             Limit table depth
  --skip-lld                  Disable low-level discovery rules
  --skip-scalars              Do not include scalar items

Debug:
  --debug                     Enable verbose debugging
```

---

## QUICKSTART

### 1) Install requirements

```
pip install pysnmp pyyaml rich lxml pysmi
sudo apt install snmp snmp-mibs-downloader
```

### 2) Create filters.yaml

```yaml
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
```

### 3) Run the OID Finder

```
./auto_oid_finder.py \
    --host 192.168.0.107 \
    --community public \
    --filter-file filters.yaml
```

Output is stored under **export_yaml/**.

### 4) Generate a Zabbix Template

```
./oid2zabbix-template.py \
    export_yaml/auto_oid_192.168.0.107_*.yaml \
    --name "Template SNMP Auto"
```

Final template appears in **export_template/**.

---

## HOW IT WORKS

### 1. Smart SNMP Scanner

Walks:
- `.1.3.6.1.2.1` (MIB-2)
- `.1.3.6.1.4.1` (Vendor subtree)
- Any additional roots via `--root`

Features:
- Discovers scalars and multi-index tables  
- Resolves MIB names & descriptions  
- Applies regex filters  
- Skips useless tables (ARP, routing, TCP, HR-MIB noise)  
- Produces a clean YAML profile  

---

### 2. LLD Table Engine

For each SNMP table:
- Generates master walk item  
- Creates discovery rule  
- Builds item prototypes  
- Names columns from MIBs  
- Applies include/exclude roots  
- Supports regex-based table filtering  

---

### 3. Template Builder

Creates a complete Zabbix 7 template:
- Async SNMP keys (get[] / walk[])  
- Deduplicated items  
- Preprocessing chains  
- Vendor & metadata injection  
- Clean and consistent naming  
- Avoids scalar/table conflicts  

![auto-oid-finder.png](auto-oid-finder.png)
---

## PROJECT STRUCTURE

```
auto_oid_finder.py       # SNMP scanner + profile generator
oid2zabbix-template.py   # Zabbix template generator
filters.yaml             # Filtering rules
export_yaml/             # Finder output
export_template/         # Zabbix templates
profiles/                # Optional saved profiles
observium_mibs/          # Optional MIB repository
```

---

## SUPPORTED DEVICES

NAS: QNAP, Synology, TrueNAS, Netgear  
Switches: Cisco, Juniper, HP, Aruba, Mikrotik  
UPS/PDU: APC, Eaton  
Servers: Linux, BSD, Windows SNMP  
Printers: HP, Brother, Xerox  
Firewalls, routers, IoT devices… anything with SNMP.

---

## CONTRIBUTIONS

Contributions for vendor-specific improvements, smarter filters, blocklists, and LLD patterns are welcome.  
The goal: **the most complete SNMP automation toolkit for Zabbix.**


