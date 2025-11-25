# filters/ — SNMP Scanner Filter Files

Filter files define how **auto_oid_finder.py** scans an SNMP device:

- Which OID roots are walked
- Which scalars are considered interesting
- Which tables become LLD
- Vendor-specific overrides and junk-table exclusions

Filters control **discovery only**.  
They do **not** decide what OIDs mean in Zabbix — that belongs in profiles/.

---

## How filter files are used

auto_oid_finder.py loads exactly one filter file via:

    --filter-file filters/filters.yaml

A filter file has three main sections:

- mib2:     regex for selecting scalars under .1.3.6.1.2.1.*
- vendor:   regex for selecting scalars under .1.3.6.1.4.1.*
- lld:      configuration for table / LLD discovery

Minimal example:

    mib2:
      regex: "(sysUpTime|hrProcessorLoad)"

    vendor:
      regex: "(temperature|fan|voltage)"

    lld:
      regex: "(ifHCInOctets|temperature)"
      include_roots:
        - ".1.3.6.1.2.1.2.2"
        - ".1.3.6.1.4.1.24681"
      exclude_roots:
        - ".1.3.6.1.2.1.4.21"

---

## Walk root logic (auto_oid_finder.py v1.0.15+)

The scanner determines which OID roots to walk as follows:

Always:

- .1.3.6.1.2.1      (MIB-2)

From filter file:

- Every lld.include_roots entry that starts with .1.3.6.1.4.1.
  becomes a vendor root, for example:
  - .1.3.6.1.4.1.24681
  - .1.3.6.1.4.1.55062

From command line:

- Any extra OID root passed with:
  
      --root <OID>

No longer walked by default:

- The full .1.3.6.1.4.1 enterprises subtree (too big, often times out).

---

## Generic vs vendor-specific filters

Generic filter (filters.yaml):

- Generic mib2 and vendor regex patterns
- LLD for ifTable / ifXTable
- Global exclude_roots (routing, ARP, tcpConn, HR-MIB junk, nsCache)
- No vendor-specific tuning

Use this when scanning unknown or mixed devices.

Vendor-specific filter (example: filters_qnap.yaml):

- Adds QNAP-specific vendor roots:
  - .1.3.6.1.4.1.24681
  - .1.3.6.1.4.1.55062
- Adds QNAP-specific lld.exclude_roots (directory-like tables)
- Keeps generic MIB-2 handling

You can create more:

- filters_cisco.yaml
- filters_apc.yaml
- filters_synology.yaml
- filters_printer.yaml

---

## Testing a filter

Example:

    ./auto_oid_finder.py \
      --host 192.168.0.107 \
      --community public \
      --filter-file filters/filters_qnap.yaml \
      --debug

Check the log for:

- LLD include_roots and exclude_roots
- Effective roots to walk
- Reasonable number of discovered OIDs

---

## Summary

- filters/ holds YAML files that control SNMP discovery.
- Filters decide what to walk, what to keep, and what to ignore.
- Filters do not define semantics; profiles/ does that.

