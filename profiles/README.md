# profiles/ — Semantic Profiles for Template Builder

Profile files in this directory are used by **oid2zabbix-template.py** to give
semantic meaning to discovered OIDs.

Profiles control:

- How OIDs are grouped (disk, fan, temperature, power, etc.)
- How different enterprise IDs map to the same device family
- Naming and categorisation inside the Zabbix template

Profiles do **not** influence SNMP scanning; that is handled by filters/.

---

## How profiles are used

The template builder takes:

- one or more auto_oid_*.yaml profiles from export_yaml/
- one profile YAML from profiles/

and produces a Zabbix template in export_template/.

Typical call:

    ./oid2zabbix-template.py \
      export_yaml/auto_oid_192.168.0.107_*.yaml \
      --profile profiles/profile_55062_QNAP.yaml \
      --name "Template SNMP QNAP"

(Adjust the profile path/option to match your actual CLI.)

---

## Profile structure

Profiles are usually keyed by enterprise ID and may share common hint blocks.

Example:

    profiles:

      qnap_common_hints: &qnap_hints
        disk:
          - "1.3.6.1.4.1.24681.1.3.11"
          - "1.3.6.1.4.1.55062.1.10.2"
        fan:
          - "1.3.6.1.4.1.24681.1.3.13"
          - "1.3.6.1.4.1.55062.1.12.9"
        temp:
          - "1.3.6.1.4.1.55062.1.10.3"

      "55062":
        name: "QNAP-55062"
        hints: *qnap_hints

      "24681":
        name: "QNAP-24681"
        hints: *qnap_hints

Key ideas:

- profiles: is the top-level key.
- Each child key like "55062" is typically a vendor enterprise ID.
- name: is the human-readable label/template name.
- hints: is a mapping from semantic groups (disk, fan, temp, etc.) to OID roots.

---

## What profiles control

Profiles affect only the template generation phase:

- How items are grouped (e.g. disk vs fan vs temp)
- Which OIDs are considered part of the same logical entity
- How item names and LLD prototypes are formed
- Vendor or family branding of the resulting template

They are the place to encode device-specific knowledge like:

- Which OIDs correspond to physical disks
- Which OIDs correspond to fan speeds
- Which OIDs are system temperatures
- Which enterprise IDs belong to the same family

---

## What profiles do NOT control

Profiles do not:

- Decide which OIDs are walked
- Decide which tables are turned into LLD
- Exclude noisy tables or scalars

All of that is driven by filters/ and the filter file passed to auto_oid_finder.py.

---

## Naming conventions

Recommended profile file names:

- profile_55062_QNAP.yaml
- profile_24681_QNAP.yaml
- profile_9_CISCO.yaml
- profile_12345_FOOVENDOR.yaml

Pick something that clearly links the file to:

- the enterprise ID(s) it describes
- the vendor or device family

---

## Creating a new profile

1. Discover OIDs using an appropriate filter file.
2. Identify interesting OID roots for disk, fan, temp, power, etc.
3. Create a new file in profiles/, for example:

       profiles/profile_12345_MyVendor.yaml

4. Add semantic hints:

       profiles:
         "12345":
           name: "MyVendor-Devices"
           hints:
             disk:
               - "1.3.6.1.4.1.12345.1.10"
             fan:
               - "1.3.6.1.4.1.12345.1.20"
             temp:
               - "1.3.6.1.4.1.12345.1.30"

5. Generate a template using this profile and an auto_oid_*.yaml export.

---

## Summary

- profiles/ holds semantic mappings for oid2zabbix-template.py.
- Profiles define what discovered OIDs mean (disk, fan, temp, etc.).
- They do not change discovery behaviour; filters/ handles that.

