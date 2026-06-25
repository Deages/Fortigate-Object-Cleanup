# FortiGate & FortiManager Address Object Cleanup Tool

A Python automation tool designed to identify unused FortiGate firewall address objects, validate them against active routing networks, and generate FortiManager cleanup artifacts for safe removal.

## Overview

Managing address objects across large FortiGate deployments can become difficult over time as legacy subnets, decommissioned services, and stale network entries accumulate.

This tool performs a **two-phase analysis and cleanup preparation workflow**:

### Phase 1 – Analysis & Identification

* Parses a FortiGate/FortiOS configuration backup.
* Extracts all firewall address objects.
* Compares objects against active routing network data.
* Excludes:

  * RFC1918 and targeted public range exceptions
  * Whitelisted networks
  * Name-based exclusions (e.g. "VRF Peer")
* Produces a report of potentially inactive objects.

### Phase 2 – FortiManager Cleanup Preparation

* Re-parses the FortiOS configuration.
* Detects inactive objects that are still referenced.
* Identifies:

  * Address Groups
  * Firewall Policies
  * VDOM ownership
* Generates:

  * FortiManager CLI cleanup script
  * Policy remediation report

---

# Features

✅ Automatic input file discovery

✅ Supports routing data from:

* CSV
* XLSX
* TXT

✅ RFC1918-aware object filtering

✅ Custom subnet whitelisting

✅ Address Group dependency tracking

✅ Firewall Policy dependency tracking

✅ VDOM-aware analysis

✅ FortiManager CLI script generation

✅ Comprehensive logging

---

# Directory Structure

```text
project/
│
├── inputs/
│   ├── firewall.conf
│   ├── active_networks.xlsx
│   └── whitelist.txt
│
├── outputs/
│   ├── inactive_objects.txt
│   ├── fmg_script_config.txt
│   ├── policy_id_cleanup.txt
│   └── logs/
│       └── script_log.txt
│
└── fortigate_cleanup.py
```

---

# Requirements

## Python Version

Python 3.9+

## Dependencies

```bash
pip install pandas openpyxl
```

### Libraries Used

| Library   | Purpose                |
| --------- | ---------------------- |
| pandas    | XLSX processing        |
| openpyxl  | Excel file support     |
| ipaddress | CIDR calculations      |
| csv       | CSV parsing            |
| logging   | Execution logging      |
| glob      | File discovery         |
| shlex     | FortiOS syntax parsing |
| re        | Pattern matching       |

---

# Input Files

Place all required files inside the `inputs/` directory.

## 1. FortiGate Configuration

Supported formats:

```text
*.conf
```

or

```text
*.txt
```

Filename must contain either:

```text
fw
```

or

```text
conf
```

Example:

```text
customer-fw.conf
```

---

## 2. Active Networks File

Supported formats:

```text
.csv
.xlsx
.txt
```

Example contents:

```text
10.10.0.0/16
10.20.0.0/16
172.16.100.0/24
129.78.50.0/24
```

The script treats these networks as active routing paths.

Any firewall object that is a subnet of one of these entries is considered active.

---

## 3. Optional Whitelist

Create:

```text
inputs/whitelist.txt
```

Example:

```text
10.0.0.0/8
172.20.0.0/16
192.168.0.0/16
```

Objects that exactly match a whitelisted subnet are excluded from analysis.

---

# Scope of Evaluation

The script only evaluates address objects contained within the following ranges:

| Range          | Description         |
| -------------- | ------------------- |
| 10.0.0.0/8     | RFC1918             |
| 172.16.0.0/12  | RFC1918             |
| 192.168.0.0/16 | RFC1918             |
| 129.78.0.0/16  | Custom Public Range |

Objects outside these ranges are ignored.

---

# How It Works

## Phase 1: Address Object Analysis

The script scans:

```fortios
config firewall address
    edit "Server_Network"
        set subnet 10.10.10.0 255.255.255.0
    next
end
```

Extracted objects are evaluated against:

1. Name whitelist
2. Scope filters
3. Network whitelist
4. Active routing table

Inactive objects are written to:

```text
outputs/inactive_objects.txt
```

---

## Phase 2: Usage Analysis

The configuration is scanned again to locate references within:

### Address Groups

Example:

```fortios
config firewall addrgrp
    edit "Servers"
        set member "Server_Network"
    next
end
```

### Firewall Policies

Example:

```fortios
config firewall policy
    edit 100
        set srcaddr "Server_Network"
    next
end
```

---

# Output Files

## inactive_objects.txt

List of all identified inactive objects.

Example:

```text
Legacy_Server_Net,10.10.50.0/24
Old_DMZ,172.16.99.0/24
```

---

## fmg_script_config.txt

Generated FortiManager CLI script.

Example:

```fortios
config vdom
edit "root"

    config firewall addrgrp
        edit "Servers"
            unselect member "Legacy_Server_Net"
        next
    end

next
```

Used to remove inactive objects from address groups before deletion.

---

## policy_id_cleanup.txt

Generated when inactive objects are still referenced by firewall policies.

Example:

```text
VDOM:       root
Policy ID:  100
Direction:  srcaddr
Object:     "Legacy_Server_Net"
```

These objects must be manually removed from policies before deletion is possible.

---

## logs/script_log.txt

Complete execution log containing:

* File discovery
* Parsing activity
* Object validation
* Group membership tracking
* Policy dependency tracking
* Errors and warnings

---

# Running the Script

```bash
python fortigate_cleanup.py
```

Example output:

```text
Starting Comprehensive FortiGate Object Cleanup Check...

Selected FortiGate Config:
customer-fw.conf

Selected Active Networks File:
active_networks.xlsx

Successfully parsed 342 subnet address objects.

Found 27 inactive objects.

Generating FortiManager CLI Script...

Comprehensive script execution finished.
```

---

# Cleanup Workflow

Recommended operational process:

```text
1. Export FortiGate configuration
          ↓
2. Export active routing networks
          ↓
3. Run script
          ↓
4. Review inactive_objects.txt
          ↓
5. Review policy_id_cleanup.txt
          ↓
6. Remove policy references manually
          ↓
7. Run generated FMG script
          ↓
8. Delete objects via FortiManager
```

---

# Safety Mechanisms

The script intentionally avoids false positives by:

* Limiting evaluation scope to approved ranges
* Supporting whitelist exclusions
* Tracking address group membership
* Tracking firewall policy references
* Generating remediation reports before deletion actions

No configuration changes are made directly to:

* FortiGate
* FortiManager
* Firewall Policies
* Address Objects

The script only generates analysis and cleanup artifacts.

---

# Example Use Cases

* Firewall object hygiene audits
* FortiManager cleanup projects
* Migration preparation
* Rulebase rationalization
* Legacy subnet retirement
* VDOM environment cleanup

---

# Limitations

Current version supports:

* IPv4 subnet address objects
* Standard FortiOS configuration exports
* Address Groups
* Firewall Policies

Not currently supported:

* FQDN objects
* Dynamic objects
* IPv6 objects
* Nested address group dependency analysis
* Direct API integration

---

# License

This project is provided as-is without warranty.

Validate all generated outputs in a non-production environment before making firewall changes.

---

# Author

Network Automation & Security Operations Tooling
