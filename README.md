# FortiGate & FortiManager Address Object Cleanup Tool

Identify unused FortiGate address objects by comparing firewall configuration data against active routing networks, then generate FortiManager cleanup artifacts to safely remove stale objects.

## What It Does

### Phase 1 – Identify Inactive Objects

The script:

* Parses FortiGate address objects from a configuration backup
* Compares them against active routing networks
* Applies whitelist and scope exclusions
* Produces a list of candidate inactive objects

### Phase 2 – Prepare Cleanup

The script:

* Checks whether inactive objects are still referenced
* Identifies Address Group dependencies
* Identifies Firewall Policy dependencies
* Generates FortiManager CLI commands to remove group references
* Generates a report for objects requiring manual policy cleanup

---

## Quick Start

### Install Dependencies

```bash
pip install pandas openpyxl
```

### Add Input Files

Place the following files into `./inputs`:

```text
inputs/
├── firewall.conf
├── active_networks.xlsx
└── whitelist.txt      # Optional
```

| File                | Description                                       |
| ------------------- | ------------------------------------------------- |
| `firewall.conf`     | FortiGate configuration export                    |
| `active_networks.*` | CSV, XLSX, or TXT containing active CIDR networks |
| `whitelist.txt`     | Optional list of networks to exclude              |

### Run

```bash
python fortigate_cleanup.py
```

### Review Outputs

```text
outputs/
├── inactive_objects.txt
├── fmg_script_config.txt
├── policy_id_cleanup.txt
└── logs/
    └── script_log.txt
```

| Output                  | Purpose                              |
| ----------------------- | ------------------------------------ |
| `inactive_objects.txt`  | Candidate objects for deletion       |
| `fmg_script_config.txt` | FortiManager cleanup commands        |
| `policy_id_cleanup.txt` | Objects still referenced in policies |
| `script_log.txt`        | Detailed execution log               |

---

## Supported Features

* Automatic file discovery
* CSV, XLSX, and TXT network imports
* RFC1918-aware filtering
* Network whitelisting
* Address Group dependency tracking
* Firewall Policy dependency tracking
* VDOM-aware analysis
* FortiManager CLI generation
* Detailed logging

## Caveats & Assumptions

Before running this tool, be aware of the following hardcoded rules and design assumptions:

### Target Evaluation Scope

The script only evaluates address objects that fall within the following network ranges:

* `10.0.0.0/8`
* `172.16.0.0/12`
* `192.168.0.0/16`
* `129.78.0.0/16`

Address objects outside these ranges are automatically ignored and will not be included in inactivity analysis.

### VRF Peer Exemption

Any address object containing the text `VRF Peer` (case-insensitive) in its name is automatically excluded from evaluation and protected from cleanup actions.

### Exact-Match Whitelisting

The optional `whitelist.txt` file uses exact subnet matching.

For example, if the following subnet is whitelisted:

```text id="exw1pc"
10.10.0.0/16
```

Only the `/16` object itself is excluded from analysis. Objects contained within that range (such as `/24` or `/32` entries) are still evaluated independently and may be flagged as inactive.

### FortiOS Dependency Restrictions

FortiOS does not allow deletion of address objects that are actively referenced by Firewall Policies.

This tool automatically identifies these dependencies and generates:

* Address Group cleanup commands (`fmg_script_config.txt`)
* Policy dependency reports (`policy_id_cleanup.txt`)

Objects referenced by Firewall Policies must be manually removed from those policies within FortiManager before they can be deleted.

### No Direct Configuration Changes

This tool does **not** make any direct changes to:

* FortiGate devices
* FortiManager
* Firewall Policies
* Address Objects

All outputs are generated for review and controlled execution by an administrator.
