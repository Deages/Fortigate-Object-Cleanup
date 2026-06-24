# FortiGate Address Object Cleanup Tool

A Python automation script designed for enterprise FortiGate environments to identify and clean up stale, unused, or orphaned firewall address objects.

When migrating services or restructuring networks (especially in environments utilizing VRFs and multiple VDOMs), address objects are frequently left behind in the configuration. This script parses a FortiOS 7.4 configuration file, compares all configured address objects against a master list of active IP routing networks, and outputs a formatted, deduplicated CSV of objects that are safe to delete.


## Quick start guide:

- Step 1: Create a whitelist.txt file with each IP/object you want to whitelist from being marked as inactive.
- Step 2: Create a txt file, csv or xlsx file (e.g. networks.txt) that has all the active networks in your environment, line separated.
- Step 3: Make sure your fortigate config file is in the same directory.
- Step 4: run python3 fw_cleanup_check.py and check inactive_addresses.csv for the output.
- Step 5: run fmg_inactive_cleanup.py
- Step 6: copy the contents of "fmg_script_output.txt" into your FortiManager Scripts section and run it.


---

## Features

### Multi-VDOM Support
Safely parses the firewall address blocks scattered across multiple Virtual Domains without halting on the first `end` statement.

### CIDR & Subnet Intelligence
Uses hierarchical subset logic. If a FortiGate object like `10.1.5.1/32` exists, it will validate it as in-use if a larger parent network like `10.1.5.0/24` exists in your routing table.

### Scope Constrained
Specifically targets RFC 1918 private address space and defined public ranges (`129.78.0.0/16`) to avoid accidentally flagging external third-party IPs that obviously won't exist in local routing tables.

### Whitelist Protection
Supports a `whitelist.txt` file to explicitly protect summary ranges or specific administrative subnets from deletion.

### Smart Formatting & Deduplication
Sorts the output numerically by IP address, removes VDOM/VRF duplicates, and intelligently cleans the output string if an IP is already built into the object's name.

**Example:**

```text
h_10.1.1.5
```

Instead of:

```text
h_10.1.1.5,10.1.1.5/32
```

### Forensic Logging
Generates a verbose `.txt` log file to provide an exact audit trail of why an object was marked valid or invalid for peer review.

---

## Nuances:
- It's hard coded to ignore 129.78.0.0/16 since that's our org IP range.
- It's hard coded to ignore any object that has "VRF Peer" in the name for our use cases.

## Prerequisites

- Python 3.x
- Required libraries:
  - `pandas`
  - `openpyxl` (required for handling `.xlsx` files)

### Install Dependencies

Using a Python virtual environment:

```bash
python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate

pip install pandas openpyxl
```

---

## File Structure & Usage

The script is designed to run locally within a directory and will automatically discover the files it needs.

Place the following files in the same directory as `fw_cleanup_check.py`:

### 1. Firewall Configuration

Your FortiGate backup file:

- `.conf`
- `.txt` (with `fw` or `conf` in the filename)

### 2. Active Networks File

A file containing active subnets in standard CIDR notation:

**Supported formats:**

- `.csv`
- `.xlsx`
- `.txt`

**Example contents:**

```text
10.1.1.0/24
10.1.2.0/24
172.16.100.0/24
```

The script automatically ignores headers and extracts IP networks.

### 3. Whitelist (Optional)

A file named exactly:

```text
whitelist.txt
```

Containing CIDR ranges that should be excluded from cleanup analysis.

**Example:**

```text
10.0.0.0/8
172.16.0.0/12
129.78.0.0/16
```

---

## Running the Script

Execute the script with Python:

```bash
python fw_cleanup_check.py
```

---

## Outputs

Upon execution, the script generates two files in the working directory.

### `inactive_addresses.csv`

A finalized, deduplicated, and numerically sorted list of firewall address objects that are ready to be deleted from the FortiGate configuration.

### `script_log.txt`

A detailed debugging and audit log showing:

- How each FortiGate object was evaluated
- Which whitelist entry it matched (if any)
- Which active subnet validated the object
- Why the object was marked valid or invalid

This provides a complete audit trail for peer review and change-control processes.

---

## Use Case

This tool is particularly useful during:

- Network migrations
- VRF consolidations
- VDOM restructures
- Firewall cleanup projects
- Configuration hygiene reviews
- Pre-upgrade configuration audits

By comparing configured address objects against known active routing networks, the script helps identify legacy objects that can be safely removed while reducing the risk of deleting valid entries.
