# FortiGate Address Object Cleanup Tool

A Python automation script designed for enterprise FortiGate environments to identify and clean up stale, unused, or orphaned firewall address objects.

When migrating services or restructuring networks (especially in environments utilizing VRFs and multiple VDOMs), address objects are frequently left behind in the configuration. This script parses a FortiOS 7.4 configuration file, compares all configured address objects against a master list of active IP routing networks, and outputs a formatted, deduplicated CSV of objects that are safe to delete.

## Features

- **Multi-VDOM Support**: Safely parses `config firewall address` blocks scattered across multiple Virtual Domains without halting on the first `end` statement.
- **CIDR & Subnet Intelligence**: Uses hierarchical subset logic (`subnet_of`). If a FortiGate object like `10.1.5.1/32` exists, it will validate it as "in-use" if a larger parent network like `10.1.5.0/24` exists in your routing table.
- **Scope Constrained**: Specifically targets RFC 1918 private address space and defined public ranges (`129.78.0.0/16`) to avoid accidentally flagging external third-party IPs that obviously won't exist in local routing tables.
- **Whitelist Protection**: Supports a `whitelist.txt` file to explicitly protect summary ranges or specific administrative subnets from deletion.
- **Smart Formatting & Deduplication**: Sorts the output numerically by IP address, removes VDOM/VRF duplicates, and intelligently cleans the output string if an IP is already built into the object's name (e.g., outputs `h_10.1.1.5` instead of `h_10.1.1.5,10.1.1.5/32`).
- **Forensic Logging**: Generates a verbose `.txt` log file to provide an exact audit trail of why an object was marked valid or invalid for peer-review.

## Prerequisites

- **Python 3.x**
- **Required Libraries**: `pandas`, `openpyxl` (Required for handling `.xlsx` files dynamically)

To install dependencies using a Python Virtual Environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install pandas openpyxl
