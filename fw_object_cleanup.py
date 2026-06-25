"""
FortiGate & FortiManager Address Object Cleanup Tool
====================================================
This script performs a comprehensive two-phase cleanup of FortiGate address objects:

Phase 1: Analysis & Identification
- Parses a FortiOS configuration file for all address objects.
- Compares those objects against a master list of active routing networks.
- Bypasses objects based on scope (RFC 1918) and whitelist criteria.
- Outputs unused objects to './outputs/inactive_objects.txt'.

Phase 2: FortiManager CLI Preparation
- Scans the FortiOS configuration again to map VDOMs, Groups, and Policies.
- Identifies if any of the inactive objects are actively referenced.
- Generates FMG CLI syntax ('./outputs/fmg_script_config.txt') to safely unbind objects from groups.
- Generates a manual cleanup report ('./outputs/policy_id_cleanup.txt') for objects stuck in policies.
"""

import os
import glob
import csv
import logging
import ipaddress
import re
import shlex
from collections import defaultdict

try:
    import pandas as pd
except ImportError:
    print("Error: pandas is not installed. Please run 'pip install pandas openpyxl'")
    exit(1)

# ==========================================
# Global Configuration & Setup
# ==========================================

INPUT_DIR = "./inputs"
OUTPUT_DIR = "./outputs"
LOG_DIR = os.path.join(OUTPUT_DIR, "logs")

# Create directories if they do not exist
os.makedirs(INPUT_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "script_log.txt")
OUTPUT_INACTIVE = os.path.join(OUTPUT_DIR, "inactive_objects.txt")
OUTPUT_FMG_CONFIG = os.path.join(OUTPUT_DIR, "fmg_script_config.txt")
POLICY_REPORT = os.path.join(OUTPUT_DIR, "policy_id_cleanup.txt")
WHITELIST_FILE = "whitelist.txt"

# Target ranges to evaluate for inactivity (RFC 1918 + Specific Public Range)
TARGET_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('129.78.0.0/16')
]

# Consolidate all logging into the single requested script_log.txt file
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, mode='w'),
        logging.StreamHandler()
    ]
)

# ==========================================
# File Discovery & Loading
# ==========================================

def find_files():
    """Locate the FortiGate config, active networks, and whitelist file inside ./inputs."""
    
    conf_search = os.path.join(INPUT_DIR, '*.conf')
    txt_search = os.path.join(INPUT_DIR, '*.txt')
    csv_search = os.path.join(INPUT_DIR, '*.csv')
    xlsx_search = os.path.join(INPUT_DIR, '*.xlsx')
    
    conf_files = glob.glob(conf_search) + [f for f in glob.glob(txt_search) if 'fw' in os.path.basename(f).lower() or 'conf' in os.path.basename(f).lower()]
    raw_data_files = glob.glob(csv_search) + glob.glob(xlsx_search) + glob.glob(txt_search)
    
    data_files = []
    
    # Aggressively filter out previous script outputs in case they are dropped in inputs
    ignore_list = ["inactive_objects.txt", "fmg_script_config.txt", "policy_id_cleanup.txt", "script_log.txt"]
    
    for f in raw_data_files:
        base_f = os.path.basename(f).lower()
        if base_f in ignore_list or 'inactive' in base_f or 'script_log' in base_f or 'fmg_' in base_f:
            continue
        data_files.append(f)
        
    for ignore_file in ignore_list:
        conf_files = [c for c in conf_files if os.path.basename(c).lower() != ignore_file]
            
    for c in conf_files:
        if c in data_files:
            data_files.remove(c)

    if not conf_files:
        logging.error(f"No FortiGate .conf (or valid .txt) config file found in '{INPUT_DIR}'.")
        exit(1)

    selected_conf = conf_files[0]
    selected_routing = None
    selected_whitelist = None
    
    for f in data_files.copy():
        if os.path.basename(f).lower() == WHITELIST_FILE:
            selected_whitelist = f
            data_files.remove(f)
            break

    if data_files:
        selected_routing = data_files[0]

    if not selected_routing:
        logging.error(f"No active networks .csv, .xlsx, or .txt file found in '{INPUT_DIR}'.")
        exit(1)

    logging.info(f"Selected FortiGate Config: {selected_conf}")
    logging.info(f"Selected Active Networks File: {selected_routing}")
    
    if selected_whitelist:
        logging.info(f"Selected Whitelist File: {selected_whitelist}")
    else:
        logging.warning(f"No {WHITELIST_FILE} found in '{INPUT_DIR}'. Whitelist logic will be bypassed.")
    
    return selected_conf, selected_routing, selected_whitelist

def load_networks_from_file(filepath, label="Networks"):
    """Read a CSV/XLSX/TXT and extract all valid CIDR IP networks."""
    networks = []
    if not filepath:
        return networks
        
    logging.info(f"--- Loading {label} ---")
    
    try:
        raw_values = []
        if filepath.endswith('.xlsx'):
            df = pd.read_excel(filepath)
            raw_values = df.values.flatten().astype(str).tolist()
        elif filepath.endswith('.csv'):
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                for row in reader:
                    raw_values.extend([str(item) for item in row])
        else:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                raw_values = f.read().splitlines()
        
        for val in raw_values:
            val = val.strip()
            if not val or val.lower() == 'nan':
                continue
            try:
                network = ipaddress.ip_network(val, strict=False)
                networks.append(network)
                logging.debug(f"Loaded {label.lower()}: {network}")
            except ValueError:
                pass 
                
        logging.info(f"Successfully loaded {len(networks)} {label.lower()}.")
        return networks
        
    except Exception as e:
        logging.error(f"Failed to read {label} file: {e}")
        exit(1)

# ==========================================
# Phase 1: Object Parsing & Evaluation
# ==========================================

def parse_fortigate_objects(conf_filepath):
    """Phase 1 Parser: Extract all firewall address objects and their subnets."""
    fw_objects = []
    logging.info("--- Parsing FortiGate Configuration (Phase 1) ---")
    
    in_firewall_address_section = False
    current_obj_name = None
    
    edit_regex = re.compile(r'^\s*edit\s+"?([^"\n]+)"?')
    subnet_regex = re.compile(r'^\s*set\s+subnet\s+([\d\.]+)\s+([\d\.]+)')

    with open(conf_filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            
            if line == "config firewall address":
                in_firewall_address_section = True
                continue
            
            if in_firewall_address_section and line == "end":
                in_firewall_address_section = False
                continue
                
            if in_firewall_address_section:
                edit_match = edit_regex.match(line)
                if edit_match:
                    current_obj_name = edit_match.group(1)
                    continue
                
                if current_obj_name:
                    subnet_match = subnet_regex.match(line)
                    if subnet_match:
                        ip = subnet_match.group(1)
                        mask = subnet_match.group(2)
                        try:
                            network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                            fw_objects.append({
                                'name': current_obj_name,
                                'network': network
                            })
                        except ValueError as e:
                            logging.warning(f"Line {line_num}: Invalid subnet for object '{current_obj_name}' - {e}")
                        
                        current_obj_name = None

    logging.info(f"Successfully parsed {len(fw_objects)} subnet address objects from the firewall.")
    return fw_objects

def compare_and_find_inactive(fw_objects, active_networks, whitelist_networks):
    """Evaluate FW objects against scope constraints, whitelists, and active routing tables."""
    inactive_objects = []
    logging.info("--- Beginning Inactivity Comparison ---")
    
    for obj in fw_objects:
        obj_name = obj['name']
        obj_network = obj['network']
        
        # 1. Name-based Whitelist Check ("VRF Peer" or similar)
        if 'vrf peer' in obj_name.lower():
            logging.debug(f"WHITELISTED (NAME): FW Object '{obj_name}' ({obj_network}) contains 'VRF Peer'.")
            continue

        # 2. Scope Constraint Check (RFC 1918 + Specific Public Ranges)
        in_target_scope = False
        for target in TARGET_RANGES:
            try:
                if obj_network.subnet_of(target):
                    in_target_scope = True
                    break
            except TypeError:
                continue
                
        if not in_target_scope:
            logging.debug(f"SKIPPED: FW Object '{obj_name}' ({obj_network}) is outside targeted check ranges.")
            continue
            
        # 3. Whitelist Subnet Exclusion Check (Summary VRF Ranges, etc.)
        # Reverted back to exact match: Only ignore the object if it exactly matches the whitelisted CIDR range
        if obj_network in whitelist_networks:
            logging.debug(f"WHITELISTED (EXACT MATCH): FW Object '{obj_name}' ({obj_network}) explicitly matches a whitelisted network.")
            continue

        # 4. Active Routing Check (Is it a subset of a known active path?)
        is_active = False
        for active_net in active_networks:
            try:
                if obj_network.subnet_of(active_net):
                    logging.debug(f"VALID: FW Object '{obj_name}' ({obj_network}) is active within routed network ({active_net})")
                    is_active = True
                    break 
            except TypeError:
                continue
                
        if not is_active:
            logging.warning(f"INACTIVE: FW Object '{obj_name}' ({obj_network}) is NOT found in active routing networks.")
            inactive_objects.append({
                'name': obj_name,
                'subnet': str(obj_network)
            })
            
    return inactive_objects

def export_inactive_to_txt(inactive_objects):
    """De-duplicate, sort, format, and write the inactive objects to OUTPUT_INACTIVE."""
    if not inactive_objects:
        logging.info(f"Great news! No inactive objects found. Skipping creation of {OUTPUT_INACTIVE}.")
        return set()

    # Deduplicate objects
    unique_inactive = []
    seen = set()
    for obj in inactive_objects:
        identifier = (obj['name'], obj['subnet'])
        if identifier not in seen:
            seen.add(identifier)
            unique_inactive.append(obj)
            
    inactive_objects = unique_inactive
    inactive_objects.sort(key=lambda x: ipaddress.ip_network(x['subnet'], strict=False))

    logging.info(f"--- Exporting {len(inactive_objects)} unique inactive objects to {OUTPUT_INACTIVE} ---")
    
    unique_names_only = set()
    
    try:
        # Note: Using csv.writer to maintain exact formatting structure matching previous outputs
        with open(OUTPUT_INACTIVE, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            for obj in inactive_objects:
                name = obj['name']
                subnet_str = obj['subnet']
                net_obj = ipaddress.ip_network(subnet_str, strict=False)
                base_ip_str = str(net_obj.network_address)
                
                unique_names_only.add(name)
                
                ip_pattern = r'(?<!\d)' + re.escape(base_ip_str) + r'(?!\d)'
                
                if re.search(ip_pattern, name) or subnet_str in name:
                    writer.writerow([name])
                else:
                    writer.writerow([name, subnet_str])
                    
        logging.info(f"Export complete. Check {OUTPUT_INACTIVE} for objects.")
    except Exception as e:
        logging.error(f"Failed to write to text file: {e}")
        
    return unique_names_only

# ==========================================
# Phase 2: FMG Policy & Group Tracking
# ==========================================

def parse_config_for_usage(conf_filepath, inactive_names):
    """
    Phase 2 Parser: 
    Scans the configuration to map VDOMs, Groups, and Policies.
    Checks if any objects in the 'inactive_names' set are actively utilized.
    """
    groups_to_modify = defaultdict(lambda: defaultdict(set))
    policy_usages = []

    logging.info("--- Parsing FortiGate Configuration for Object Usage (Phase 2) ---")

    current_vdom = "root"
    current_config = None
    current_edit = None

    with open(conf_filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            stripped_line = line.strip()

            if not stripped_line:
                continue

            # State Machine context tracking
            if stripped_line.startswith("config vdom"):
                pass 
            elif stripped_line.startswith("config "):
                current_config = stripped_line[7:].strip()
            elif stripped_line.startswith("edit "):
                name = stripped_line[5:].strip().strip('"')
                if current_config is None:
                    current_vdom = name
                else:
                    current_edit = name
            elif stripped_line == "next":
                current_edit = None
                if current_config is None:
                    current_vdom = "root" 
            elif stripped_line == "end":
                current_config = None

            elif current_edit:
                # 1. Address Groups
                if current_config == "firewall addrgrp" and stripped_line.startswith("set member "):
                    try:
                        tokens = shlex.split(stripped_line)
                        members = tokens[2:]
                        for m in members:
                            if m in inactive_names:
                                groups_to_modify[current_vdom][current_edit].add(m)
                                logging.info(f"[VDOM: {current_vdom}] Object '{m}' found in Address Group '{current_edit}'. Queued for unselect.")
                    except ValueError:
                        logging.warning(f"Line {line_num}: Malformed group member syntax: {stripped_line}")

                # 2. Firewall Policies
                elif current_config == "firewall policy" and (stripped_line.startswith("set srcaddr ") or stripped_line.startswith("set dstaddr ")):
                    try:
                        tokens = shlex.split(stripped_line)
                        direction = tokens[1] 
                        members = tokens[2:]
                        for m in members:
                            if m in inactive_names:
                                policy_usages.append({
                                    'vdom': current_vdom,
                                    'policy_id': current_edit,
                                    'direction': direction,
                                    'object': m
                                })
                                logging.warning(f"[VDOM: {current_vdom}] Policy {current_edit} is actively using target object '{m}' as {direction}.")
                    except ValueError:
                        logging.warning(f"Line {line_num}: Malformed policy syntax: {stripped_line}")

    return groups_to_modify, policy_usages

def generate_policy_report(policy_usages):
    """Write a report detailing which policies are blocking object deletion."""
    if not policy_usages:
        logging.info(f"No active firewall policies are using these objects. Skipping {POLICY_REPORT}.")
        return

    logging.info(f"--- Generating Policy Usage Report ({POLICY_REPORT}) ---")
    
    policy_usages.sort(key=lambda x: (x['vdom'], int(x['policy_id']) if x['policy_id'].isdigit() else x['policy_id']))

    try:
        with open(POLICY_REPORT, mode='w', encoding='utf-8') as f:
            f.write("======================================================================\n")
            f.write("                       POLICY CLEANUP REQUIRED\n")
            f.write("======================================================================\n")
            f.write("The following objects are actively used in Firewall Policies.\n")
            f.write("You must manually remove them from these policies via the FortiManager\n")
            f.write("GUI before FortiOS will allow them to be deleted.\n")
            f.write("======================================================================\n\n")
            
            for usage in policy_usages:
                f.write(f"VDOM:       {usage['vdom']}\n")
                f.write(f"Policy ID:  {usage['policy_id']}\n")
                f.write(f"Direction:  {usage['direction']}\n")
                f.write(f"Object:     \"{usage['object']}\"\n")
                f.write("-" * 40 + "\n")
                
        logging.info(f"Policy report successfully written to {POLICY_REPORT}")
    except Exception as e:
        logging.error(f"Failed to write policy report: {e}")

def generate_fmg_script(groups_to_modify):
    """Generate the FortiManager CLI script (Group removal unselect commands only)."""
    if not groups_to_modify:
        logging.info("No groups require modification. Skipping FMG script generation.")
        return

    logging.info(f"--- Generating FortiManager CLI Script ({OUTPUT_FMG_CONFIG}) ---")
    
    try:
        with open(OUTPUT_FMG_CONFIG, mode='w', encoding='utf-8') as f:
            f.write("# ==================================================================\n")
            f.write("# FortiManager CLI Script - Inactive Address Group Cleanup\n")
            f.write("# Target: FortiOS 7.6 (Device Manager -> Scripts)\n")
            f.write("# This script explicitly unbinds inactive objects from Address Groups.\n")
            f.write("# Bulk object deletions are handled natively via FMG UI tooling.\n")
            f.write("# ==================================================================\n\n")
            
            for vdom, vdom_groups in groups_to_modify.items():
                if not vdom_groups:
                    continue
                    
                f.write(f"config vdom\n")
                f.write(f"edit \"{vdom}\"\n\n")
                
                # Strip the objects out of any address groups in this VDOM
                f.write("    config firewall addrgrp\n")
                for group_name, members in vdom_groups.items():
                    f.write(f"        edit \"{group_name}\"\n")
                    for member in members:
                        f.write(f"            unselect member \"{member}\"\n")
                    f.write("        next\n")
                f.write("    end\n\n")
                f.write("next\n\n")
                
        logging.info(f"Success! Script written to '{OUTPUT_FMG_CONFIG}'.")
    except Exception as e:
        logging.error(f"Failed to write FMG config script: {e}")

# ==========================================
# Main Execution Block
# ==========================================
if __name__ == "__main__":
    logging.info("Starting Comprehensive FortiGate Object Cleanup Check...")
    
    # 1. Locate all necessary files dynamically
    conf_file, routing_file, whitelist_file = find_files()
    
    # 2. Extract networks into actionable data structures
    active_nets = load_networks_from_file(routing_file, "Active Networks")
    whitelist_nets = load_networks_from_file(whitelist_file, "Summary Ranges")
    
    # 3. [Phase 1] Extract FortiOS firewall objects
    fw_objs = parse_fortigate_objects(conf_file)
    
    # 4. [Phase 1] Evaluate objects for inactivity
    inactive_data = compare_and_find_inactive(fw_objs, active_nets, whitelist_nets)
    
    # 5. [Phase 1] Output the initial evaluation and retain the set of unique names 
    inactive_obj_names = export_inactive_to_txt(inactive_data)
    
    if inactive_obj_names:
        # 6. [Phase 2] Parse the config again for Group and Policy usages
        grps_to_modify, pol_usages = parse_config_for_usage(conf_file, inactive_obj_names)
        
        # 7. [Phase 2] Generate outputs for FMG UI handling
        generate_policy_report(pol_usages)
        generate_fmg_script(grps_to_modify)
    
    logging.info("Comprehensive script execution finished.")
