import os
import glob
import csv
import logging
import ipaddress
import re
try:
    import pandas as pd
except ImportError:
    print("Error: pandas is not installed. Please run 'pip install pandas openpyxl'")
    exit(1)

# ==========================================
# Configuration and Setup
# ==========================================

LOG_FILE = "script_log.txt"
OUTPUT_CSV = "inactive_addresses.csv"
WHITELIST_FILE = "whitelist.txt"

# Target ranges to evaluate for inactivity (RFC 1918 + Specific Public Range)
TARGET_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('129.78.0.0/16')
]

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, mode='w'),
        logging.StreamHandler()
    ]
)

def find_files():
    """Locate the FortiGate config, active networks, and whitelist file."""
    # Look for configs. If a user saved it as .txt, try to catch it if 'fw' or 'conf' is in the name.
    conf_files = glob.glob('*.conf') + [f for f in glob.glob('*.txt') if 'fw' in f.lower() or 'conf' in f.lower()]
    
    # Look for data lists
    data_files = glob.glob('*.csv') + glob.glob('*.xlsx') + glob.glob('*.txt')
    
    # Remove script outputs from being parsed as inputs
    for ignore_file in [OUTPUT_CSV, LOG_FILE]:
        if ignore_file in data_files:
            data_files.remove(ignore_file)
        if ignore_file in conf_files:
            conf_files.remove(ignore_file)
            
    # Prevent the config file from being processed as a data file if it's a .txt
    for c in conf_files:
        if c in data_files:
            data_files.remove(c)

    if not conf_files:
        logging.error("No FortiGate .conf (or valid .txt) config file found in the current directory.")
        exit(1)

    selected_conf = conf_files[0]
    selected_routing = None
    selected_whitelist = None
    
    # Identify the whitelist file exactly by name
    # We do a case-insensitive check just to be safe
    for f in data_files.copy():
        if f.lower() == WHITELIST_FILE:
            selected_whitelist = f
            data_files.remove(f) # Remove so it isn't picked up as the routing file
            break

    # Any remaining .csv, .xlsx, or .txt file is assumed to be the active networks file
    if data_files:
        selected_routing = data_files[0]

    if not selected_routing:
        logging.error("No active networks .csv, .xlsx, or .txt file found.")
        exit(1)

    logging.info(f"Selected FortiGate Config: {selected_conf}")
    logging.info(f"Selected Active Networks File: {selected_routing}")
    
    if selected_whitelist:
        logging.info(f"Selected Whitelist File: {selected_whitelist}")
    else:
        logging.warning(f"No {WHITELIST_FILE} found. Whitelist logic will be bypassed.")
    
    return selected_conf, selected_routing, selected_whitelist

def load_networks_from_file(filepath, label="Networks"):
    """Read a CSV/XLSX/TXT and extract all valid CIDR IP networks."""
    networks = []
    if not filepath:
        return networks
        
    logging.info(f"--- Loading {label} ---")
    
    try:
        # Pandas handles structured files, standard open handles flat text
        if filepath.endswith('.xlsx'):
            df = pd.read_excel(filepath)
            raw_values = df.values.flatten().astype(str).tolist()
        elif filepath.endswith('.csv'):
            df = pd.read_csv(filepath)
            raw_values = df.values.flatten().astype(str).tolist()
        else: # Handle .txt files
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                raw_values = f.read().splitlines()
        
        for val in raw_values:
            val = val.strip()
            if not val or val.lower() == 'nan':
                continue
            try:
                # Convert string to IPv4Network. strict=False allows valid processing 
                # even if host bits are set in a subnet string.
                network = ipaddress.ip_network(val, strict=False)
                networks.append(network)
                logging.debug(f"Loaded {label.lower()}: {network}")
            except ValueError:
                pass # Skip headers, descriptions, or invalid strings silently
                
        logging.info(f"Successfully loaded {len(networks)} {label.lower()}.")
        return networks
        
    except Exception as e:
        logging.error(f"Failed to read {label} file: {e}")
        exit(1)

def parse_fortigate_objects(conf_filepath):
    """Parse the FortiGate config file to extract firewall address objects across all VDOMs."""
    fw_objects = []
    logging.info("--- Parsing FortiGate Configuration ---")
    
    in_firewall_address_section = False
    current_obj_name = None
    
    # Matches: edit "ObjectName"
    edit_regex = re.compile(r'^\s*edit\s+"?([^"\n]+)"?')
    # Matches: set subnet 192.168.1.0 255.255.255.0
    subnet_regex = re.compile(r'^\s*set\s+subnet\s+([\d\.]+)\s+([\d\.]+)')

    with open(conf_filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            
            # Enter address section parsing mode
            if line == "config firewall address":
                in_firewall_address_section = True
                continue
            
            # Exit address section parsing mode (safely continues reading file for other VDOMs)
            if in_firewall_address_section and line == "end":
                in_firewall_address_section = False
                continue
                
            if in_firewall_address_section:
                # Attempt to extract object name
                edit_match = edit_regex.match(line)
                if edit_match:
                    current_obj_name = edit_match.group(1)
                    continue
                
                # If we have an object name in memory, look for its subnet details
                if current_obj_name:
                    subnet_match = subnet_regex.match(line)
                    if subnet_match:
                        ip = subnet_match.group(1)
                        mask = subnet_match.group(2)
                        try:
                            # Translate FortiOS syntax into CIDR
                            network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                            fw_objects.append({
                                'name': current_obj_name,
                                'network': network
                            })
                            logging.debug(f"Found FW Object: '{current_obj_name}' -> {network}")
                        except ValueError as e:
                            logging.warning(f"Line {line_num}: Invalid subnet for object '{current_obj_name}' - {e}")
                        
                        # Flush current object so subsequent set commands aren't falsely mapped
                        current_obj_name = None

    logging.info(f"Successfully parsed {len(fw_objects)} subnet address objects from the firewall.")
    return fw_objects

def compare_and_find_inactive(fw_objects, active_networks, whitelist_networks):
    """Evaluate FW objects against scope constraints, whitelists, and active routing tables."""
    inactive_objects = []
    logging.info("--- Beginning Comparison ---")
    
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
            
        # 3. Whitelist Exclusion Check (Summary VRF Ranges, etc.)
        if obj_network in whitelist_networks:
            logging.debug(f"WHITELISTED: FW Object '{obj_name}' ({obj_network}) matches a summary range.")
            continue

        # 4. Active Routing Check (Is it a subset of a known active path?)
        is_active = False
        for active_net in active_networks:
            try:
                # subnet_of validates if the object resides inside the active network
                if obj_network.subnet_of(active_net):
                    logging.debug(f"VALID: FW Object '{obj_name}' ({obj_network}) is active within routed network ({active_net})")
                    is_active = True
                    break 
            except TypeError:
                continue
                
        # If it passes constraints but fails the active routing check, flag for deletion
        if not is_active:
            logging.warning(f"INACTIVE: FW Object '{obj_name}' ({obj_network}) is NOT found in active routing networks.")
            inactive_objects.append({
                'name': obj_name,
                'subnet': str(obj_network)
            })
            
    return inactive_objects

def export_inactive_to_csv(inactive_objects):
    """De-duplicate, sort, format, and write the inactive objects to a final CSV."""
    if not inactive_objects:
        logging.info(f"Great news! No inactive objects found. Skipping creation of {OUTPUT_CSV}.")
        return

    # Deduplication (Handles objects duplicated across multiple VDOMs/VRFs)
    unique_inactive = []
    seen = set()
    for obj in inactive_objects:
        identifier = (obj['name'], obj['subnet'])
        if identifier not in seen:
            seen.add(identifier)
            unique_inactive.append(obj)
            
    inactive_objects = unique_inactive

    # Sort numerically by IP subnet
    inactive_objects.sort(key=lambda x: ipaddress.ip_network(x['subnet'], strict=False))

    logging.info(f"--- Exporting {len(inactive_objects)} unique inactive objects to {OUTPUT_CSV} ---")
    try:
        with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            for obj in inactive_objects:
                name = obj['name']
                subnet_str = obj['subnet']
                net_obj = ipaddress.ip_network(subnet_str, strict=False)
                base_ip_str = str(net_obj.network_address)
                
                # Intelligent string formatting logic
                # Regex boundary check ensures we don't accidentally match 10.1.1.1 
                # against a custom name like "Server_10.1.1.15"
                ip_pattern = r'(?<!\d)' + re.escape(base_ip_str) + r'(?!\d)'
                
                # If the exact IP or the full CIDR notation is found anywhere within the object name
                # write a clean single-column line. Otherwise, retain the custom name alongside the IP.
                if re.search(ip_pattern, name) or subnet_str in name:
                    writer.writerow([name])
                else:
                    writer.writerow([name, subnet_str])
                    
        logging.info(f"Export complete. Check {OUTPUT_CSV} for objects to delete.")
    except Exception as e:
        logging.error(f"Failed to write to CSV: {e}")

# ==========================================
# Main Execution Block
# ==========================================
if __name__ == "__main__":
    logging.info("Starting FortiGate Object Cleanup Check...")
    
    # 1. Locate working files dynamically
    conf_file, routing_file, whitelist_file = find_files()
    
    # 2. Extract networks into actionable data structures
    active_nets = load_networks_from_file(routing_file, "Active Networks")
    whitelist_nets = load_networks_from_file(whitelist_file, "Summary Ranges")
    
    # 3. Extract FortiOS firewall objects
    fw_objs = parse_fortigate_objects(conf_file)
    
    # 4. Compare datasets based on specific logic
    inactive = compare_and_find_inactive(fw_objs, active_nets, whitelist_nets)
    
    # 5. Output finalized intelligence
    export_inactive_to_csv(inactive)
    
    logging.info("Script execution finished.")
