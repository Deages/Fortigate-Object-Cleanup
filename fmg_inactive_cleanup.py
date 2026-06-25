import os
import glob
import csv
import logging
import shlex
from collections import defaultdict

# ==========================================
# Configuration and Setup
# ==========================================

LOG_FILE = "fmg_script_log.txt"
INPUT_CSV = "inactive_addresses.csv"
OUTPUT_TXT = "fmg_script_output.txt"
POLICY_REPORT = "policy_id_cleanup.txt"

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, mode='w'),
        logging.StreamHandler()
    ]
)

def find_conf_file():
    """Locate the FortiGate config file."""
    conf_files = glob.glob('*.conf') + [f for f in glob.glob('*.txt') if 'fw' in f.lower() or 'conf' in f.lower()]
    
    # Ensure we don't accidentally parse our own outputs
    for ignore in [OUTPUT_TXT, POLICY_REPORT, LOG_FILE]:
        if ignore in conf_files:
            conf_files.remove(ignore)

    if not conf_files:
        logging.error("No FortiGate .conf (or valid .txt) config file found in the current directory.")
        exit(1)

    selected_conf = conf_files[0]
    logging.info(f"Selected FortiGate Config: {selected_conf}")
    return selected_conf

def load_inactive_objects():
    """Load the target inactive objects from the Phase 1 CSV."""
    if not os.path.exists(INPUT_CSV):
        logging.error(f"Could not find '{INPUT_CSV}'. Please ensure Phase 1 has been run.")
        exit(1)

    inactive_objects = set()
    logging.info(f"--- Loading Inactive Objects from {INPUT_CSV} ---")
    
    try:
        with open(INPUT_CSV, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                obj_name = row[0].strip()
                if obj_name.lower() in ['object name', 'name']:
                    continue
                inactive_objects.add(obj_name)
                
        logging.info(f"Loaded {len(inactive_objects)} objects to process.")
        return inactive_objects
    except Exception as e:
        logging.error(f"Failed to read CSV: {e}")
        exit(1)

def parse_config_and_map(conf_filepath, inactive_objects):
    """
    State-machine parser that reads the FortiOS config to find:
    1. Which VDOM each inactive object belongs to.
    2. Which Address Groups contain the inactive objects.
    3. Which Firewall Policies are actively using the inactive objects.
    """
    objects_by_vdom = defaultdict(set)
    groups_to_modify = defaultdict(lambda: defaultdict(set))
    policy_usages = []

    logging.info("--- Parsing FortiGate Configuration for Object Usage ---")

    current_vdom = "root"
    current_config = None
    current_edit = None

    with open(conf_filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            stripped_line = line.strip()

            if not stripped_line:
                continue

            # State Machine: Context Tracking
            if stripped_line.startswith("config vdom"):
                pass # Just a marker, the 'edit' line below captures the VDOM name
            
            elif stripped_line.startswith("config "):
                current_config = stripped_line[7:].strip()
            
            elif stripped_line.startswith("edit "):
                # Extract the name safely (removes surrounding quotes if they exist)
                name = stripped_line[5:].strip().strip('"')
                
                if current_config is None:
                    # If we aren't in a sub-config, 'edit' dictates the VDOM
                    current_vdom = name
                else:
                    # Otherwise, it dictates the object/group/policy being edited
                    current_edit = name
                    
                    # Track which VDOM owns the object so we can write the correct delete statement later
                    if current_config == "firewall address" and current_edit in inactive_objects:
                        objects_by_vdom[current_vdom].add(current_edit)
                        logging.debug(f"[VDOM: {current_vdom}] Found target object definition: '{current_edit}'")

            elif stripped_line == "next":
                current_edit = None
                if current_config is None:
                    current_vdom = "root" # Dropped out of a VDOM block
                    
            elif stripped_line == "end":
                current_config = None

            # State Machine: Data Extraction based on context
            elif current_edit:
                # 1. Address Groups
                if current_config == "firewall addrgrp" and stripped_line.startswith("set member "):
                    try:
                        # shlex handles FortiOS quotes gracefully (e.g. set member "Obj 1" "Obj 2")
                        tokens = shlex.split(stripped_line)
                        members = tokens[2:]
                        for m in members:
                            if m in inactive_objects:
                                groups_to_modify[current_vdom][current_edit].add(m)
                                logging.info(f"[VDOM: {current_vdom}] Object '{m}' found in Address Group '{current_edit}'. Queued for unselect.")
                    except ValueError:
                        logging.warning(f"Line {line_num}: Malformed group member syntax: {stripped_line}")

                # 2. Firewall Policies
                elif current_config == "firewall policy" and (stripped_line.startswith("set srcaddr ") or stripped_line.startswith("set dstaddr ")):
                    try:
                        tokens = shlex.split(stripped_line)
                        direction = tokens[1] # 'srcaddr' or 'dstaddr'
                        members = tokens[2:]
                        for m in members:
                            if m in inactive_objects:
                                policy_usages.append({
                                    'vdom': current_vdom,
                                    'policy_id': current_edit,
                                    'direction': direction,
                                    'object': m
                                })
                                logging.warning(f"[VDOM: {current_vdom}] Policy {current_edit} is actively using target object '{m}' as {direction}.")
                    except ValueError:
                        logging.warning(f"Line {line_num}: Malformed policy syntax: {stripped_line}")

    return objects_by_vdom, groups_to_modify, policy_usages

def generate_policy_report(policy_usages):
    """Write the report detailing which policies are blocking deletion."""
    if not policy_usages:
        logging.info(f"No active firewall policies are using these objects. Skipping {POLICY_REPORT}.")
        return

    logging.info(f"--- Generating Policy Usage Report ({POLICY_REPORT}) ---")
    
    # Sort for readability: VDOM -> Policy ID
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

def generate_fmg_script(objects_by_vdom, groups_to_modify):
    """Generate the final FortiManager CLI script, separated by VDOM."""
    if not objects_by_vdom:
        logging.info("No mapped objects found in the configuration to delete.")
        return

    logging.info(f"--- Generating FortiManager CLI Script ({OUTPUT_TXT}) ---")
    
    try:
        with open(OUTPUT_TXT, mode='w', encoding='utf-8') as f:
            f.write("# ==================================================================\n")
            f.write("# FortiManager CLI Script - Inactive Address Object Cleanup\n")
            f.write("# Target: FortiOS 7.6 (Device Manager -> Scripts)\n")
            f.write("# This script explicitly unbinds objects from Address Groups first,\n")
            f.write("# and then deletes the objects per VDOM.\n")
            f.write("# ==================================================================\n\n")
            
            for vdom, objects in objects_by_vdom.items():
                f.write(f"config vdom\n")
                f.write(f"edit \"{vdom}\"\n\n")
                
                # Step 1: Strip the objects out of any address groups in this VDOM
                vdom_groups = groups_to_modify.get(vdom, {})
                if vdom_groups:
                    f.write("    config firewall addrgrp\n")
                    for group_name, members in vdom_groups.items():
                        f.write(f"        edit \"{group_name}\"\n")
                        for member in members:
                            # 'unselect' is safe FortiOS CLI syntax to remove a specific list entry
                            f.write(f"            unselect member \"{member}\"\n")
                        f.write("        next\n")
                    f.write("    end\n\n")
                
                # Step 2: Delete the objects in this VDOM
                if objects:
                    f.write("    config firewall address\n")
                    for obj in sorted(objects):
                        f.write(f"        delete \"{obj}\"\n")
                    f.write("    end\n\n")
                    
                f.write("next\n\n")
                
        logging.info(f"Success! Script written to '{OUTPUT_TXT}'.")
    except Exception as e:
        logging.error(f"Failed to write FMG script: {e}")

# ==========================================
# Main Execution Block
# ==========================================
if __name__ == "__main__":
    logging.info("Starting Phase 2: FortiManager Cleanup Script Generator...")
    
    # 1. Locate files
    conf_file = find_conf_file()
    
    # 2. Get target objects from Phase 1
    inactive_objs = load_inactive_objects()
    
    # 3. Parse the FortiOS backup to map VDOMs, Groups, and Policies
    objs_by_vdom, grps_to_modify, pol_usages = parse_config_and_map(conf_file, inactive_objs)
    
    # 4. Generate the manual cleanup report for policies
    generate_policy_report(pol_usages)
    
    # 5. Generate the FMG CLI automated script
    generate_fmg_script(objs_by_vdom, grps_to_modify)
    
    logging.info("Phase 2 execution finished.")
