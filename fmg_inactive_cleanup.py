import csv
import logging
import os

# ==========================================
# Configuration
# ==========================================

INPUT_CSV = "inactive_addresses.csv"
OUTPUT_TXT = "fmg_script_output.txt"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def generate_fmg_script():
    logging.info("Starting FortiManager script generation...")

    if not os.path.exists(INPUT_CSV):
        logging.error(f"Could not find '{INPUT_CSV}'. Please ensure Phase 1 has been run.")
        exit(1)

    objects_to_delete = []

    # Read the CSV file
    try:
        with open(INPUT_CSV, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                # Skip empty lines
                if not row:
                    continue
                
                # The object name is always the first element in the row, 
                # regardless of whether the subnet is listed in the second column.
                obj_name = row[0].strip()
                
                # Skip header if one accidentally exists
                if obj_name.lower() in ['object name', 'name']:
                    continue
                    
                objects_to_delete.append(obj_name)
    except Exception as e:
        logging.error(f"Failed to read CSV: {e}")
        exit(1)

    if not objects_to_delete:
        logging.info("No objects found in the CSV to delete. Exiting.")
        return

    # Generate the FortiManager CLI Script
    logging.info(f"Found {len(objects_to_delete)} objects. Writing FMG CLI script...")
    
    try:
        with open(OUTPUT_TXT, mode='w', encoding='utf-8') as f:
            # Add a descriptive header (FortiOS/FMG ignores lines starting with #)
            f.write("# ==================================================================\n")
            f.write("# FortiManager CLI Script - Inactive Address Object Cleanup\n")
            f.write("# Target: FortiOS 7.6 (Device Manager -> Scripts)\n")
            f.write("# \n")
            f.write("# IMPORTANT NOTE ON GROUPS AND POLICIES:\n")
            f.write("# FortiOS natively protects objects that are actively referenced \n")
            f.write("# in an Address Group or Firewall Policy. If an object below is \n")
            f.write("# still in a group, the 'delete' command will fail safely for that \n")
            f.write("# specific line, leaving the rest to process successfully.\n")
            f.write("# ==================================================================\n\n")
            
            # Enter the firewall address configuration context
            f.write("config firewall address\n")
            
            # Iterate and write the delete commands
            for obj in objects_to_delete:
                # We wrap the object name in quotes to handle spaces (e.g., "CTC SSID")
                f.write(f'    delete "{obj}"\n')
                
            # Exit and save the configuration context
            f.write("end\n")
            
        logging.info(f"Success! Script written to '{OUTPUT_TXT}'.")
        logging.info("You can now copy the contents of that text file into your FortiManager Scripts section.")
        
    except Exception as e:
        logging.error(f"Failed to write to text file: {e}")

if __name__ == "__main__":
    generate_fmg_script()
