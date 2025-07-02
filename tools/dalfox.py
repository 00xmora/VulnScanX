import subprocess
import json
import os
import logging
from sqlalchemy.exc import IntegrityError
from tools.database import Vulnerability # Import the Vulnerability model
from tools.database import try_save_vulnerability

# Define colors for console output
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m'
BOLD = '\033[1m'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Function to execute a command and capture output (for general use)
def run_command_capture_output(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False) # check=False because external tools might exit with non-zero on no findings
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        print(f"{RED}An unexpected error occurred during command execution: {e}{NC}")
        return "", str(e), 1

# Helper to save a vulnerability, handling duplicates and errors.
def try_save_vulnerability(vuln_data, session, scan_id):
    try:
        new_vulnerability = Vulnerability(
            scan_id=scan_id,
            vulnerability_data=vuln_data,
            vulnerability_type=vuln_data["vulnerability"],
            severity=vuln_data["severity"],
            url=vuln_data["url"]
        )
        session.add(new_vulnerability)
        session.commit()
        print(f"{GREEN}   [+] XSS vulnerability stored for: {vuln_data['url']}{NC}")
    except IntegrityError:
        session.rollback()
        logger.info(f"Duplicate XSS vulnerability found and skipped for URL: {vuln_data.get('url')}")
    except Exception as db_e:
        session.rollback()
        logger.error(f"Error saving XSS vulnerability to DB: {db_e}")

# DalFox outputs the POC only so we decoded the payload
def run_dalfox_on_url(urls_file_path, url_directory, session=None, scan_id=None):
    print(f"{YELLOW}[+] Running DalFox for XSS scanning...{NC}")
    
    if not os.path.exists(urls_file_path):
        print(f"{RED}[!] URLs file not found at {urls_file_path}. Skipping DalFox scan.{NC}")
        return

    # DalFox outputs a JSON file with findings
    dalfox_output_file = os.path.join(url_directory, "dalfox_results.json")
    
    # Check if DalFox is installed
    stdout, stderr, returncode = run_command_capture_output("command -v dalfox")
    if returncode != 0:
        print(f"{RED}[!] DalFox is not installed or not in PATH. Please install it to use XSS scanning. Skipping.{NC}")
        return

    # Using -o for JSON output, --skip-bav to potentially speed up if not needed
    # Using --no-gandi to avoid issues with Gandi API
    # Using --mass-json-output to get multiple scan results in one JSON
    dalfox_command = f"dalfox file {urls_file_path} --output {dalfox_output_file} --no-gandi --mass-json-output"
    
    try:
        process = subprocess.run(dalfox_command, shell=True, capture_output=True, text=True, check=False) # Check false to handle non-zero exit on no findings
        print(f"{GREEN}[+] DalFox scan completed for URLs in {urls_file_path}{NC}")

        if os.path.exists(dalfox_output_file):
            with open(dalfox_output_file, 'r') as f:
                dalfox_raw_results = f.read()
            
            dalfox_json_results = []
            if dalfox_raw_results.strip():
                # Attempt to split concatenated JSON objects
                for line in dalfox_raw_results.strip().split('\n'):
                    try:
                        dalfox_json_results.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.warning(f"Could not decode line as JSON from DalFox output: {line[:100]}...")
                        pass # Skip invalid lines
            
            # Process and store vulnerabilities in the database
            if session and scan_id is not None:
                for result_obj in dalfox_json_results:
                    found_url = result_obj.get("url")
                    vulnerability_type_raw = result_obj.get("type") # e.g., "reflected_xss"
                    payload = result_obj.get("payload")
                    method = result_obj.get("method", "GET") # DalFox might not always provide method, default to GET

                    if found_url and vulnerability_type_raw:
                        vulnerability_type = vulnerability_type_raw.replace("_", " ").title()
                        if "xss" not in vulnerability_type.lower():
                            vulnerability_type = f"XSS ({vulnerability_type})"

                        severity = "medium" # Default severity
                        if "reflected" in vulnerability_type_raw or "stored" in vulnerability_type_raw:
                            severity = "high" # Often higher severity for these types

                        vuln_data = {
                            "vulnerability": vulnerability_type,
                            "severity": severity,
                            "url": found_url,
                            "method": method, # Include method in data
                            "payload": payload, # Include payload for more context
                            "tool_output": result_obj # Store raw tool output for debugging/details
                        }
                        
                        try_save_vulnerability(vuln_data, session, scan_id)
            else:
                print(f"{YELLOW}[!] Session or scan_id not provided. XSS results not stored in database.{NC}")
            
            os.remove(dalfox_output_file) # Clean up DalFox output file
            print(f"{GREEN}[+] DalFox results processed and stored in database.{NC}")
        else:
            print(f"{YELLOW}[!] No DalFox output file found at {dalfox_output_file}{NC}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Error running DalFox: {e}{NC}")
        print(f"DalFox stdout: {e.stdout}")
        print(f"DalFox stderr: {e.stderr}")
    except Exception as e:
        print(f"{RED}An unexpected error occurred during DalFox execution or processing: {e}{NC}")

# This part is for direct testing of the module
if __name__ == "__main__":
    # This is for testing purposes only. In production, DalFox is called from VulnScanX.py.
    # You would need to set up a dummy session and scan_id for testing.
    from tools.database import init_db, get_session, Base, ScanHistory # For local testing
    
    # Initialize a temporary database for testing
    temp_db_engine = init_db('sqlite:///test_dalfox.db')
    test_session = get_session(temp_db_engine)
    
    # Create a dummy ScanHistory record for testing
    test_domain = "example.com"
    test_scan = test_session.query(ScanHistory).filter_by(domain=test_domain).first()
    if not test_scan:
        test_scan = ScanHistory(domain=test_domain)
        test_session.add(test_scan)
        test_session.commit()
    test_scan_id = test_scan.id

    dummy_output_dir = "test_dalfox_output"
    os.makedirs(dummy_output_dir, exist_ok=True)
    dummy_urls_file = os.path.join(dummy_output_dir, "dummy_urls.txt")
    
    # Create a dummy urls.txt file for testing DalFox
    # Use a known vulnerable URL for testing
    with open(dummy_urls_file, "w") as f:
        f.write("http://testphp.vulnweb.com/listproducts.php?cat=1\n") 
        f.write("http://example.com/search?q=test\n") 

    print(f"{BLUE}[+] Running DalFox test with dummy data...{NC}")
    run_dalfox_on_url(dummy_urls_file, dummy_output_dir, session=test_session, scan_id=test_scan_id)
    
    print(f"{BLUE}[+] Verifying results from database...{NC}")
    retrieved_vulns = test_session.query(Vulnerability).filter_by(scan_id=test_scan_id).all()
    for vuln in retrieved_vulns:
        print(f"   Vulnerability Found: {vuln.vulnerability_type} at {vuln.url} (Severity: {vuln.severity})")
        print(f"     Full Data: {vuln.vulnerability_data}")

    test_session.close()
    
    # Clean up test files
    if os.path.exists(dummy_urls_file):
        os.remove(dummy_urls_file)
    
    # Clean up dummy directory only if it's empty
    if os.path.exists(dummy_output_dir):
        try:
            if not os.listdir(dummy_output_dir):
                os.rmdir(dummy_output_dir)
            else:
                print(f"{YELLOW}[!] Directory {dummy_output_dir} not empty, skipping rmdir.{NC}")
        except OSError as e:
            print(f"{RED}Error removing directory {dummy_output_dir}: {e}{NC}")
    
    # Clean up test database file
    if os.path.exists('test_dalfox.db'):
        os.remove('test_dalfox.db')

    print(f"{GREEN}[+] DalFox test completed.{NC}")