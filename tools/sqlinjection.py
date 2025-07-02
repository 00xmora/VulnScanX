from concurrent.futures import ThreadPoolExecutor
import re
import os
import time
import subprocess
import threading
from urllib.parse import parse_qs, urlparse, urlencode
import logging
import json
from sqlalchemy.exc import IntegrityError
from tools.database import Vulnerability, Endpoint # Import the Vulnerability and Endpoint models

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

# Function to execute a command and capture output
def run_command_capture_output(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False) # check=False because sqlmap exits with 1 on no findings
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        print(f"{RED}An unexpected error occurred during command execution: {e}{NC}")
        return "", str(e), 1

def run_sqlmap(endpoint_data, output_dir, session, scan_id):
    url = endpoint_data['url']
    method = endpoint_data.get('method', 'GET').upper()
    headers = endpoint_data.get('extra_headers', {})
    body_params = endpoint_data.get('body_params', {})

    print(f"{YELLOW}[+] Running SQLMap for SQL Injection scanning on: {url} ({method}){NC}")

    # Check if sqlmap is installed
    if not subprocess.run("command -v sqlmap", shell=True, capture_output=True).returncode == 0:
        print(f"{RED}[!] SQLMap is not installed or not in PATH. Please install it to use SQL Injection scanning. Skipping.{NC}")
        return

    # Create a unique output directory for each URL/request to avoid conflicts for sqlmap
    parsed_url_netloc = urlparse(url).netloc.replace('.', '_').replace(':', '_')
    url_hash = str(abs(hash(url + method + str(body_params))))[:8] # More robust hash
    sqlmap_output_path = os.path.join(output_dir, f"sqlmap_{parsed_url_netloc}_{url_hash}")
    os.makedirs(sqlmap_output_path, exist_ok=True)

    sqlmap_command_parts = [
        "sqlmap",
        f"--output-dir=\"{sqlmap_output_path}\"",
        "--batch",
        "--risk=3", # Medium risk, can be adjusted
        "--level=3", # Medium level, can be adjusted
        "--parse-errors", # Helps identify potential SQL errors
        "--skip-waf" # Attempt to bypass WAF/IDS
    ]

    temp_req_file_path = None

    if method == "GET":
        sqlmap_command_parts.append(f"-u \"{url}\"")
        if headers:
            # sqlmap accepts headers with --headers. Format: "Header1: Val1,Header2: Val2"
            header_str = ",".join([f"{k}: {v}" for k, v in headers.items()])
            sqlmap_command_parts.append(f"--headers=\"{header_str}\"")
    else: # POST, PUT, DELETE, PATCH
        # For non-GET requests, it's generally best to use --data or --req
        # If body_params are present, we construct --data or a --req file.
        # SQLMap can handle JSON or form-urlencoded via --data if Content-Type is set.
        # For complex scenarios or if headers are crucial for the body, --req is better.

        # Let's use --data if it's simple form/json or create a --req file otherwise.
        
        # Check if body_params is a dictionary, convert from string if needed
        if isinstance(body_params, str):
            try:
                body_params = json.loads(body_params)
            except json.JSONDecodeError:
                # If not JSON, assume it's URL-encoded form data string and parse it.
                body_params = parse_qs(body_params)
        
        if body_params:
            content_type = headers.get("Content-Type", "").lower()
            if "application/json" in content_type:
                data_string = json.dumps(body_params)
                sqlmap_command_parts.append(f"--data=\"{data_string}\"")
                sqlmap_command_parts.append("--json-req") # Inform sqlmap it's a JSON request
            elif "application/x-www-form-urlencoded" in content_type or not content_type: # Default to form-urlencoded
                data_string = urlencode(body_params)
                sqlmap_command_parts.append(f"--data=\"{data_string}\"")
            else:
                # Fallback to --req file for other content types or complex structures
                temp_req_filename = f"sqlmap_req_{abs(hash(url))}_{method}.txt"
                temp_req_file_path = os.path.join(sqlmap_output_path, temp_req_filename)
                
                with open(temp_req_file_path, "w") as f:
                    # Write request line (path and query)
                    parsed_url = urlparse(url)
                    path_with_query = f"{parsed_url.path}"
                    if parsed_url.query:
                        path_with_query += f"?{parsed_url.query}"
                    f.write(f"{method} {path_with_query} HTTP/1.1\n")
                    f.write(f"Host: {parsed_url.netloc}\n")
                    for header_key, header_value in headers.items():
                        f.write(f"{header_key}: {header_value}\n")
                    f.write("\n") # End of headers
                    if isinstance(body_params, dict):
                        f.write(json.dumps(body_params) if "application/json" in content_type else urlencode(body_params))
                    else:
                        f.write(str(body_params)) # Write raw body if not dict
                sqlmap_command_parts.append(f"--req=\"{temp_req_file_path}\"")

        sqlmap_command_parts.append(f"-u \"{url}\"") # URL must still be provided with --req
        sqlmap_command_parts.append(f"--method=\"{method}\"")
        if headers:
            header_str = ",".join([f"{k}: {v}" for k, v in headers.items()])
            sqlmap_command_parts.append(f"--headers=\"{header_str}\"")
    
    sqlmap_command = " ".join(sqlmap_command_parts)
    
    sqlmap_log_file = os.path.join(sqlmap_output_path, "sqlmap_log.txt")
    sqlmap_error_log_file = os.path.join(sqlmap_output_path, "sqlmap_error.txt")

    try:
        process = subprocess.run(sqlmap_command, shell=True, capture_output=True, text=True)
        stdout = process.stdout
        stderr = process.stderr

        with open(sqlmap_log_file, "w") as f:
            f.write(stdout)
        with open(sqlmap_error_log_file, "w") as f:
            f.write(stderr)

        if "is vulnerable" in stdout.lower() or "vulnerable" in stdout.lower() or "found" in stdout.lower():
            vulnerability_type = "SQL Injection"
            severity = "high"
            
            details_match = re.search(r"the parameter '(.+?)' is vulnerable\.(.*?)(?:\n\n|\Z)", stdout, re.DOTALL | re.IGNORECASE)
            parameter = details_match.group(1).strip() if details_match else "N/A"
            tech_match = re.search(r"It is injectable with the following(.*?)techniques: (.*?)(?:\n|$)", stdout, re.DOTALL | re.IGNORECASE)
            technique = tech_match.group(2).strip() if tech_match else "N/A"

            vuln_data = {
                "vulnerability": vulnerability_type,
                "severity": severity,
                "url": url,
                "method": method,
                "tool": "SQLMap",
                "parameter": parameter,
                "technique": technique,
                "sqlmap_stdout_summary": stdout[:1000],
                "description": f"SQL Injection detected by SQLMap on parameter '{parameter}' using {method} request. Techniques: {technique}. See sqlmap_log.txt for full details."
            }

            try:
                new_vulnerability = Vulnerability(
                    scan_id=scan_id,
                    vulnerability_data=json.dumps(vuln_data), # Store as JSON string
                    vulnerability_type=vuln_data["vulnerability"],
                    severity=vuln_data["severity"],
                    url=vuln_data["url"]
                )
                session.add(new_vulnerability)
                session.commit()
                print(f"{GREEN}   [+] SQL Injection vulnerability stored for: {url} ({method}){NC}")
            except IntegrityError:
                session.rollback()
                logger.info(f"Duplicate SQL Injection vulnerability found and skipped for URL: {url}")
            except Exception as db_e:
                session.rollback()
                logger.error(f"Error saving SQL Injection vulnerability to DB: {db_e}")
        else:
            print(f"{YELLOW}   [!] No SQL Injection vulnerability detected by SQLMap for: {url} ({method}){NC}")

    except Exception as e:
        print(f"{RED}An unexpected error occurred during SQLMap execution or processing for {url} ({method}): {e}{NC}")
    finally:
        if temp_req_file_path and os.path.exists(temp_req_file_path):
            os.remove(temp_req_file_path)
    print(f"{GREEN}[+] SQLMap scan for {url} ({method}) completed.{NC}")

# Main SQL Injection function
def sql_injection_test(output_dir, thread_count=1, delay=1, session=None, scan_id=None):
    """
    Performs SQL Injection testing on endpoints from the database using SQLMap.
    Results are stored in the database.
    Args:
        output_dir (str): Directory to store SQLMap output files.
        thread_count (int): Number of threads for concurrent SQLMap runs.
        delay (int): Delay in seconds between starting new SQLMap threads.
        session (sqlalchemy.orm.session.Session): SQLAlchemy session for database operations.
        scan_id (int): ID of the current scan in ScanHistory.
    """
    print(f"{YELLOW}[+] Starting SQL Injection scan...{NC}")
    
    if session is None or scan_id is None:
        print(f"{RED}[!] Database session or scan_id not provided. Cannot perform SQL Injection scan.{NC}")
        return

    # Fetch endpoints from the database for the current scan
    endpoints_to_test = session.query(Endpoint).filter_by(scan_id=scan_id).all()

    if not endpoints_to_test:
        print(f"{RED}[!] No endpoints found in the database for scan_id {scan_id} to test for SQL Injection.{NC}")
        return

    max_workers = int(thread_count) if thread_count and int(thread_count) > 0 else 1
    
    # Use ThreadPoolExecutor for concurrent processing, which is generally safer and
    # more efficient than manually managing threads with Semaphore for this type of task.
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for endpoint in endpoints_to_test:
            endpoint_data = {
                "url": endpoint.url,
                "method": endpoint.method,
                # Ensure body_params and extra_headers are parsed from JSON strings
                "body_params": json.loads(endpoint.body_params) if isinstance(endpoint.body_params, str) and endpoint.body_params else {},
                "extra_headers": json.loads(endpoint.extra_headers) if isinstance(endpoint.extra_headers, str) and endpoint.extra_headers else {}
            }
            # Submit the task to the executor
            futures.append(executor.submit(run_sqlmap, endpoint_data, output_dir, session, scan_id))
            if delay > 0:
                time.sleep(delay) # Apply delay between submitting tasks

        # Wait for all submitted tasks to complete
        for future in futures:
            future.result() # This will re-raise any exceptions from the threads

    print(f"{GREEN}[+] SQL Injection scan completed. Results stored in database.{NC}")

# This part is for direct testing of the module
if __name__ == "__main__":
    from tools.database import init_db, get_session, ScanHistory, Endpoint # For local testing

    temp_db_engine = init_db('sqlite:///test_sqlinjection.db')
    test_session = get_session(temp_db_engine)
    
    test_domain = "test-sqli-target.com"
    test_scan = test_session.query(ScanHistory).filter_by(domain=test_domain).first()
    if not test_scan:
        test_scan = ScanHistory(domain=test_domain)
        test_session.add(test_scan)
        test_session.commit()
    test_scan_id = test_scan.id

    dummy_output_dir = "test_sqli_output"
    os.makedirs(dummy_output_dir, exist_ok=True)
    
    # Add dummy endpoints to the database for testing GET/POST with SQLi
    dummy_endpoints_data = [
        {"url": "http://testphp.vulnweb.com/listproducts.php?cat=1", "method": "GET", "body_params": {}, "extra_headers": {}}, # Known vulnerable
        {"url": "http://example.com/login", "method": "POST", "body_params": {"username": "admin", "password": "password"}, "extra_headers": {"Content-Type": "application/x-www-form-urlencoded"}},
        {"url": "http://example.com/api/user/profile", "method": "PUT", "body_params": {"id": 1, "name": "test"}, "extra_headers": {"Content-Type": "application/json"}},
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

    print(f"{BLUE}[+] Running SQL Injection test with sqlmap integration...{NC}")
    # Corrected call for local testing:
    sql_injection_test(output_dir=dummy_output_dir, session=test_session, scan_id=test_scan_id, thread_count=2, delay=0.5)
    
    print(f"{BLUE}[+] Verifying results from database...{NC}")
    retrieved_vulns = test_session.query(Vulnerability).filter_by(scan_id=test_scan_id).all()
    for vuln in retrieved_vulns:
        print(f"   Vulnerability Found: {vuln.vulnerability_type} at {vuln.url} (Severity: {vuln.severity})")
        print(f"     Full Data: {vuln.vulnerability_data}")

    test_session.close()
    
    import shutil
    if os.path.exists(dummy_output_dir):
        try:
            shutil.rmtree(dummy_output_dir)
            print(f"{GREEN}[+] Cleaned up directory: {dummy_output_dir}{NC}")
        except OSError as e:
            print(f"{RED}Error removing directory {dummy_output_dir}: {e}{NC}")
    
    if os.path.exists('test_sqlinjection.db'):
        os.remove('test_sqlinjection.db')

    print(f"{GREEN}[+] SQL Injection test with SQLMap completed.{NC}")
