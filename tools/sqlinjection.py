import re
import os
import time
import subprocess
import threading
from urllib.parse import urlparse
import logging
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

# Function to execute a command and capture output
def run_command_capture_output(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False) # check=False because sqlmap exits with 1 on no findings
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        print(f"{RED}An unexpected error occurred during command execution: {e}{NC}")
        return "", str(e), 1

def run_sqlmap(url, output_dir, session, scan_id):
    print(f"{YELLOW}[+] Running SQLMap for SQL Injection scanning on: {url}{NC}")

    # Check if sqlmap is installed
    if not subprocess.run("command -v sqlmap", shell=True, capture_output=True).returncode == 0:
        print(f"{RED}[!] SQLMap is not installed or not in PATH. Please install it to use SQL Injection scanning. Skipping.{NC}")
        return

    # SQLMap can output JSON. Using --batch for automated execution.
    # --dump-format=JSON is for dumping data from databases, not for vulnerability reports directly.
    # We will use --dump to capture stdout/stderr for vulnerability messages.
    # Also, --level and --risk can be configured based on desired scan depth.
    # Using --forms, --crawl, --batch to make it more comprehensive.
    
    # Create a unique output directory for each URL to avoid conflicts for sqlmap
    # SQLMap's default output directory naming is quite robust, but explicit is better.
    parsed_url_netloc = urlparse(url).netloc.replace('.', '_').replace(':', '_')
    url_hash = str(abs(hash(url)))[:8] # Simple hash for unique folder name
    sqlmap_output_path = os.path.join(output_dir, f"sqlmap_{parsed_url_netloc}_{url_hash}")
    os.makedirs(sqlmap_output_path, exist_ok=True)

    sqlmap_command = (
        f"sqlmap -u \"{url}\" --batch --risk=3 --level=3 "
        f"--crawl=3 --forms --output-dir=\"{sqlmap_output_path}\" "
        f"--parse-errors" # Helps identify potential SQL errors even if no direct injection
    )
    
    # Redirecting stdout to a file to capture verbose output that might contain findings
    sqlmap_log_file = os.path.join(sqlmap_output_path, "sqlmap_log.txt")
    sqlmap_error_log_file = os.path.join(sqlmap_output_path, "sqlmap_error.txt")

    try:
        # sqlmap doesn't always exit with 0 on "no vulnerability", so check=True isn't always good.
        # Instead, we will check the captured output.
        process = subprocess.run(sqlmap_command, shell=True, capture_output=True, text=True)
        stdout = process.stdout
        stderr = process.stderr

        # Write outputs to files for debugging/review if needed
        with open(sqlmap_log_file, "w") as f:
            f.write(stdout)
        with open(sqlmap_error_log_file, "w") as f:
            f.write(stderr)

        if "is vulnerable" in stdout.lower() or "vulnerable" in stdout.lower() or "found" in stdout.lower():
            # Parse sqlmap's stdout for vulnerability details
            # This parsing is heuristic and might need refinement based on actual sqlmap output.
            vulnerability_type = "SQL Injection"
            severity = "high" # Default severity
            
            # Try to extract details from stdout
            details_match = re.search(r"the parameter '(.+?)' is vulnerable\.(.*?)(?:\n\n|\Z)", stdout, re.DOTALL | re.IGNORECASE)
            parameter = details_match.group(1).strip() if details_match else "N/A"
            tech_match = re.search(r"It is injectable with the following(.*?)techniques: (.*?)(?:\n|$)", stdout, re.DOTALL | re.IGNORECASE)
            technique = tech_match.group(2).strip() if tech_match else "N/A"

            vuln_data = {
                "vulnerability": vulnerability_type,
                "severity": severity,
                "url": url,
                "tool": "SQLMap",
                "parameter": parameter,
                "technique": technique,
                "sqlmap_stdout_summary": stdout[:1000] # Store a snippet of stdout
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
                print(f"{GREEN}   [+] SQL Injection vulnerability stored for: {url}{NC}")
            except IntegrityError:
                session.rollback()
                logger.info(f"Duplicate SQL Injection vulnerability found and skipped for URL: {url}")
            except Exception as db_e:
                session.rollback()
                logger.error(f"Error saving SQL Injection vulnerability to DB: {db_e}")
        else:
            print(f"{YELLOW}   [!] No SQL Injection vulnerability detected by SQLMap for: {url}{NC}")

    except Exception as e:
        print(f"{RED}An unexpected error occurred during SQLMap execution or processing for {url}: {e}{NC}")
    finally:
        # Clean up sqlmap's verbose output directory if no findings or on error.
        # However, sqlmap might create sub-directories (like `output/target_domain/`),
        # so simple os.rmdir won't work. For robust cleanup, `shutil.rmtree` is needed.
        # For now, leaving the directory for manual inspection if needed.
        # Or, can add: import shutil; shutil.rmtree(sqlmap_output_path)
        pass 
    print(f"{GREEN}[+] SQLMap scan for {url} completed.{NC}")

# Main SQL Injection function
def sql_injection_test(urls_file_path, output_dir, headers=None, thread_count=1, delay=1, session=None, scan_id=None):
    """
    Performs SQL Injection testing on URLs from a given file using SQLMap.
    Results are stored in the database.
    """
    print(f"{YELLOW}[+] Starting SQL Injection scan...{NC}")
    
    urls = read_urls_from_file(urls_file_path)
    if not urls:
        print(f"{RED}[!] No URLs found to test for SQL Injection.{NC}")
        return

    # Using ThreadPoolExecutor for concurrent SQLMap scans
    # sqlmap itself can handle concurrency, but if we call it per URL, Python threads help.
    # However, running multiple sqlmap instances concurrently might be resource intensive.
    # Limiting threads to a reasonable number.
    max_workers = int(thread_count) if thread_count and int(thread_count) > 0 else 1
    
    with threading.Semaphore(max_workers): # Use semaphore to limit active threads
        threads = []
        for url in urls:
            # Create a new thread for each URL
            t = threading.Thread(target=run_sqlmap, args=(url, output_dir, session, scan_id))
            threads.append(t)
            t.start()
            if delay > 0:
                time.sleep(delay) # Optional delay between starting threads

        for t in threads:
            t.join() # Wait for all threads to complete

    print(f"{GREEN}[+] SQL Injection scan completed. Results stored in database.{NC}")

# This part is for direct testing of the module
if __name__ == "__main__":
    # This is for testing purposes only. In production, this is called from VulnScanX.py.
    # You would need to set up a dummy session and scan_id for testing.
    from tools.database import init_db, get_session, Base, ScanHistory # For local testing

    # Initialize a temporary database for testing
    temp_db_engine = init_db('sqlite:///test_sqlinjection.db')
    test_session = get_session(temp_db_engine)
    
    # Create a dummy ScanHistory record for testing
    test_domain = "test-sqli-target.com"
    test_scan = test_session.query(ScanHistory).filter_by(domain=test_domain).first()
    if not test_scan:
        test_scan = ScanHistory(domain=test_domain)
        test_session.add(test_scan)
        test_session.commit()
    test_scan_id = test_scan.id

    dummy_output_dir = "test_sqli_output"
    os.makedirs(dummy_output_dir, exist_ok=True)
    dummy_urls_file = os.path.join(dummy_output_dir, "dummy_urls_sqli.txt")
    
    # Create a dummy urls.txt file for testing (example vulnerable URLs)
    with open(dummy_urls_file, "w") as f:
        f.write("http://testphp.vulnweb.com/listproducts.php?cat=1\n") # Known vulnerable URL
        f.write("http://example.com/search?q=test\n") # Benign URL

    print(f"{BLUE}[+] Running SQL Injection test with sqlmap integration...{NC}")
    sql_injection_test(dummy_urls_file, dummy_output_dir, session=test_session, scan_id=test_scan_id)
    
    print(f"{BLUE}[+] Verifying results from database...{NC}")
    retrieved_vulns = test_session.query(Vulnerability).filter_by(scan_id=test_scan_id).all()
    for vuln in retrieved_vulns:
        print(f"   Vulnerability Found: {vuln.vulnerability_type} at {vuln.url} (Severity: {vuln.severity})")
        print(f"     Full Data: {vuln.vulnerability_data}")

    test_session.close()
    
    # Clean up test files and directory
    if os.path.exists(dummy_urls_file):
        os.remove(dummy_urls_file)
    
    # SQLMap creates complex directory structures. For robust cleanup, shutil.rmtree is needed.
    # import shutil
    # if os.path.exists(dummy_output_dir):
    #     try:
    #         shutil.rmtree(dummy_output_dir)
    #         print(f"{GREEN}[+] Cleaned up directory: {dummy_output_dir}{NC}")
    #     except OSError as e:
    #         print(f"{RED}Error removing directory {dummy_output_dir}: {e}{NC}")
    print(f"{YELLOW}[!] Please manually clean up SQLMap output directory: {dummy_output_dir}{NC}")

    # Clean up test database file
    if os.path.exists('test_sqlinjection.db'):
        os.remove('test_sqlinjection.db')

    print(f"{GREEN}[+] SQL Injection test with SQLMap completed.{NC}")