#!/usr/bin/env python3

import os
import shutil
import configparser
import logging
import json
from pathlib import Path
from urllib.parse import urlparse
import threading

# Import from new modules
from tools.browser_utils import get_selenium_driver # Only needed for the interactive login prompt if the main app doesn't call crawl_website directly
from tools.subdomain_enum import get_subdomains_from_free_services, passive_subdomain_enum, filter_live_domains, active_subdomain_enum, set_api_keys
from tools.url_crawling import passive_url_crawl, crawl_website ,jslinks
from tools.database import init_db, get_session, ScanHistory, ReconResult, Endpoint # Import all necessary DB components

# Define colors (kept for autorecon's own output formatting)
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m'
BOLD = '\033[1m'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration
config = configparser.ConfigParser()
config_file = 'config.ini'
script_dir = Path(__file__).parent
config_file_path = script_dir / config_file

if os.path.exists(config_file_path):
    config.read(config_file_path)
else:
    config['API_KEYS'] = {
        'pentest_tools': '',
        'securitytrails': '',
        'virustotal': '',
        'dnsdumpster': '',
        'crtsh': '',
        'subdomainfinder': '',
        'findsubdomains': '',
        'netcraft': '',
        'socradar': '',
        'waybackmachine': ''
    }
    with open(config_file_path, 'w') as f:
        config.write(f)
    print(f"{YELLOW}[+] Created default config.ini. Please add your API keys if available.{NC}")

# Set API keys in the subdomain_enum module
set_api_keys(
    config['API_KEYS'].get('pentest_tools', ''),
    config['API_KEYS'].get('securitytrails', ''),
    config['API_KEYS'].get('virustotal', '')
)


def print_banner():
    print(f"{CYAN}{BOLD}")
    print(r"                                                         ")
    print(r"             _       _____                             ")
    print(r"   /\        | |     |  __ \                            ")
    print(r"  /  \  _   _| |_ ___ | |__) |___  ___ ___  _ __  ")
    print(r" / /\ \| | | | __/ _ \|  _  // _ \/ __/ _ \| '_ \ ")
    print(r"/ ____ \ |_| | || (_) | | \ \  __/ (_| (_) | | | |")
    print(r"/_/    \_\__,_|\__\___/|_|  \_\___|\___\___/|_| |_|")
    print(f"{NC}")
    print(f"{YELLOW}{BOLD}By: omar samy{NC}")
    print(f"{BLUE}{BOLD}Twitter: @00xmora{NC}")
    print("===================================================\n")

def setup_project(project_name):
    """
    Sets up the project directory.
    Args:
        project_name (str): The name of the project.
    Returns:
        Path: The path to the project directory.
    """
    project_path = Path(project_name).resolve()
    project_path.mkdir(parents=True, exist_ok=True)
    print(f"{GREEN}{BOLD}[+] Project directory created: {project_name}{NC}")
    return project_path

def setup_domain_directory(project_path, domain):
    """
    Sets up a domain-specific directory within the project.
    Args:
        project_path (Path): The path to the project directory.
        domain (str): The domain name.
    Returns:
        Path: The path to the domain directory.
    """
    safe_domain = domain.replace('.', '_').replace(':', '_')
    target_path = (project_path / safe_domain).resolve()
    target_path.mkdir(parents=True, exist_ok=True)
    print(f"{BLUE}[+] Directory created: {project_path}/{safe_domain}{NC}")
    return target_path


def autorecon(url, url_directory=None, headers=None, max_pages=50, threads=4, session=None, scan_id=None,
              passive_crawl_enabled=False, active_crawl_enabled=False, open_browser_for_active_crawl=False,
              passive_subdomain_enabled=False, active_subdomain_enabled=False, wordlist_path=None,
              login_event=None):
    """
    Perform reconnaissance on a target URL with optional subdomain enumeration and crawling.

    Args:
        url (str): Target URL or domain.
        url_directory (str): Directory to store output files (still used by some tools).
        headers (dict, optional): Custom HTTP headers as a dictionary.
        max_pages (int): Maximum number of pages to crawl.
        threads (int): Number of threads for concurrent tasks (e.g., passive subdomain enum).
        session (sqlalchemy.orm.session.Session): SQLAlchemy session for database operations.
        scan_id (int): ID of the current scan in ScanHistory.
        passive_crawl_enabled (bool): Enable passive URL crawling.
        active_crawl_enabled (bool): Enable active URL crawling using Selenium.
        open_browser_for_active_crawl (bool): If True, open browser for active crawling (requires active_crawl_enabled).
        passive_subdomain_enabled (bool): Enable passive subdomain enumeration.
        active_subdomain_enabled (bool): Enable active subdomain enumeration.
        wordlist_path (str, optional): Path to the wordlist for active enumeration tools.
        login_event (threading.Event, optional): Event to signal completion of manual login.
    
    Returns:
        dict: Results containing subdomains, endpoints, and any errors.
    """
    print_banner()
    
    if not url_directory:
        print(f"{RED}{BOLD}Error: url_directory is required{NC}")
        return {"error": "url_directory is required"}
    
    domain = urlparse(url).netloc or url
    project_name = url_directory
    
    original_cwd = os.getcwd()
    try:
        project_path = setup_project(project_name)
        target_dir_path = setup_domain_directory(project_path, domain)
        os.chdir(target_dir_path)

        result = {"subdomains": [], "endpoints": [], "error": None}
        
        if passive_subdomain_enabled:
            print(f"{CYAN}{BOLD}[+] Performing passive subdomain enumeration for {domain}{NC}")
            get_subdomains_from_free_services(domain, session, scan_id)
            passive_subdomain_enum(domain, threads, session, scan_id)
            filter_live_domains(session, scan_id)
        
        if active_subdomain_enabled:
            print(f"{CYAN}{BOLD}[+] Performing active subdomain enumeration for {domain}{NC}")
            active_subdomain_enum(domain, session, scan_id, wordlist_path)
            filter_live_domains(session, scan_id)

        db_subdomains = session.query(ReconResult).filter(
            ReconResult.scan_id == scan_id,
            ReconResult.data_type.in_(["subdomain", "live_subdomain"])
        ).all()
        result["subdomains"] = [s.value for s in db_subdomains]

        if passive_crawl_enabled:
            print(f"{YELLOW}[+] Running passive URL crawling...{NC}")
            passive_url_crawl(domain, session, scan_id)
            jslinks(domain, recursive=True, headers=headers, session=session, scan_id=scan_id)

        if active_crawl_enabled:
            print(f"{YELLOW}[+] Running active URL crawling with Selenium crawler...{NC}")
            endpoints = crawl_website(url, headers=headers, max_pages=max_pages, 
                                      headless=not open_browser_for_active_crawl, 
                                      session=session, scan_id=scan_id, 
                                      interactive_login=open_browser_for_active_crawl,
                                      login_event=login_event)
            result["endpoints"].extend(endpoints)
        
        db_endpoints = session.query(Endpoint).filter(
            Endpoint.scan_id == scan_id
        ).all()
        result["endpoints"] = [{
            "url": e.url, 
            "method": e.method, 
            "body_params": json.loads(e.body_params) if e.body_params else {},
            "extra_headers": json.loads(e.extra_headers) if e.extra_headers else {}
        } for e in db_endpoints]

        print(f"{GREEN}{BOLD}[+] All selected reconnaissance tasks completed. Results stored in database and '{url_directory}' directory{NC}")
        return result
    
    except Exception as e:
        logger.error(f"Error occurred during autorecon: {str(e)}")
        result["error"] = str(e)
        return result
    
    finally:
        os.chdir(original_cwd)

if __name__ == "__main__":
    # This is for testing purposes only. In production, this is called from VulnScanX.py.
    import threading

    temp_db_engine = init_db('sqlite:///test_autorecon.db')
    test_session = get_session(temp_db_engine)
    
    test_domain = "web-security-academy.net"
    test_scan = test_session.query(ScanHistory).filter_by(domain=test_domain).first()
    if not test_scan:
        test_scan = ScanHistory(domain=test_domain)
        test_session.add(test_scan)
        test_session.commit()
    test_scan_id = test_scan.id

    dummy_url_directory = "test_autorecon_output"
    os.makedirs(dummy_url_directory, exist_ok=True)

    test_headers = {"User-Agent": "Mozilla/5.0", "Cookie": "sessionid=test_session_id"}

    test_login_event = threading.Event()

    print(f"{BLUE}[+] Running autorecon test with various options...{NC}")
    
    print(f"\n{CYAN}--- Test Case 1: Passive Subdomain and Passive Crawl ---{NC}")
    autorecon(
        url=f"http://{test_domain}",
        url_directory=os.path.join(dummy_url_directory, "passive_only"),
        session=test_session,
        scan_id=test_scan_id,
        passive_subdomain_enabled=True,
        passive_crawl_enabled=True,
        max_pages=5
    )

    print(f"\n{CYAN}--- Test Case 2: Active Subdomain and Active Crawl (Headless) ---{NC}")
    autorecon(
        url=f"http://{test_domain}/login",
        url_directory=os.path.join(dummy_url_directory, "active_headless"),
        headers=test_headers,
        session=test_session,
        scan_id=test_scan_id,
        active_subdomain_enabled=True,
        active_crawl_enabled=True,
        open_browser_for_active_crawl=False,
        max_pages=10
    )

    print(f"\n{BLUE}[+] Verifying autorecon results from database...{NC}")
    retrieved_subdomains = test_session.query(ReconResult).filter_by(scan_id=test_scan_id, data_type="live_subdomain").all()
    print(f"   Found {len(retrieved_subdomains)} live subdomains:")
    for sub in retrieved_subdomains:
        print(f"     - {sub.value}")

    retrieved_endpoints = test_session.query(Endpoint).filter_by(scan_id=test_scan_id).all()
    print(f"   Found {len(retrieved_endpoints)} endpoints:")
    for ep in retrieved_endpoints:
        print(f"     - {ep.url} ({ep.method})")

    test_session.close()
    
    if os.path.exists('test_autorecon.db'):
        os.remove('test_autorecon.db')
    
    if os.path.exists(dummy_url_directory):
        try:
            shutil.rmtree(dummy_url_directory)
            print(f"{GREEN}[+] Cleaned up directory: {dummy_url_directory}{NC}")
        except OSError as e:
            print(f"{RED}Error removing directory {dummy_url_directory}: {e}{NC}")

    print(f"{GREEN}[+] Autorecon test completed.{NC}")