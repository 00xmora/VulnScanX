#!/usr/bin/env python3

import os
import subprocess
from bs4 import BeautifulSoup
import requests
import re
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
# Import WebDriverManager for automatic driver management
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select
from urllib.parse import urljoin, urlparse, parse_qs
import configparser
import logging
from sqlalchemy.exc import IntegrityError
from tools.database import ReconResult, Endpoint # Import new models
import shutil
import platform

# Define colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m'
BOLD = '\033[1m'

# Configure logging for crawler
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration (assuming config.ini is in the same directory as autorecon.py or a known path)
config = configparser.ConfigParser()
config_file = 'config.ini'
# Adjusting path to config.ini to be relative to the script's directory
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
        'waybackmachine': '' # Added for passive URL crawling
    }
    with open(config_file_path, 'w') as f:
        config.write(f)
    print(f"{YELLOW}[+] Created default config.ini. Please add your API keys if available.{NC}")

PENTEST_API_KEY = config['API_KEYS'].get('pentest_tools', '')
SECURITYTRAILS_API_KEY = config['API_KEYS'].get('securitytrails', '')
VIRUSTOTAL_API_KEY = config['API_KEYS'].get('virustotal', '')

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

def run_command(command, silent=False, output_file=None):
    """
    Executes a shell command.
    Args:
        command (str): The command to execute.
        silent (bool): If True, suppress stdout and stderr.
        output_file (str): If provided, redirect stdout to this file.
    Returns:
        bool: True if command succeeded, False otherwise.
    """
    try:
        if silent and output_file:
            with open(output_file, 'w') as f:
                subprocess.run(command, shell=True, check=True, stdout=f, stderr=subprocess.DEVNULL)
        elif silent:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error running command: {command} - {e}{NC}")
        return False
    return True

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
    # Sanitize domain for directory name
    safe_domain = domain.replace('.', '_').replace(':', '_')
    target_path = (project_path / safe_domain).resolve()
    target_path.mkdir(parents=True, exist_ok=True)
    print(f"{BLUE}[+] Directory created: {project_path}/{safe_domain}{NC}")
    return target_path


def get_driver(headless=True):
    """
    Initialize a browser driver using webdriver_manager for automatic setup.
    Tries Chrome first, then Firefox.
    """
    try:
        chrome_options = ChromeOptions()
        chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        if headless:
            chrome_options.add_argument("--headless=new")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
        
        # Use ChromeDriverManager to get the path to the chromedriver executable
        driver_path = ChromeDriverManager().install()
        print(f"[DEBUG] Using ChromeDriver from: {driver_path}")
        service = ChromeService(executable_path=driver_path)
        return webdriver.Chrome(service=service, options=chrome_options)

    except Exception as e:
        logger.warning(f"Chrome WebDriver failed: {str(e)}. Falling back to Firefox. Ensure Chrome is installed if you prefer it.")
        try:
            firefox_options = FirefoxOptions()
            if headless:
                firefox_options.add_argument("--headless")
            
            # Use GeckoDriverManager to get the path to the geckodriver executable
            driver_path = GeckoDriverManager().install()
            print(f"[DEBUG] Using GeckoDriver from: {driver_path}")
            service = FirefoxService(executable_path=driver_path)
            return webdriver.Firefox(service=service, options=firefox_options)

        except Exception as e:
            logger.error(f"Firefox WebDriver failed: {str(e)}. No browser available. "
                         f"Please ensure Firefox is installed and/or install 'webdriver_manager' if you haven't already (`pip install webdriver-manager`).")
            raise Exception("No supported browser WebDriver found.")


def is_valid_url(url, base_domain):
    """
    Validate if a URL is a legitimate endpoint and belongs to the base domain.
    Args:
        url (str): The URL to validate.
        base_domain (str): The base domain to check against.
    Returns:
        bool: True if the URL is valid and belongs to the domain, False otherwise.
    """
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ["http", "https"]:
            return False
        # Ensure the URL belongs to the base domain or its subdomains
        if not (parsed_url.netloc == base_domain or parsed_url.netloc.endswith(f".{base_domain}")):
            return False
        path = parsed_url.path
        if not path or path == "/":
            return True
        # Allow paths with common web characters
        if not re.match(r'^[a-zA-Z0-9\-_/~.!@#$%^&*()+=/]*$', path): # Relaxed path regex
            return False
        exclude_extensions = r'\.(css|js|ico|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|map|txt|xml|pdf)$'
        if re.search(exclude_extensions, path, re.IGNORECASE):
            return False
        invalid_patterns = [
            r'function\(', r'\}\}', r'\|\|', r'\(\s*\)', r'\[.*\]', r'\{.*\}', r'==',
            r'\?\d+:e=', r'\bvar\b', r'\bif\b', r'\belse\b', r'#\\|\?\$\|', r',Pt=function'
        ]
        full_url = url.lower()
        if any(re.search(pattern, full_url) for pattern in invalid_patterns):
            return False
        query = parsed_url.query
        if query:
            # Allow more diverse query parameters
            if any(len(value) > 200 or not re.match(r'^[a-zA-Z0-9\-_.~!*\'():@&=+$,/?%#\[\]]*$', value) for values in parse_qs(query).values() for value in values):
                return False
        return True
    except Exception:
        return False


def extract_parameters(request_body):
    """
    Extract body parameters from a request body.
    Args:
        request_body (str): The raw request body.
    Returns:
        dict: A dictionary of extracted parameters.
    """
    body_params = {}
    if request_body:
        try:
            body_params = json.loads(request_body)
        except (json.JSONDecodeError, TypeError):
            # If not JSON, try to parse as form-urlencoded string
            try:
                body_params = parse_qs(request_body)
                # parse_qs returns lists for values, convert to single values if possible
                body_params = {k: v[0] if len(v) == 1 else v for k, v in body_params.items()}
            except Exception:
                body_params = {"raw_body": request_body}
    return body_params

def extract_form_data(form, driver):
    """
    Extract form data without submitting.
    Args:
        form (selenium.webdriver.remote.webelement.WebElement): The form element.
        driver (selenium.webdriver.remote.webdriver.WebDriver): The WebDriver instance.
    Returns:
        dict: A dictionary containing URL, method, body parameters, and extra headers, or None if an error occurs.
    """
    form_data = {}
    try:
        inputs = form.find_elements(By.CSS_SELECTOR, "input[type='text'], input[type='search'], input[type='email'], input[type='password'], input[type='number'], textarea")
        selects = form.find_elements(By.TAG_NAME, "select")
        checkboxes = form.find_elements(By.CSS_SELECTOR, "input[type='checkbox'], input[type='radio']")
        
        for input_field in inputs:
            try:
                if input_field.is_displayed() and input_field.is_enabled():
                    name = input_field.get_attribute("name") or f"input_{len(form_data)}"
                    input_type = input_field.get_attribute("type")
                    value = "test"
                    if input_type == "password":
                        value = "Test123!"
                    elif input_type == "number":
                        value = "42"
                    elif input_field.tag_name == "textarea":
                        value = "Sample text"
                    # input_field.send_keys(value) # Not actually typing, just extracting structure
                    form_data[name] = value
            except Exception as e:
                logger.warning(f"Error processing input field: {str(e)}")
        
        for select in selects:
            try:
                if select.is_displayed() and select.is_enabled():
                    select_obj = Select(select)
                    name = select.get_attribute("name") or f"select_{len(form_data)}"
                    options = select_obj.options
                    if options:
                        # select_obj.select_by_index(len(options) - 1) # Not actually selecting
                        selected_option_value = options[0].get_attribute("value") # Just pick first option as example
                        form_data[name] = selected_option_value
            except Exception as e:
                logger.warning(f"Error processing dropdown: {str(e)}")
        
        for checkbox in checkboxes:
            try:
                if checkbox.is_displayed() and checkbox.is_enabled():
                    name = checkbox.get_attribute("name") or f"checkbox_{len(form_data)}"
                    # if not checkbox.is_selected(): # Not actually clicking
                    #     checkbox.click()
                    form_data[name] = checkbox.get_attribute("value") or "on"
            except Exception as e:
                logger.warning(f"Error processing checkbox/radio: {str(e)}")
        
        action = form.get_attribute("action")
        method = form.get_attribute("method") or "POST"
        base_url = driver.current_url
        full_url = urljoin(base_url, action) if action else base_url
        
        return {
            "url": full_url,
            "method": method.upper(),
            "body_params": form_data,
            "extra_headers": {}
        }
    except Exception as e:
        logger.error(f"Error extracting form data: {str(e)}")
        return None

def extract_endpoints_from_js(js_content, base_url):
    """
    Extract valid endpoints from JavaScript content with method inference.
    Args:
        js_content (str): The JavaScript content.
        base_url (str): The base URL for resolving relative paths.
    Returns:
        list: A list of dictionaries, each representing an endpoint.
    """
    endpoints = []
    # Pattern to find URLs (http/s) or relative paths starting with /
    # Adjusted to allow more characters in paths for realistic URLs
    path_pattern = r'(?:https?:\/\/[^"\s\',]+)|(?:/[^"\s\'/?#][^"\s\',]*)'
    quoted_path_pattern = r'[\'"](?:https?:\/\/[^"\s\',]+|/[^"\s\'/?#][^"\s\',]*)[\'"]'
    
    paths = re.findall(path_pattern, js_content) + re.findall(quoted_path_pattern, js_content)
    
    base_domain = urlparse(base_url).netloc
    for path in paths:
        path = path.strip('"\'')
        full_url = urljoin(base_url, path)
        if is_valid_url(full_url, base_domain):
            method = "GET" # Default to GET
            # Look for common patterns indicating POST/PUT/DELETE
            if re.search(r'\.post\s*\(', js_content, re.IGNORECASE) or re.search(r'method:\s*[\'"]POST[\'"]', js_content, re.IGNORECASE):
                method = "POST"
            elif re.search(r'\.put\s*\(', js_content, re.IGNORECASE) or re.search(r'method:\s*[\'"]PUT[\'"]', js_content, re.IGNORECASE):
                method = "PUT"
            elif re.search(r'\.delete\s*\(', js_content, re.IGNORECASE) or re.search(r'method:\s*[\'"]DELETE[\'"]', js_content, re.IGNORECASE):
                method = "DELETE"
            endpoints.append({"url": full_url, "method": method})
    
    return endpoints

def crawl_website(url, headers=None, max_pages=10, headless=True, session=None, scan_id=None, interactive_login=False, login_event=None): # ADDED login_event
    """
    Crawl a website and extract endpoints, saving to DB.
    Args:
        url (str): The starting URL to crawl.
        headers (dict, optional): Custom HTTP headers.
        max_pages (int): Maximum number of pages to crawl.
        headless (bool): If True, run browser in headless mode.
        session (sqlalchemy.orm.session.Session): SQLAlchemy session for database operations.
        scan_id (int): ID of the current scan in ScanHistory.
        interactive_login (bool): If True, prompt user to log in manually in browser.
        login_event (threading.Event, optional): Event to signal completion of manual login.
    Returns:
        list: A list of unique endpoints found.
    """
    if headers is None:
        headers = {}
    
    driver = get_driver(headless)
    endpoints_to_store = []
    visited_urls = set()
    urls_to_visit = [url]
    base_domain = urlparse(url).netloc
    js_urls = set()
    
    basic_headers = {
        'Host', 'Connection', 'User-Agent', 'Accept', 'Accept-Encoding', 
        'Accept-Language', 'Content-Length', 'Content-Type', 'Origin', 
        'Referer', 'Sec-Fetch-Site', 'Sec-Fetch-Mode', 'Sec-Fetch-Dest'
    }
    
    try:
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {"headers": headers})
        
        driver.get(url) # Initial navigation

        if interactive_login and not headless:
            print(f"{YELLOW}🔒 Please log in manually in the opened Chrome window. Waiting for signal to continue...{NC}")
            if login_event: # Check if event is provided
                login_event.wait() # Wait for the event to be set by the main app
                print(f"{GREEN}Login signal received. Continuing scan...{NC}")
            else:
                input() # Fallback to blocking input if no event is provided
                print(f"{GREEN}Manual input received. Continuing scan...{NC}")

        while urls_to_visit and len(visited_urls) < max_pages:
            current_url = urls_to_visit.pop(0)
            if current_url in visited_urls:
                continue
            
            try:
                driver.get(current_url)
                visited_urls.add(current_url)
                time.sleep(2)
            except Exception as e:
                logger.error(f"Failed to load {current_url}: {str(e)}")
                continue
            
            try:
                # Interact with clickable elements and forms (without actual submission)
                clickable_elements = driver.find_elements(By.CSS_SELECTOR, "button, input[type='button'], [onclick]")
                for element in clickable_elements:
                    try:
                        # Just simulate interaction, don't actually click if it navigates away
                        if element.is_displayed() and element.is_enabled():
                            pass # No action needed, just identifying
                    except Exception as e:
                        logger.warning(f"Error processing clickable element: {str(e)}")
                
                forms = driver.find_elements(By.CSS_SELECTOR, "form")
                for form in forms:
                    try:
                        if form.is_displayed():
                            form_data = extract_form_data(form, driver)
                            if form_data and is_valid_url(form_data["url"], base_domain):
                                form_data["extra_headers"] = headers # Add current session headers
                                endpoints_to_store.append(form_data)
                    except Exception as e:
                        logger.warning(f"Error processing form: {str(e)}")
                
                search_inputs = driver.find_elements(By.CSS_SELECTOR, "input[type='text'], input[type='search']")
                for input_field in search_inputs:
                    try:
                        if input_field.is_displayed() and input_field.is_enabled():
                            # input_field.send_keys("test") # Not actually typing
                            # input_field.send_keys(Keys.RETURN) # Not actually submitting
                            pass
                    except Exception as e:
                        logger.warning(f"Error interacting with search bar: {str(e)}")
                
                event_elements = driver.find_elements(By.CSS_SELECTOR, "[onchange], [oninput]")
                for element in event_elements:
                    try:
                        if element.is_displayed() and element.is_enabled():
                            if element.tag_name == "input":
                                # element.send_keys("test") # Not actually typing
                                pass
                    except Exception as e:
                        logger.warning(f"Error triggering event on element: {str(e)}")
                
            except Exception as e:
                logger.error(f"Error interacting with elements on {current_url}: {str(e)}")
            
            try:
                logs = driver.get_log("performance")
                for entry in logs:
                    try:
                        message = json.loads(entry["message"])["message"]
                        if message["method"] == "Network.requestWillBeSent":
                            request = message["params"]["request"]
                            request_url = request["url"]
                            if is_valid_url(request_url, base_domain):
                                body_params = extract_parameters(request.get("postData"))
                                request_headers = {k: v for k, v in request.get("headers", {}).items() if k not in basic_headers}
                                endpoints_to_store.append({
                                    "url": request_url,
                                    "method": request["method"],
                                    "body_params": body_params,
                                    "extra_headers": request_headers
                                })
                            if request_url.endswith(".js") and is_valid_url(request_url, base_domain):
                                js_urls.add(request_url)
                    except (KeyError, json.JSONDecodeError) as e:
                        logger.warning(f"Error processing log entry: {str(e)}")
            
            except Exception as e:
                logger.error(f"Error capturing network logs: {str(e)}")
            
            try:
                links = driver.find_elements(By.CSS_SELECTOR, "a[href], [href]")
                for link in links:
                    href = link.get_attribute("href")
                    if href:
                        parsed_href = urlparse(href)
                        if parsed_href.netloc == base_domain or parsed_href.netloc.endswith(f".{base_domain}"):
                            full_url = urljoin(current_url, href)
                            if is_valid_url(full_url, base_domain) and full_url not in visited_urls and full_url not in urls_to_visit:
                                urls_to_visit.append(full_url)
            except Exception as e:
                logger.error(f"Error extracting links from {current_url}: {str(e)}")
        
        for js_url in js_urls:
            try:
                response = requests.get(js_url, headers=headers, timeout=5)
                if response.status_code == 200:
                    js_endpoints = extract_endpoints_from_js(response.text, url)
                    for endpoint in js_endpoints:
                        # body_params are usually not directly in JS extracted endpoints, assume empty dict
                        body_params = {}
                        endpoints_to_store.append({
                            "url": endpoint["url"],
                            "method": endpoint["method"],
                            "body_params": body_params,
                            "extra_headers": headers
                        })
            except Exception as e:
                logger.error(f"Error processing JavaScript file {js_url}: {str(e)}")
        
        unique_endpoints = []
        seen_endpoints_tuples = set() # To store (url, method) tuples for uniqueness
        for endpoint_data in endpoints_to_store:
            # Create a simple tuple for uniqueness check
            endpoint_tuple = (endpoint_data["url"], endpoint_data["method"])
            if endpoint_tuple not in seen_endpoints_tuples and is_valid_url(endpoint_data["url"], base_domain):
                seen_endpoints_tuples.add(endpoint_tuple)
                unique_endpoints.append(endpoint_data)
                
                # Store in database
                if session and scan_id is not None:
                    try:
                        new_endpoint = Endpoint(
                            scan_id=scan_id,
                            url=endpoint_data["url"],
                            method=endpoint_data["method"],
                            body_params=json.dumps(endpoint_data.get("body_params")), # Store as JSON string
                            extra_headers=json.dumps(endpoint_data.get("extra_headers")) # Store as JSON string
                        )
                        session.add(new_endpoint)
                        session.commit() # Commit each endpoint for better granular control and to handle IntegrityError
                    except IntegrityError:
                        session.rollback()
                        logger.info(f"Duplicate endpoint found and skipped: {endpoint_data['url']} [{endpoint_data['method']}]")
                    except Exception as db_e:
                        session.rollback()
                        logger.error(f"Error saving endpoint to DB: {db_e}")

        print(f"{GREEN}[+] Endpoints crawled and stored in database{NC}")
        
        return unique_endpoints # Return for potential further processing in the main app
    
    except Exception as e:
        logger.error(f"Error occurred during crawling: {str(e)}")
        return endpoints_to_store # Return what was collected before error
    
    finally:
        driver.quit()

def passive_url_crawl(domain, session=None, scan_id=None):
    """
    Performs passive URL crawling using Wayback Machine and SecurityTrails.
    Args:
        domain (str): The target domain.
        session (sqlalchemy.orm.session.Session): SQLAlchemy session for database operations.
        scan_id (int): ID of the current scan in ScanHistory.
    Returns:
        set: A set of unique URLs found.
    """
    print(f"{YELLOW}[+] Performing passive URL crawling for {domain}...{NC}")
    found_urls = set()
    base_domain = domain

    # Wayback Machine
    try:
        wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
        response = requests.get(wayback_url, timeout=10)
        if response.status_code == 200:
            urls_data = response.json()
            if urls_data and len(urls_data) > 1: # First element is header
                for entry in urls_data[1:]:
                    url = entry[0]
                    if is_valid_url(url, base_domain):
                        found_urls.add(url)
            print(f"{GREEN}[+] Retrieved URLs from Wayback Machine.{NC}")
        else:
            print(f"{RED}Error fetching from Wayback Machine: Status {response.status_code}{NC}")
    except Exception as e:
        print(f"{RED}Error with Wayback Machine: {e}{NC}")

    # Store unique URLs in the database
    if session and scan_id is not None:
        for url_value in found_urls:
            try:
                new_endpoint = Endpoint(
                    scan_id=scan_id,
                    url=url_value,
                    method="GET", # Assume GET for passively found URLs
                    body_params=json.dumps({}),
                    extra_headers=json.dumps({})
                )
                session.add(new_endpoint)
                session.commit()
            except IntegrityError:
                session.rollback()
                logger.info(f"Duplicate URL found and skipped: {url_value}")
            except Exception as db_e:
                session.rollback()
                logger.error(f"Error saving URL to DB: {db_e}")
    
    return found_urls


def get_subdomains_from_free_services(target, session=None, scan_id=None):
    """
    Retrieves subdomains from various free online services.
    Args:
        target (str): The target domain.
        session (sqlalchemy.orm.session.Session): SQLAlchemy session for database operations.
        scan_id (int): ID of the current scan in ScanHistory.
    Returns:
        set: A set of unique subdomains found.
    """
    subdomains = set()
    base_domain = target # Use target as base domain for validation

    # Pentest-Tools API
    if PENTEST_API_KEY:
        headers = {"X-API-Key": PENTEST_API_KEY}
        base_url = "https://pentest-tools.com/api"
        try:
            response = requests.post(f"{base_url}/targets", json={"name": target, "type": "domain"}, headers=headers)
            target_id = response.json().get("id")
            scan_data = {"target_id": target_id, "tool": "subdomain_finder"}
            response = requests.post(f"{base_url}/scans", json=scan_data, headers=headers)
            scan_id_pt = response.json().get("scan_id") # Use a different var to avoid conflict with function param
            while True:
                response = requests.get(f"{base_url}/scans/{scan_id_pt}", headers=headers)
                data = response.json()
                if data.get("status") == "finished":
                    for sub in data.get("results", {}).get("subdomains", []):
                        if sub.endswith(f".{target}") or sub == target: # Ensure it belongs to the target
                            subdomains.add(sub)
                    break
                time.sleep(10)
            print(f"{GREEN}[+] Retrieved subdomains from Pentest-Tools API{NC}")
        except Exception as e:
            print(f"{RED}Error with Pentest-Tools API: {e}{NC}")
    else:
        try:
            url = f"https://pentest-tools.com/information-gathering/find-subdomains-of-domain?domain={target}"
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            for div in soup.select("div.subdomain-result"):
                subdomain = div.text.strip()
                if subdomain.endswith(f".{target}") or subdomain == target:
                    subdomains.add(subdomain)
            print(f"{GREEN}[+] Retrieved subdomains from Pentest-Tools web{NC}")
        except Exception as e:
            print(f"{RED}Error with Pentest-Tools web: {e}{NC}")

    # DNSdumpster
    try:
        response = requests.get("https://dnsdumpster.com", timeout=10)
        csrf_token_match = re.search(r'name="csrfmiddlewaretoken" value="(.+?)"', response.text)
        if csrf_token_match:
            csrf_token = csrf_token_match.group(1)
            data = {"csrfmiddlewaretoken": csrf_token, "targetip": target}
            headers = {"Referer": "https://dnsdumpster.com"}
            response = requests.post("https://dnsdumpster.com", data=data, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            for td in soup.select("td.col-md-4"):
                subdomain = td.text.strip()
                if subdomain.endswith(f".{target}") or subdomain == target:
                    subdomains.add(subdomain)
            print(f"{GREEN}[+] Retrieved subdomains from DNSdumpster{NC}")
        else:
            print(f"{YELLOW}[!] CSRF token not found for DNSdumpster.{NC}")
    except Exception as e:
        print(f"{RED}Error with DNSdumpster: {e}{NC}")

    print(f"{YELLOW}[+] Nmmapper.com requires manual retrieval: https://www.nmmapper.com/subdomains{NC}")

    # SecurityTrails
    if SECURITYTRAILS_API_KEY:
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        try:
            response = requests.get(f"https://api.securitytrails.com/v1/domain/{target}/subdomains", headers=headers)
            data = response.json()
            for sub in data.get("subdomains", []):
                full_subdomain = f"{sub}.{target}"
                if full_subdomain.endswith(f".{target}") or full_subdomain == target:
                    subdomains.add(full_subdomain)
            print(f"{GREEN}[+] Retrieved subdomains from SecurityTrails{NC}")
        except Exception as e:
            print(f"{RED}Error with SecurityTrails: {e}{NC}")

    # Crt.sh
    try:
        response = requests.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=10)
        for entry in response.json():
            name = entry.get("name_value", "").strip()
            if name.endswith(f".{target}") or name == target:
                subdomains.add(name)
        print(f"{GREEN}[+] Retrieved subdomains from Crt.sh{NC}")
    except Exception as e:
        print(f"{RED}Error with Crt.sh: {e}{NC}")

    print(f"{YELLOW}[+] SubdomainFinder.c99.nl requires manual retrieval: https://subdomainfinder.c99.nl{NC}")

    # VirusTotal
    if VIRUSTOTAL_API_KEY:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/domains/{target}/subdomains", headers=headers)
            data = response.json()
            for sub in data.get("data", []):
                sub_id = sub.get("id")
                if sub_id and (sub_id.endswith(f".{target}") or sub_id == target):
                    subdomains.add(sub_id)
            print(f"{GREEN}[+] Retrieved subdomains from VirusTotal{NC}")
        except Exception as e:
            print(f"{RED}Error with VirusTotal: {e}{NC}")

    print(f"{YELLOW}[+] FindSubDomains.com requires manual retrieval: https://findsubdomains.com{NC}")

    # Netcraft
    try:
        response = requests.get(f"https://searchdns.netcraft.com/?host=*.{target}", timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        for a in soup.select("a[href*='site=']"):
            subdomain_match = re.search(r"site=([^&]+)", a["href"])
            if subdomain_match:
                subdomain = subdomain_match.group(1)
                if subdomain.endswith(f".{target}") or subdomain == target:
                    subdomains.add(subdomain)
        print(f"{GREEN}[+] Retrieved subdomains from Netcraft{NC}")
    except Exception as e:
        print(f"{RED}Error with Netcraft: {e}{NC}")

    # SOCRadar
    try:
        response = requests.get(f"https://api.socradar.io/tools/subdomains?domain={target}", timeout=10)
        data = response.json()
        for sub in data.get("subdomains", []):
            if sub.endswith(f".{target}") or sub == target:
                subdomains.add(sub)
        print(f"{GREEN}[+] Retrieved subdomains from SOCRadar{NC}")
    except Exception as e:
        print(f"{RED}Error with SOCRadar: {e}{NC}")

    # Store unique subdomains in the database
    if session and scan_id is not None:
        for subdomain_value in subdomains:
            try:
                new_recon_result = ReconResult(
                    scan_id=scan_id,
                    data_type="subdomain",
                    value=subdomain_value
                )
                session.add(new_recon_result)
                session.commit() # Commit individually to handle IntegrityError for duplicates
            except IntegrityError:
                session.rollback()
                logger.info(f"Duplicate subdomain found and skipped: {subdomain_value}")
            except Exception as db_e:
                session.rollback()
                logger.error(f"Error saving subdomain to DB: {db_e}")

    return subdomains

def passive_subdomain_enum(domain, threads=20, session=None, scan_id=None):
    """
    Performs passive subdomain enumeration using tools like Amass, Subfinder, and Sublist3r.
    Args:
        domain (str): The target domain.
        threads (int): Number of threads for concurrent execution.
        session (sqlalchemy.orm.session.Session): SQLAlchemy session for database operations.
        scan_id (int): ID of the current scan in ScanHistory.
    """
    print(f"{YELLOW}[+] Running passive subdomain enumeration with {threads} threads...{NC}")
    # Temp files are created by run_command, then deleted. Results are read from them.
    amass_output_file = "amass_passive_output.txt"
    subfinder_output_file = "subfinder_passive_output.txt"
    sublist3r_output_file = "sublist3r_passive_output.txt"
    
    commands = [
        (f"amass enum -passive -d {domain} -o {amass_output_file}", amass_output_file),
        (f"subfinder -d {domain} -o {subfinder_output_file}", subfinder_output_file),
        (f"sublist3r -d {domain} -o {sublist3r_output_file}", sublist3r_output_file)
    ]
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(run_command, cmd, True, outfile): outfile 
                   for cmd, outfile in commands}
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"{RED}Error in thread for {futures[future]}: {e}{NC}")
    
    all_subdomains = set()
    for outfile in [amass_output_file, subfinder_output_file, sublist3r_output_file]:
        if os.path.exists(outfile):
            with open(outfile, 'r') as f:
                for line in f:
                    sub = line.strip()
                    if sub.endswith(f".{domain}") or sub == domain: # Filter
                        all_subdomains.add(sub)
            os.remove(outfile) # Clean up temp file

    # Store unique subdomains in the database
    if session and scan_id is not None:
        for subdomain_value in all_subdomains:
            try:
                new_recon_result = ReconResult(
                    scan_id=scan_id,
                    data_type="subdomain",
                    value=subdomain_value
                )
                session.add(new_recon_result)
                session.commit()
            except IntegrityError:
                session.rollback()
                logger.info(f"Duplicate subdomain found and skipped: {subdomain_value}")
            except Exception as db_e:
                session.rollback()
                logger.error(f"Error saving subdomain to DB: {db_e}")

def filter_live_domains(session=None, scan_id=None):
    """
    Filters live domains from the stored subdomains using httpx.
    Args:
        session (sqlalchemy.orm.session.Session): SQLAlchemy session for database operations.
        scan_id (int): ID of the current scan in ScanHistory.
    """
    print(f"{YELLOW}[+] Filtering live domains...{NC}")
    
    # Fetch all subdomains from the database for the current scan
    current_subdomains = session.query(ReconResult).filter_by(scan_id=scan_id, data_type="subdomain").all()
    
    if not current_subdomains:
        print(f"{RED}[!] No subdomains found in DB for filtering{NC}")
        return

    # Write subdomains to a temporary file for httpx
    temp_domains_file = "temp_domains_for_httpx.txt"
    with open(temp_domains_file, "w") as f:
        for sub in current_subdomains:
            f.write(sub.value + "\n")

    live_domains_output_file = "domain.live" # httpx output file
    if run_command(f"cat {temp_domains_file} | httpx -silent -o {live_domains_output_file}", silent=True):
        print(f"{GREEN}[+] Live domains filtered{NC}")
        if os.path.exists(live_domains_output_file):
            with open(live_domains_output_file, "r") as f:
                live_domains = set(f.read().splitlines())
            os.remove(live_domains_output_file) # Clean up temp file

            if session and scan_id is not None:
                for live_sub in live_domains:
                    try:
                        new_live_recon = ReconResult(
                            scan_id=scan_id,
                            data_type="live_subdomain", # New type to denote live
                            value=live_sub
                        )
                        session.add(new_live_recon)
                        session.commit()
                    except IntegrityError:
                        session.rollback()
                        logger.info(f"Duplicate live subdomain found and skipped: {live_sub}")
                    except Exception as db_e:
                        session.rollback()
                        logger.error(f"Error saving live subdomain to DB: {db_e}")

    else:
        print(f"{RED}[!] Failed to filter live domains{NC}")
    
    os.remove(temp_domains_file) # Clean up temp file

def active_subdomain_enum(domain, session=None, scan_id=None, wordlist_path=None):
    """
    Performs active subdomain enumeration using dnsrecon and ffuf for virtual host enumeration.
    Args:
        domain (str): The target domain.
        session (sqlalchemy.orm.session.Session): SQLAlchemy session for database operations.
        scan_id (int): ID of the current scan in ScanHistory.
        wordlist_path (str, optional): Path to the wordlist for FFUF.
    """
    print(f"{YELLOW}[+] Running active subdomain enumeration with dnsrecon and ffuf...{NC}")
    
    # Fetch live subdomains from the database for this scan (used as base for further enum)
    live_domains_from_db = session.query(ReconResult).filter_by(scan_id=scan_id, data_type="live_subdomain").all()
    live_domains = {ld.value for ld in live_domains_from_db}

    # DNSRecon part
    try:
        dns_output_file = "dns_servers.txt"
        run_command(f"dig @8.8.8.8 NS {domain} +short > {dns_output_file}", silent=True)
        
        dns_servers = set()
        if os.path.exists(dns_output_file):
            with open(dns_output_file, "r") as f:
                dns_servers = {line.strip().rstrip('.') for line in f if line.strip()}
            os.remove(dns_output_file)
        
        ns_ips = []
        if dns_servers:
            for ns in dns_servers:
                ip_output_file = f"ns_ip_{ns}.txt"
                run_command(f"dig @8.8.8.8 A {ns} +short > {ip_output_file}", silent=True)
                if os.path.exists(ip_output_file):
                    with open(ip_output_file, "r") as f:
                        ips = [line.strip() for line in f if line.strip() and re.match(r"^\d+\.\d+\.\d+\.\d+$", line)]
                        if ips:
                            ns_ips.append(ips[0])
                    os.remove(ip_output_file)
        
        wordlist = wordlist_path or "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
        if not os.path.exists(wordlist):
            print(f"{RED}[!] DNSRecon wordlist not found: {wordlist}. Skipping DNSRecon.{NC}")
            # Do not return, continue to FFUF
        else:
            if ns_ips:
                ns_list_str = ",".join(ns_ips)
                print(f"{BLUE}[+] Querying name servers: -n {ns_list_str}{NC}")
                
                for i, ns_ip in enumerate(ns_ips):
                    ns_option = f"-n {ns_ip}"
                    dnsrecon_output = f"dnsrecon_output_{i}.json"
                    cmd = f"dnsrecon -d {domain} -t brt -D {wordlist} {ns_option} --lifetime 10 --threads 50 -j {dnsrecon_output} -f"
                    
                    if run_command(cmd, silent=True):
                        if os.path.exists(dnsrecon_output):
                            try:
                                with open(dnsrecon_output, "r") as f:
                                    data = json.load(f)
                                    for record in data:
                                        if record.get("type") in ["A", "CNAME"] and (record.get("name", "").endswith(f".{domain}") or record.get("name", "") == domain):
                                            live_domains.add(record.get("name"))
                            except json.JSONDecodeError:
                                print(f"{RED}[!] Failed to parse dnsrecon JSON output for {dnsrecon_output}{NC}")
                            os.remove(dnsrecon_output)
                        else:
                            print(f"{RED}[!] Failed to run dnsrecon with {ns_option}{NC}")
            else:
                print(f"{YELLOW}[!] No authoritative DNS server IPs resolved, using system resolvers for dnsrecon{NC}")
                dnsrecon_output = "dnsrecon_output.json"
                cmd = f"dnsrecon -d {domain} -t brt -D {wordlist} --lifetime 10 --threads 50 -j {dnsrecon_output} -f"
                if run_command(cmd, silent=True):
                    if os.path.exists(dnsrecon_output):
                        try:
                            with open(dnsrecon_output, "r") as f:
                                data = json.load(f)
                                for record in data:
                                    if record.get("type") in ["A", "CNAME"] and (record.get("name", "").endswith(f".{domain}") or record.get("name", "") == domain):
                                        live_domains.add(record.get("name"))
                        except json.JSONDecodeError:
                            print(f"{RED}[!] Failed to parse dnsrecon JSON output{NC}")
                        os.remove(dnsrecon_output)
                    else:
                        print(f"{RED}[!] Failed to run dnsrecon with system resolvers{NC}")
    except Exception as e:
        print(f"{RED}[!] Error in dnsrecon part of active subdomain enumeration: {e}{NC}")

    # FFUF for Virtual Host Enumeration
    print(f"{YELLOW}[+] Running FFUF for virtual host enumeration...{NC}")
    ffuf_wordlist = wordlist_path or "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt" # Using the same wordlist for now
    if not os.path.exists(ffuf_wordlist):
        print(f"{RED}[!] FFUF wordlist not found: {ffuf_wordlist}. Skipping FFUF.{NC}")
    else:
        ffuf_output_file = "ffuf_vhost_output.json"
        # Assuming the target URL is accessible via HTTP/HTTPS for FFUF
        # FFUF will try to resolve FUZZ.domain and then send requests to domain.com with Host header
        ffuf_cmd = (
            f"ffuf -w {ffuf_wordlist}:FUZZ -u http://{domain} -H 'Host: FUZZ.{domain}' "
            f"-mc 200,204,301,302,307,403 -of json -o {ffuf_output_file} -s" # -s for silent, -of json for JSON output
        )
        
        if run_command(ffuf_cmd, silent=True):
            if os.path.exists(ffuf_output_file):
                try:
                    with open(ffuf_output_file, "r") as f:
                        ffuf_results = json.load(f)
                        for result in ffuf_results.get("results", []):
                            host_header_value = result.get("host")
                            if host_header_value and (host_header_value.endswith(f".{domain}") or host_header_value == domain):
                                live_domains.add(host_header_value) # Add as a live subdomain
                except json.JSONDecodeError:
                    print(f"{RED}[!] Failed to parse FFUF JSON output for {ffuf_output_file}{NC}")
                os.remove(ffuf_output_file)
            else:
                print(f"{RED}[!] Failed to run FFUF for virtual host enumeration{NC}")

    # Store all found live domains (from dnsrecon and ffuf) in the database as 'live_subdomain'
    if session and scan_id is not None:
        for live_sub_value in live_domains:
            try:
                new_live_recon = ReconResult(
                    scan_id=scan_id,
                    data_type="live_subdomain",
                    value=live_sub_value
                )
                session.add(new_live_recon)
                session.commit()
            except IntegrityError:
                session.rollback()
                logger.info(f"Duplicate live subdomain from active enum found and skipped: {live_sub_value}")
            except Exception as db_e:
                session.rollback()
                logger.error(f"Error saving live subdomain from active enum to DB: {db_e}")

    print(f"{GREEN}[+] Active subdomain enumeration completed and saved to DB{NC}")


def autorecon(url, url_directory=None, headers=None, max_pages=10, threads=4, session=None, scan_id=None,
              passive_crawl_enabled=False, active_crawl_enabled=False, open_browser_for_active_crawl=False,
              passive_subdomain_enabled=False, active_subdomain_enabled=False, wordlist_path=None,
              login_event=None): # ADDED login_event
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
    project_name = url_directory # url_directory now serves as the project name
    
    # Ensure the current working directory is managed carefully
    original_cwd = os.getcwd()
    try:
        project_path = setup_project(project_name)
        # Change to the target-specific directory for tools that write temporary files
        target_dir_path = setup_domain_directory(project_path, domain)
        os.chdir(target_dir_path) # Temporarily change CWD

        result = {"subdomains": [], "endpoints": [], "error": None}
        
        if passive_subdomain_enabled:
            print(f"{CYAN}{BOLD}[+] Performing passive subdomain enumeration for {domain}{NC}")
            get_subdomains_from_free_services(domain, session, scan_id)
            passive_subdomain_enum(domain, threads, session, scan_id)
            filter_live_domains(session, scan_id) # Filter live domains from passive sources
        
        if active_subdomain_enabled:
            print(f"{CYAN}{BOLD}[+] Performing active subdomain enumeration for {domain}{NC}")
            active_subdomain_enum(domain, session, scan_id, wordlist_path)
            filter_live_domains(session, scan_id) # Re-filter after active enum to catch new live ones

        # Fetch all subdomains (including live) from the DB for the result
        db_subdomains = session.query(ReconResult).filter(
            ReconResult.scan_id == scan_id,
            ReconResult.data_type.in_(["subdomain", "live_subdomain"])
        ).all()
        result["subdomains"] = [s.value for s in db_subdomains]

        if passive_crawl_enabled:
            print(f"{YELLOW}[+] Running passive URL crawling...{NC}")
            passive_url_crawl(domain, session, scan_id)

        if active_crawl_enabled:
            print(f"{YELLOW}[+] Running active URL crawling with Selenium crawler...{NC}")
            # headless parameter for crawl_website is the inverse of open_browser_for_active_crawl
            endpoints = crawl_website(url, headers=headers, max_pages=max_pages, 
                                      headless=not open_browser_for_active_crawl, 
                                      session=session, scan_id=scan_id, 
                                      interactive_login=open_browser_for_active_crawl,
                                      login_event=login_event) # PASSED login_event
            result["endpoints"].extend(endpoints)
        
        # Fetch all endpoints from the DB for the result
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

# Removed the main() function and argparse setup as this script will be imported as a module.
# The `autorecon` function is now directly callable.
