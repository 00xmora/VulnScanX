import logging
import requests
import json
import time
from urllib.parse import urlparse, urljoin
from selenium.webdriver.common.by import By
from tools.browser_utils import get_selenium_driver # Assuming tools.browser_utils is the path
from tools.recon_utils import is_valid_url, extract_parameters, extract_form_data, extract_endpoints_from_js # Assuming tools.recon_utils is the path
from sqlalchemy.exc import IntegrityError
from tools.database import Endpoint # Assuming tools.database is the path

logger = logging.getLogger(__name__)

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
    print(f"[+] Performing passive URL crawling for {domain}...")
    found_urls = set()
    base_domain = domain

    # Wayback Machine
    try:
        wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
        response = requests.get(wayback_url, timeout=10)
        if response.status_code == 200:
            urls_data = response.json()
            if urls_data and len(urls_data) > 1:
                for entry in urls_data[1:]:
                    url = entry[0]
                    if is_valid_url(url, base_domain):
                        found_urls.add(url)
            print(f"[+] Retrieved URLs from Wayback Machine.")
        else:
            print(f"Error fetching from Wayback Machine: Status {response.status_code}")
    except Exception as e:
        print(f"Error with Wayback Machine: {e}")

    if session and scan_id is not None:
        for url_value in found_urls:
            try:
                new_endpoint = Endpoint(
                    scan_id=scan_id,
                    url=url_value,
                    method="GET",
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

def crawl_website(url, headers=None, max_pages=10, headless=True, session=None, scan_id=None, interactive_login=False, login_event=None):
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
    
    driver = get_selenium_driver(headless)
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
        if isinstance(driver, type(get_selenium_driver(True))): # Check if it's a Chrome-based driver for CDP
            driver.execute_cdp_cmd("Network.enable", {})
            driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {"headers": headers})
        else:
            logger.info(f"Skipping Network.enable and setExtraHTTPHeaders for non-Chrome driver ({type(driver).__name__}).")
        
        driver.get(url)

        if interactive_login and not headless:
            print(f"🔒 Please log in manually in the opened browser window. Waiting for signal to continue...")
            if login_event:
                login_event.wait()
                print(f"Login signal received. Continuing scan...")
            else:
                input()
                print(f"Manual input received. Continuing scan...")

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
                        if element.is_displayed() and element.is_enabled():
                            pass
                    except Exception as e:
                        logger.warning(f"Error processing clickable element: {str(e)}")
                
                forms = driver.find_elements(By.CSS_SELECTOR, "form")
                for form in forms:
                    try:
                        if form.is_displayed():
                            form_data = extract_form_data(form, driver)
                            if form_data and is_valid_url(form_data["url"], base_domain):
                                form_data["extra_headers"] = headers
                                endpoints_to_store.append(form_data)
                    except Exception as e:
                        logger.warning(f"Error processing form: {str(e)}")
                
                search_inputs = driver.find_elements(By.CSS_SELECTOR, "input[type='text'], input[type='search']")
                for input_field in search_inputs:
                    try:
                        if input_field.is_displayed() and input_field.is_enabled():
                            pass
                    except Exception as e:
                        logger.warning(f"Error interacting with search bar: {str(e)}")
                
                event_elements = driver.find_elements(By.CSS_SELECTOR, "[onchange], [oninput]")
                for element in event_elements:
                    try:
                        if element.is_displayed() and element.is_enabled():
                            if element.tag_name == "input":
                                pass
                    except Exception as e:
                        logger.warning(f"Error triggering event on element: {str(e)}")
                
            except Exception as e:
                logger.error(f"Error interacting with elements on {current_url}: {str(e)}")
            
            if isinstance(driver, type(get_selenium_driver(True))):
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
            else:
                logger.info(f"Skipping network log capture for non-Chrome driver ({type(driver).__name__}).")
            
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
        seen_endpoints_tuples = set()
        for endpoint_data in endpoints_to_store:
            endpoint_tuple = (endpoint_data["url"], endpoint_data["method"])
            if endpoint_tuple not in seen_endpoints_tuples and is_valid_url(endpoint_data["url"], base_domain):
                seen_endpoints_tuples.add(endpoint_tuple)
                unique_endpoints.append(endpoint_data)
                
                if session and scan_id is not None:
                    try:
                        new_endpoint = Endpoint(
                            scan_id=scan_id,
                            url=endpoint_data["url"],
                            method=endpoint_data["method"],
                            body_params=json.dumps(endpoint_data.get("body_params")),
                            extra_headers=json.dumps(endpoint_data.get("extra_headers"))
                        )
                        session.add(new_endpoint)
                        session.commit()
                    except IntegrityError:
                        session.rollback()
                        logger.info(f"Duplicate endpoint found and skipped: {endpoint_data['url']} [{endpoint_data['method']}]")
                    except Exception as db_e:
                        session.rollback()
                        logger.error(f"Error saving endpoint to DB: {db_e}")

        print(f"[+] Endpoints crawled and stored in database")
        
        return unique_endpoints
    
    except Exception as e:
        logger.error(f"Error occurred during crawling: {str(e)}")
        return endpoints_to_store
    
    finally:
        driver.quit()