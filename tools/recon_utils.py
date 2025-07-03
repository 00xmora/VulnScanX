import re
import json
from urllib.parse import urlparse, parse_qs, urljoin
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
import logging

logger = logging.getLogger(__name__)

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
                        selected_option_value = options[0].get_attribute("value")
                        form_data[name] = selected_option_value
            except Exception as e:
                logger.warning(f"Error processing dropdown: {str(e)}")
        
        for checkbox in checkboxes:
            try:
                if checkbox.is_displayed() and checkbox.is_enabled():
                    name = checkbox.get_attribute("name") or f"checkbox_{len(form_data)}"
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
    path_pattern = r'(?:https?:\/\/[^"\s\',]+)|(?:/[^"\s\'/?#][^"\s\',]*)'
    quoted_path_pattern = r'[\'"](?:https?:\/\/[^"\s\',]+|/[^"\s\'/?#][^"\s\',]*)[\'"]'
    
    paths = re.findall(path_pattern, js_content) + re.findall(quoted_path_pattern, js_content)
    
    base_domain = urlparse(base_url).netloc
    for path in paths:
        path = path.strip('"\'')
        full_url = urljoin(base_url, path)
        if is_valid_url(full_url, base_domain):
            method = "GET"
            if re.search(r'\.post\s*\(', js_content, re.IGNORECASE) or re.search(r'method:\s*[\'"]POST[\'"]', js_content, re.IGNORECASE):
                method = "POST"
            elif re.search(r'\.put\s*\(', js_content, re.IGNORECASE) or re.search(r'method:\s*[\'"]PUT[\'"]', js_content, re.IGNORECASE):
                method = "PUT"
            elif re.search(r'\.delete\s*\(', js_content, re.IGNORECASE) or re.search(r'method:\s*[\'"]DELETE[\'"]', js_content, re.IGNORECASE):
                method = "DELETE"
            endpoints.append({"url": full_url, "method": method})
    
    return endpoints