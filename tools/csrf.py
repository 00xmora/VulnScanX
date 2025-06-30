from urllib.parse import urlparse, parse_qs, unquote, urlencode
import json
import requests
import os
import logging
from sqlalchemy.exc import IntegrityError
from tools.database import Vulnerability, Endpoint # Import Vulnerability and Endpoint models
from tools.ai_assistant import gemini # Use the consistent ai_assistant integration

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

# Function to clean Gemini's response (remove markdown wrappers)
def clean_gemini_response(raw_text):
    if raw_text.startswith("```json"):
        raw_text = raw_text[len("```json"):].strip()
    if raw_text.endswith("```"):
        raw_text = raw_text[:-3].strip()
    return raw_text

# Function to send a request (similar to idor.py, for consistency)
def send_request(req_data):
    method = req_data.get("method", "GET").upper()
    url = req_data["url"]
    headers = req_data.get("extra_headers", {})
    body = req_data.get("body_params", None)

    try:
        parsed = urlparse(url)

        if not parsed.scheme:
            host = headers.get("Host")
            if not host:
                return {"error": "Missing 'Host' header for relative URL"}

            scheme = "https" # Default to https if not specified
            url = f"{scheme}://{host}{url}"

        # Convert dict body to form-urlencoded string if Content-Type is set
        # Ensure 'body' and 'headers' are dictionaries before using .get() or checking 'in'
        if isinstance(body, dict) and "application/x-www-form-urlencoded" in headers.get("Content-Type", ""):
            body = urlencode(body)
        elif isinstance(body, dict) and "application/json" in headers.get("Content-Type", ""):
            body = json.dumps(body) # Convert dict to JSON string for JSON content type

        if method == "GET":
            res = requests.get(url, headers=headers)
        elif method == "POST":
            res = requests.post(url, headers=headers, data=body)
        elif method == "PUT":
            res = requests.put(url, headers=headers, data=body)
        elif method == "PATCH":
            res = requests.patch(url, headers=headers, data=body)
        elif method == "DELETE":
            res = requests.delete(url, headers=headers, data=body)
        else:
            return {"error": f"Unsupported HTTP method: {method}"}

        return {
            "url": url,
            "status": res.status_code,
            "response_body": res.text,
            "headers": res.headers # Include response headers for SameSite check
        }
    except Exception as e:
        logger.error(f"Error sending request to {url}: {str(e)}")
        return {"error": str(e)}

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
    except IntegrityError:
        session.rollback()
        logger.info(f"Duplicate vulnerability found and skipped: {vuln_data.get('vulnerability')} at {vuln_data.get('url')}")
    except Exception as db_e:
        session.rollback()
        logger.error(f"Error saving vulnerability to DB: {db_e}")

# Function that asks the AI to check whether there is a CSRF defense mechanism in the request
def csrfCheck(request_data, session, scan_id):
    """
    Analyzes a given HTTP request using AI to check for CSRF vulnerability and defense mechanisms.
    Stores findings directly in the database.
    """
    print(f"{BLUE}[*] Checking for CSRF defense mechanisms for: {request_data.get('url', 'N/A')}{NC}")
    
    prompt = f"""
    Analyze the following HTTP request to determine if it is vulnerable to Cross-Site Request Forgery (CSRF).
    Consider these conditions for vulnerability:
    1. Relevant action (e.g., state-changing request like POST, PUT, DELETE).
    2. Cookie-based session handling.
    3. No unpredictable parameters (e.g., CSRF token, unique nonce).

    Identify any defense mechanisms present, such as:
    - CSRF Token (unpredictable token in form fields or headers)
    - SameSite Cookies (Strict, Lax, None)
    - Referer-based validation

    Here is the HTTP request:
    {json.dumps(request_data, indent=2)}

    Return ONLY a JSON object with the following structure:
    {{
        "vulnerable": true/false,
        "reason": "Brief explanation of vulnerability or lack thereof",
        "defense_mechanisms": ["CSRF Token", "SameSite=Lax", "Referer Check", "None"],
        "csrf_parameter": "Name of the CSRF token parameter, if found",
        "csrf_token_value": "Value of the CSRF token, if found (for test purposes)",
        "action_url": "The URL where the action is performed",
        "method": "The HTTP method"
    }}
    """

    gemini_output = gemini(prompt)
    gemini_output = clean_gemini_response(gemini_output)

    try:
        ai_response = json.loads(gemini_output)
        
        # Store initial CSRF analysis as a potential vulnerability or note
        vulnerability_type = "CSRF Analysis"
        severity = "info" # Initial analysis is informational
        description = ai_response.get("reason", "CSRF analysis performed.")
        
        # Extract token for further testing if available
        csrf_parameter = ai_response.get("csrf_parameter", "N/A")
        csrf_token_value = ai_response.get("csrf_token_value", "")
        flag = 0 # 0 : No Vulnerability -- 1 : Vulnerability detected -- 2 : Potention vulnerability
        if ai_response.get("vulnerable") is True and ai_response['defense_mechanisms'][0] == "None":
            vulnerability_type = "CSRF"
            severity = "High" # Mark as potential medium if AI says vulnerable
            description = f"Potential CSRF vulnerability: {ai_response.get('reason')}. Defense mechanisms detected: {', '.join(ai_response.get('defense_mechanisms', ['None']))}"
            print(f"{YELLOW}   [!] AI indicates potential CSRF vulnerability for {request_data.get('url', 'N/A')}{NC}")
            flag = 1
            
        elif ai_response.get("vulnerable") is True and ai_response['defense_mechanisms'][0] != "None":
            vulnerability_type = "CSRF (Potential)"
            severity = "Mediam" # Mark as potential medium if AI says vulnerable
            description = f"Potential CSRF vulnerability: {ai_response.get('reason')}. Defense mechanisms detected: {', '.join(ai_response.get('defense_mechanisms', ['None']))}"
            print(f"{YELLOW}   [!] AI indicates potential CSRF vulnerability for {request_data.get('url', 'N/A')}{NC}")
            flag=2
        else:
            description = f"No immediate CSRF vulnerability detected by AI. Defenses: {', '.join(ai_response.get('defense_mechanisms', ['None']))}"
            print(f"{GREEN}   [+] AI indicates no immediate CSRF vulnerability for {request_data.get('url', 'N/A')}{NC}")
            

        vuln_data = {
            "vulnerability": vulnerability_type,
            "severity": severity,
            "url": request_data.get("url", "N/A"),
            "method": request_data.get("method", "N/A"),
            "description": description,
            "ai_analysis": ai_response # Store full AI analysis for context
        }
        
        if flag == 1:
            try_save_vulnerability(vuln_data, session, scan_id)
        return ai_response,flag # Return AI response for further testing
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Gemini response for CSRF check for request {request_data.get('url', 'N/A')}: {str(e)}")
        logger.error(f"Raw response was: {gemini_output}")
        # Store error as a low-severity vulnerability/info
        vuln_data = {
            "vulnerability": "CSRF Analysis Error",
            "severity": "low",
            "url": request_data.get("url", "N/A"),
            "method": request_data.get("method", "N/A"),
            "description": f"Failed to parse AI response for CSRF check: {str(e)}. Raw AI response: {gemini_output[:500]}..."
        }
        try_save_vulnerability(vuln_data, session, scan_id)
        return None
    except Exception as e:
        logger.error(f"Error during CSRF AI check for {request_data.get('url', 'N/A')}: {str(e)}")
        return None

# Function to perform CSRF tests based on AI analysis
def csrfTests(ai_analysis_response, original_request_data, session, scan_id):
    print(f"{BLUE}[*] Performing CSRF tests for: {original_request_data.get('url', 'N/A')}{NC}")
    
    if not ai_analysis_response or ai_analysis_response.get("vulnerable") is not True:
        print(f"{YELLOW}   [!] AI analysis did not indicate initial vulnerability, skipping detailed CSRF tests.{NC}")
        return

    url = original_request_data["url"]
    method = original_request_data.get("method", "POST").upper()
    
    # Ensure body and headers are dictionaries
    body = original_request_data.get("body_params")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            body = parse_qs(body) # Try to parse as form-urlencoded if not JSON
    if not isinstance(body, dict):
        body = {}

    headers = original_request_data.get("extra_headers")
    if isinstance(headers, str):
        try:
            headers = json.loads(headers)
        except json.JSONDecodeError:
            headers = {} # Default to empty dict if it's a non-JSON string
    if not isinstance(headers, dict):
        headers = {}


    # Extract original cookie for session handling
    original_cookie_header = headers.get("Cookie", "")
    cookies = {}
    if original_cookie_header:
        for c in original_cookie_header.split(';'):
            if '=' in c:
                key, val = c.strip().split('=', 1)
                cookies[key] = val

    csrf_parameter = ai_analysis_response.get("csrf_parameter")
    # In a real scenario, valid_csrf_token would be dynamically fetched from a GET request to the page
    # that serves the form, or the initial legitimate login/session.
    # For automated testing, this might be a known valid token if available, or extracted via scraping.
    valid_csrf_token = ai_analysis_response.get("csrf_token_value", "") # Token extracted by AI for original request

    # Analyze responses for successful action (heuristic)
    # Common indicators of successful action: 200 OK, redirect (3xx), specific success messages.
    # Common indicators of failed CSRF: 403 Forbidden, 400 Bad Request (invalid token), error messages.

    def is_successful_action(response):
        if not response or response.get("error"):
            return False
        status = response.get("status")
        body = response.get("response_body", "").lower()
        if status in [200, 302, 301, 204]: # 204 No Content also indicates success
            if "error" in body or "fail" in body or "invalid token" in body or "forbidden" in body:
                return False
            return True
        return False

    # --- Test 1: Request without any CSRF token ---
    test_1_body = body.copy()
    if csrf_parameter and csrf_parameter in test_1_body:
        test_1_body.pop(csrf_parameter) # Remove the CSRF token
    
    # Remove Referer header if defense_mechanisms includes "Referer Check"
    test_1_headers = headers.copy()
    if "Referer Check" in ai_analysis_response.get("defense_mechanisms", []):
        test_1_headers.pop("Referer", None)

    print(f"   [ ] Test 1: Request without CSRF token and potentially without Referer")
    res1 = send_request({"url": url, "method": method, "body_params": test_1_body, "extra_headers": test_1_headers})
    
    if is_successful_action(res1):
        vuln_data = {
            "vulnerability": "CSRF (No Token)",
            "severity": "high",
            "url": url,
            "method": method,
            "description": f"Vulnerable to CSRF (no token): Request succeeded after removing CSRF token. Status: {res1.get('status')}",
            "evidence": res1.get('response_body', '')[:500]
        }
        try_save_vulnerability(vuln_data, session, scan_id)
        print(f"{GREEN}   [+] CSRF (No Token) vulnerability confirmed for {url}{NC}")
        return
    
    # --- Test 2: Request with invalid/empty CSRF token ---
    test_2_body = body.copy()
    if csrf_parameter:
        test_2_body[csrf_parameter] = "INVALID_TOKEN_TEST" # Invalid token
    
    test_2_headers = headers.copy()
    if "Referer Check" in ai_analysis_response.get("defense_mechanisms", []):
        test_2_headers.pop("Referer", None)

    print(f"   [ ] Test 2: Request with invalid CSRF token")
    res2 = send_request({"url": url, "method": method, "body_params": test_2_body, "extra_headers": test_2_headers})

    if is_successful_action(res2):
        vuln_data = {
            "vulnerability": "CSRF (Invalid Token)",
            "severity": "high",
            "url": url,
            "method": method,
            "description": f"Vulnerable to CSRF (invalid token): Request succeeded with an invalid/dummy CSRF token. Status: {res2.get('status')}",
            "evidence": res2.get('response_body', '')[:500]
        }
        try_save_vulnerability(vuln_data, session, scan_id)
        print(f"{GREEN}   [+] CSRF (Invalid Token) vulnerability confirmed for {url}{NC}")
        return

    # --- Test 3: Request with a valid token but from a different "origin" (simulated by removing Referer) ---
    test_3_body = body.copy()
    # Keep original valid token if it exists in body
    
    test_3_headers = headers.copy()
    test_3_headers.pop("Referer", None) # Remove Referer to simulate cross-origin
    
    print(f"   [ ] Test 3: Request with valid token but no Referer")
    res3 = send_request({"url": url, "method": method, "body_params": test_3_body, "extra_headers": test_3_headers})

    if is_successful_action(res3) and "SameSite=Strict" not in ai_analysis_response.get("defense_mechanisms", []) and "Referer Check" not in ai_analysis_response.get("defense_mechanisms", []):
        vuln_data = {
            "vulnerability": "CSRF (Referer Bypass/SameSite Lax)",
            "severity": "medium",
            "url": url,
            "method": method,
            "description": f"Vulnerable to CSRF (Referer bypass): Request succeeded when Referer was removed. Status: {res3.get('status')}. This might indicate weak Referer validation or SameSite=Lax/None.",
            "evidence": res3.get('response_body', '')[:500]
        }
        try_save_vulnerability(vuln_data, session, scan_id)
        print(f"{GREEN}   [+] CSRF (Referer Bypass/SameSite Lax) vulnerability confirmed for {url}{NC}")

    print(f"{GREEN}[+] CSRF tests completed for {url}.{NC}")
    return
    
    
    

    

    

    

# Main CSRF function
def csrf(urls_file_path, session=None, scan_id=None):
    """
    Performs CSRF vulnerability checks and tests based on a file containing URLs/requests.
    All findings are stored in the database.
    """
    print(f"{YELLOW}[+] Starting CSRF scan...{NC}")

    if session is None or scan_id is None:
        print(f"{RED}[!] Database session or scan_id not provided. Cannot perform CSRF scan.{NC}")
        return

    # Fetch relevant endpoints from the database for CSRF testing.
    # CSRF typically applies to state-changing requests (POST, PUT, DELETE).
    # We will fetch all such endpoints for the current scan ID.
    requests_to_test_from_db = session.query(Endpoint).filter(
        Endpoint.scan_id == scan_id,
        Endpoint.method.in_(['POST', 'PUT', 'DELETE'])
    ).all()

    if not requests_to_test_from_db:
        print(f"{YELLOW}[!] No relevant POST/PUT/DELETE endpoints found for CSRF testing for scan ID {scan_id}. Skipping.{NC}")
        return []

    # Convert Endpoint objects to dictionary format expected by AI and send_request
    requests_data_for_ai = []
    for ep in requests_to_test_from_db:
        # Safely load JSON strings from DB fields, defaulting to empty dict if null/malformed
        body_params = {}
        if ep.body_params:
            try:
                body_params = json.loads(ep.body_params) if isinstance(ep.body_params, str) else ep.body_params
            except json.JSONDecodeError:
                logger.warning(f"Failed to decode body_params JSON for {ep.url}. Attempting parse_qs.")
                body_params = parse_qs(ep.body_params) # Fallback for form-urlencoded
            if not isinstance(body_params, dict): # Ensure it's a dict after all attempts
                body_params = {}

        extra_headers = {}
        if ep.extra_headers:
            try:
                extra_headers = json.loads(ep.extra_headers) if isinstance(ep.extra_headers, str) else ep.extra_headers
            except json.JSONDecodeError:
                logger.warning(f"Failed to decode extra_headers JSON for {ep.url}. Defaulting to empty dict.")
            if not isinstance(extra_headers, dict): # Ensure it's a dict after all attempts
                extra_headers = {}

        requests_data_for_ai.append({
            "url": ep.url,
            "method": ep.method,
            "body_params": body_params,
            "extra_headers": extra_headers
        })

    if not requests_data_for_ai:
        print(f"{RED}[!] No suitable requests found from DB to test for CSRF after filtering.{NC}")
        return []

    for req_data in requests_data_for_ai:
        # Step 1: AI analysis for CSRF defense mechanisms
        ai_res,flag = csrfCheck(req_data, session, scan_id)
        print("flag: ",flag)
        if flag == 2:
            # Step 2: Perform active CSRF tests based on AI analysis
            if ai_res: # Only proceed if AI analysis was successful
                csrfTests(ai_res, req_data, session, scan_id)
        

    print(f"{GREEN}[+] CSRF scan completed. Results stored in database.{NC}")

# This part is for direct testing of the module
if __name__ == "__main__":
    # This is for testing purposes only.
    from tools.database import init_db, get_session, Base, ScanHistory, Endpoint # For local testing

    # Initialize a temporary database for testing
    temp_db_engine = init_db('sqlite:///test_csrf.db')
    test_session = get_session(temp_db_engine)
    
    # Create a dummy ScanHistory record for testing
    test_domain = "test-csrf-target.com"
    test_scan = test_session.query(ScanHistory).filter_by(domain=test_domain).first()
    if not test_scan:
        test_scan = ScanHistory(domain=test_domain)
        test_session.add(test_scan)
        test_session.commit()
    test_scan_id = test_scan.id

    dummy_output_dir = "test_csrf_output"
    os.makedirs(dummy_output_dir, exist_ok=True)

    # Add some dummy endpoints to the database for CSRF testing
    # These would normally come from autorecon.py and represent state-changing actions
    dummy_endpoints_data = [
        {"url": "[http://test-csrf-target.com/change_password](http://test-csrf-target.com/change_password)", "method": "POST", "body_params": {"old_pass": "oldpass", "new_pass": "newpass", "csrf_token": "a_valid_csrf_token_example"}, "extra_headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "sessionid=test_session_id; other_cookie=value"}},
        {"url": "[http://test-csrf-target.com/delete_item](http://test-csrf-target.com/delete_item)", "method": "POST", "body_params": {"item_id": 123}, "extra_headers": {"Content-Type": "application/json", "Cookie": "sessionid=test_session_id"}},
        {"url": "[http://test-csrf-target.com/view_profile](http://test-csrf-target.com/view_profile)", "method": "GET", "body_params": {}, "extra_headers": {"Cookie": "sessionid=test_session_id"}} # GET request, should be ignored by filter
    ]

    for ep_data in dummy_endpoints_data:
        try:
            # Ensure body_params and extra_headers are stored as JSON strings if they are dicts
            body_params_json = json.dumps(ep_data["body_params"]) if isinstance(ep_data["body_params"], dict) else ep_data["body_params"]
            extra_headers_json = json.dumps(ep_data["extra_headers"]) if isinstance(ep_data["extra_headers"], dict) else ep_data["extra_headers"]

            new_endpoint = Endpoint(
                scan_id=test_scan_id,
                url=ep_data["url"],
                method=ep_data["method"],
                body_params=body_params_json,
                extra_headers=extra_headers_json
            )
            test_session.add(new_endpoint)
            test_session.commit()
        except IntegrityError:
            test_session.rollback()
            logger.info(f"Duplicate endpoint added for testing: {ep_data['url']}")
        except Exception as db_e:
            test_session.rollback()
            logger.error(f"Error adding dummy endpoint to DB: {db_e}")

    print(f"{BLUE}[+] Running CSRF test with database integration...{NC}")
    # Note: `gemini` function from `ai_assistant.py` must be configured and accessible for this to work.
    csrf("dummy_file_path_not_used_anymore", session=test_session, scan_id=test_scan_id)
    
    print(f"{BLUE}[+] Verifying CSRF results from database...{NC}")
    retrieved_vulns = test_session.query(Vulnerability).filter_by(scan_id=test_scan_id).all()
    for vuln in retrieved_vulns:
        print(f"   Vulnerability Found: {vuln.vulnerability_type} at {vuln.url} (Severity: {vuln.severity})")
        print(f"     Full Data: {vuln.vulnerability_data}")

    test_session.close()
    
    # Clean up test files and directory
    if os.path.exists('test_csrf.db'):
        os.remove('test_csrf.db')
    
    try:
        if os.path.exists(dummy_output_dir) and not os.listdir(dummy_output_dir):
            os.rmdir(dummy_output_dir)
        else:
            print(f"{YELLOW}[!] Directory {dummy_output_dir} not empty, skipping rmdir.{NC}")
    except OSError as e:
        print(f"{RED}Error removing directory {dummy_output_dir}: {e}{NC}")

    print(f"{GREEN}[+] CSRF test completed.{NC}")