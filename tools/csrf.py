import re
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
            "headers": dict(res.headers) # Include response headers for SameSite check
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
    1. Relevant action (e.g., state-changing request like POST, PUT, DELETE, PATCH).
    2. Cookie-based session handling.
    3. Absence of effective unpredictable parameters (e.g., CSRF token, unique nonce) or improper validation of them.

    Identify any defense mechanisms present, such as:
    - CSRF Token: Look for unpredictable tokens in form fields (body_params), query parameters, or HTTP headers (extra_headers).
    - SameSite Cookies: Check 'Cookie' header for 'SameSite=Strict' or 'SameSite=Lax'.
    - Referer-based validation: Implied if 'Referer' header is expected/checked.

    If a CSRF token is found, specify its name, value, and where it was found (e.g., "body_params", "extra_headers", "url_query", "cookie").

    Here is the HTTP request:
    {json.dumps(request_data, indent=2)}

    Return ONLY a JSON object with the following structure:
    {{
        "vulnerable": true/false,
        "reason": "Brief explanation of vulnerability or lack thereof",
        "defense_mechanisms": ["CSRF Token", "SameSite=Lax", "Referer Check", "None"],
        "csrf_token_info": {{
            "name": "Name of the CSRF token parameter, if found (e.g., 'csrf_token', 'authenticity_token')",
            "value": "Value of the CSRF token, if found",
            "location": "Where the token was found (e.g., 'body_params', 'extra_headers', 'url_query', 'cookie')"
        }} | null,
        "action_url": "The URL where the action is performed",
        "method": "The HTTP method"
    }}
    """

    gemini_output = gemini(prompt)
    gemini_output = clean_gemini_response(gemini_output)

    try:
        ai_response = json.loads(gemini_output)
        
        vulnerability_type = "CSRF Analysis"
        severity = "info" # Initial analysis is informational
        description = ai_response.get("reason", "CSRF analysis performed.")
        flag = 0 # 0 : No Vulnerability -- 1 : Vulnerability detected (no defenses) -- 2 : Potential vulnerability (some defenses)

        if ai_response.get("vulnerable") is True:
            if "None" in ai_response.get("defense_mechanisms", []):
                vulnerability_type = "CSRF"
                severity = "high"
                description = f"Confirmed CSRF vulnerability: {ai_response.get('reason')}. No defense mechanisms detected."
                print(f"{RED}   [!!!] AI indicates CONFIRMED CSRF vulnerability for {request_data.get('url', 'N/A')} (No Defenses){NC}")
                flag = 1
            else:
                vulnerability_type = "CSRF (Potential)"
                severity = "medium"
                description = f"Potential CSRF vulnerability: {ai_response.get('reason')}. Defenses: {', '.join(ai_response.get('defense_mechanisms', []))}."
                print(f"{YELLOW}   [!] AI indicates potential CSRF vulnerability for {request_data.get('url', 'N/A')} (Defenses Present){NC}")
                flag = 2
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
        
        if flag == 1: # Only save if confirmed high vulnerability
            try_save_vulnerability(vuln_data, session, scan_id)
        
        return ai_response, flag # Return AI response and flag for further testing decision
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Gemini response for CSRF check for request {request_data.get('url', 'N/A')}: {str(e)}")
        logger.error(f"Raw response was: {gemini_output}")
        vuln_data = {
            "vulnerability": "CSRF Analysis Error",
            "severity": "low",
            "url": request_data.get("url", "N/A"),
            "method": request_data.get("method", "N/A"),
            "description": f"Failed to parse AI response for CSRF check: {str(e)}. Raw AI response: {gemini_output[:500]}..."
        }
        try_save_vulnerability(vuln_data, session, scan_id)
        return None, 0
    except Exception as e:
        logger.error(f"Error during CSRF AI check for {request_data.get('url', 'N/A')}: {str(e)}")
        return None, 0

def get_csrf_token_from_response(response_body, csrf_param_name):
    """
    Attempts to extract a CSRF token from HTML or JSON response body.
    This is a heuristic and might need to be more sophisticated for real-world apps.
    """
    if not csrf_param_name:
        return None

    # Try to find in HTML form input
    match = re.search(rf'<input[^>]+name=["\']{re.escape(csrf_param_name)}["\'][^>]+value=["\']([^"\']+)["\']', response_body)
    if match:
        return match.group(1)
    
    # Try to find in JSON (simple key-value)
    try:
        json_data = json.loads(response_body)
        if csrf_param_name in json_data:
            return str(json_data[csrf_param_name])
    except json.JSONDecodeError:
        pass # Not a JSON response

    # Try to find in JavaScript (e.g., var csrfToken = '...' )
    match = re.search(rf'var\s+{re.escape(csrf_param_name)}\s*=\s*["\']([^"\']+)["\']', response_body)
    if match:
        return match.group(1)

    return None

# Function to perform CSRF tests based on AI analysis
def csrfTests(ai_analysis_response, original_request_data, session, scan_id, headers1=None, headers2=None):
    print(f"{BLUE}[*] Performing CSRF tests for: {original_request_data.get('url', 'N/A')}{NC}")
    
    if not ai_analysis_response or ai_analysis_response.get("vulnerable") is not True:
        print(f"{YELLOW}   [!] AI analysis did not indicate initial vulnerability for active tests. Skipping.{NC}")
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

    # Use headers1 if provided, otherwise default to original_request_data's headers
    user1_headers = headers1 if headers1 is not None else original_request_data.get("extra_headers", {})
    if isinstance(user1_headers, str): # Ensure headers are dicts
        try:
            user1_headers = json.loads(user1_headers)
        except json.JSONDecodeError:
            user1_headers = {}
    if not isinstance(user1_headers, dict):
        user1_headers = {}

    user2_headers = headers2 if headers2 is not None else {} # User2 headers, default to empty if not provided
    if isinstance(user2_headers, str): # Ensure headers are dicts
        try:
            user2_headers = json.loads(user2_headers)
        except json.JSONDecodeError:
            user2_headers = {}
    if not isinstance(user2_headers, dict):
        user2_headers = {}


    csrf_token_info = ai_analysis_response.get("csrf_token_info")
    csrf_parameter = csrf_token_info.get("name") if csrf_token_info else None
    original_csrf_token_value = csrf_token_info.get("value") if csrf_token_info else None
    csrf_token_location = csrf_token_info.get("location") if csrf_token_info else None


    def is_successful_action(response):
        if not response or response.get("error"):
            return False
        status = response.get("status")
        body = response.get("response_body", "").lower()
        # Check for success codes AND absence of explicit error messages
        if status in [200, 302, 301, 204]:
            if "error" in body or "fail" in body or "invalid token" in body or "forbidden" in body or "access denied" in body:
                return False
            # Further checks: if original response had certain unique content (e.g., "Welcome UserX"),
            # and the modified request returns the same, it could indicate success.
            # This would require comparing responses, which is complex for a generic tool.
            return True
        return False

    # Helper to modify request data based on token location
    def modify_request_for_token(req_body, req_headers, token_name, token_value, token_location):
        modified_body = req_body.copy()
        modified_headers = req_headers.copy()
        
        if token_location == "body_params":
            modified_body[token_name] = token_value
        elif token_location == "extra_headers":
            modified_headers[token_name] = token_value
        elif token_location == "url_query": # This means token is in URL query params
            # For URL query, we need to reconstruct the URL. This is complex.
            # For simplicity, we'll assume the base URL is constant and only modify body/headers for now.
            # A more robust solution would involve parsing and re-encoding the URL query.
            pass 
        elif token_location == "cookie":
            # Modifying cookies directly in headers is complex as it might overwrite other cookies.
            # This would typically require a session object or more granular cookie management.
            # For now, we'll assume token is not primarily in cookie for direct manipulation here.
            pass
        return modified_body, modified_headers

    # --- Test 1: Request without any CSRF token ---
    test_1_body = body.copy()
    test_1_headers = user1_headers.copy()

    if csrf_parameter and csrf_token_location:
        if csrf_token_location == "body_params" and csrf_parameter in test_1_body:
            test_1_body.pop(csrf_parameter)
        elif csrf_token_location == "extra_headers" and csrf_parameter in test_1_headers:
            test_1_headers.pop(csrf_parameter)
        # For URL query or cookie, removing the token is more complex and might not be directly achievable here
        # without full URL manipulation or cookie management.

    if "Referer Check" in ai_analysis_response.get("defense_mechanisms", []):
        test_1_headers.pop("Referer", None) # Simulate cross-origin by removing Referer

    print(f"   [ ] Test 1: Request without CSRF token (User 1 session)")
    res1 = send_request({"url": url, "method": method, "body_params": test_1_body, "extra_headers": test_1_headers})
    
    if is_successful_action(res1):
        vuln_data = {
            "vulnerability": "CSRF (No Token)",
            "severity": "high",
            "url": url,
            "method": method,
            "description": f"Vulnerable to CSRF (no token): Request succeeded after removing CSRF token. Status: {res1.get('status')}.",
            "evidence": res1.get('response_body', '')[:500]
        }
        try_save_vulnerability(vuln_data, session, scan_id)
        print(f"{GREEN}   [+] CSRF (No Token) vulnerability confirmed for {url}{NC}")
        return # Found critical vulnerability, no need for further tests on this endpoint

    # --- Test 2: Request with invalid/empty CSRF token ---
    if csrf_parameter and csrf_token_location: # Only run if a CSRF parameter was identified
        test_2_body, test_2_headers = modify_request_for_token(body, user1_headers, csrf_parameter, "INVALID_TOKEN_TEST", csrf_token_location)
        
        if "Referer Check" in ai_analysis_response.get("defense_mechanisms", []):
            test_2_headers.pop("Referer", None)

        print(f"   [ ] Test 2: Request with invalid CSRF token (User 1 session)")
        res2 = send_request({"url": url, "method": method, "body_params": test_2_body, "extra_headers": test_2_headers})

        if is_successful_action(res2):
            vuln_data = {
                "vulnerability": "CSRF (Invalid Token)",
                "severity": "high",
                "url": url,
                "method": method,
                "description": f"Vulnerable to CSRF (invalid token): Request succeeded with an invalid/dummy CSRF token. Status: {res2.get('status')}.",
                "evidence": res2.get('response_body', '')[:500]
            }
            try_save_vulnerability(vuln_data, session, scan_id)
            print(f"{GREEN}   [+] CSRF (Invalid Token) vulnerability confirmed for {url}{NC}")
            return # Found critical vulnerability, no need for further tests on this endpoint

    # --- Test 3: Request with a valid token but from a different "origin" (simulated by removing Referer) ---
    # This test is more about Referer/SameSite than token itself, but included for completeness.
    # We still use the original valid token from User 1's perspective.
    test_3_body = body.copy() # Keep original body with its token
    test_3_headers = user1_headers.copy()
    test_3_headers.pop("Referer", None) # Remove Referer to simulate cross-origin
    
    print(f"   [ ] Test 3: Request with original token but no Referer (User 1 session)")
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
        # Not a critical block, so continue to next test if any.

    # --- Test 4: Request with a valid token from User 2, but User 1's session (if headers2 provided and token found) ---
    if csrf_parameter and csrf_token_location and headers2:
        print(f"   [ ] Test 4: Request with valid token from User 2, but User 1 session")
        
        # Step 4.1: Get a valid CSRF token using user2_headers
        # Make a GET request to the URL with User 2's headers to fetch a token from the response body
        # This assumes the token is present in the response to a GET request to the same URL.
        get_token_request_data = {
            "url": url,
            "method": "GET",
            "body_params": {},
            "extra_headers": user2_headers
        }
        print(f"       [*] Fetching User 2's CSRF token from {url} with their headers...")
        token_response_user2 = send_request(get_token_request_data)
        
        valid_token_from_user2 = None
        if token_response_user2 and not token_response_user2.get("error"):
            valid_token_from_user2 = get_csrf_token_from_response(token_response_user2.get("response_body", ""), csrf_parameter)
            if valid_token_from_user2:
                print(f"       [+] Successfully fetched User 2's token: {valid_token_from_user2[:10]}...{NC}")
            else:
                print(f"       [!] Could not extract User 2's CSRF token from response. Skipping Test 4.{NC}")

        if valid_token_from_user2:
            test_4_body, test_4_headers = modify_request_for_token(body, user1_headers, csrf_parameter, valid_token_from_user2, csrf_token_location)
            
            if "Referer Check" in ai_analysis_response.get("defense_mechanisms", []):
                test_4_headers.pop("Referer", None) # Remove Referer for cross-origin simulation

            print(f"       [*] Sending request with User 1 session and User 2's token...")
            res4 = send_request({"url": url, "method": method, "body_params": test_4_body, "extra_headers": test_4_headers})

            if is_successful_action(res4):
                vuln_data = {
                    "vulnerability": "CSRF (Token Replay/Improper Validation)",
                    "severity": "high",
                    "url": url,
                    "method": method,
                    "description": f"Vulnerable to CSRF (Token Replay/Improper Validation): Request succeeded with a valid CSRF token issued to another user. This indicates the server does not tie the token to the current user's session. Status: {res4.get('status')}.",
                    "evidence": res4.get('response_body', '')[:500]
                }
                try_save_vulnerability(vuln_data, session, scan_id)
                print(f"{GREEN}   [+] CSRF (Token Replay/Improper Validation) vulnerability confirmed for {url}{NC}")
                return # Found critical vulnerability, no need for further tests on this endpoint
            else:
                print(f"{YELLOW}   [!] Test 4: Request with User 1 session and User 2's token failed as expected.{NC}")
        else:
            print(f"{YELLOW}   [!] Test 4 skipped due to inability to retrieve valid token from User 2 or headers2 not provided.{NC}")

    print(f"{GREEN}[+] CSRF tests completed for {url}.{NC}")
    return
    
# Main CSRF function
def csrf(urls_file_path=None, session=None, scan_id=None, headers1=None, headers2=None):
    """
    Performs CSRF vulnerability checks and tests based on endpoints from the database.
    Optional headers1 and headers2 can be provided for multi-user testing.
    All findings are stored in the database.
    """
    print(f"{YELLOW}[+] Starting CSRF scan...{NC}")

    if session is None or scan_id is None:
        print(f"{RED}[!] Database session or scan_id not provided. Cannot perform CSRF scan.{NC}")
        return

    # Fetch relevant endpoints from the database for CSRF testing.
    # CSRF typically applies to state-changing requests (POST, PUT, DELETE, PATCH).
    # We will fetch all such endpoints for the current scan ID.
    requests_to_test_from_db = session.query(Endpoint).filter(
        Endpoint.scan_id == scan_id,
        Endpoint.method.in_(['POST', 'PUT', 'DELETE', 'PATCH'])
    ).all()

    if not requests_to_test_from_db:
        print(f"{YELLOW}[!] No relevant POST/PUT/DELETE/PATCH endpoints found for CSRF testing for scan ID {scan_id}. Skipping.{NC}")
        return []

    # Convert Endpoint objects to dictionary format expected by AI and send_request
    requests_data_for_ai = []
    for ep in requests_to_test_from_db:
        body_params = {}
        if ep.body_params:
            try:
                body_params = json.loads(ep.body_params) if isinstance(ep.body_params, str) else ep.body_params
            except json.JSONDecodeError:
                logger.warning(f"Failed to decode body_params JSON for {ep.url}. Attempting parse_qs.")
                body_params = parse_qs(ep.body_params)
            if not isinstance(body_params, dict):
                body_params = {}

        extra_headers = {}
        if ep.extra_headers:
            try:
                extra_headers = json.loads(ep.extra_headers) if isinstance(ep.extra_headers, str) else ep.extra_headers
            except json.JSONDecodeError:
                logger.warning(f"Failed to decode extra_headers JSON for {ep.url}. Defaulting to empty dict.")
            if not isinstance(extra_headers, dict):
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
        ai_res, flag = csrfCheck(req_data, session, scan_id)
        
        # Only perform active tests if the initial AI analysis indicates a potential vulnerability (flag == 2)
        # If flag is 1 (confirmed high vulnerability with no defenses), we skip active tests.
        if flag == 2:
            if ai_res:
                csrfTests(ai_res, req_data, session, scan_id, headers1=headers1, headers2=headers2)
        elif flag == 1:
            print(f"{YELLOW}   [!] Skipping active CSRF tests for {req_data.get('url')} because it's already confirmed vulnerable (flag=1).{NC}")

    print(f"{GREEN}[+] CSRF scan completed. Results stored in database.{NC}")

# This part is for direct testing of the module
if __name__ == "__main__":
    from tools.database import init_db, get_session, Base, ScanHistory, Endpoint # For local testing

    temp_db_engine = init_db('sqlite:///test_csrf.db')
    test_session = get_session(temp_db_engine)
    
    test_domain = "test-csrf-target.com"
    test_scan = test_session.query(ScanHistory).filter_by(domain=test_domain).first()
    if not test_scan:
        test_scan = ScanHistory(domain=test_domain)
        test_session.add(test_scan)
        test_session.commit()
    test_scan_id = test_scan.id

    dummy_output_dir = "test_csrf_output"
    os.makedirs(dummy_output_dir, exist_ok=True)

    # Example: Headers for two different users
    headers_user1 = {"User-Agent": "Mozilla/5.0", "Accept": "application/json", "Cookie": "sessionid=user1_session_id; other_cookie=value"}
    headers_user2 = {"User-Agent": "Mozilla/5.0", "Accept": "application/json", "Cookie": "sessionid=user2_session_id; another_cookie=value"}

    dummy_endpoints_data = [
        # Vulnerable to no token/invalid token
        {"url": "[http://test-csrf-target.com/change_password](http://test-csrf-target.com/change_password)", "method": "POST", 
         "body_params": {"old_pass": "oldpass", "new_pass": "newpass", "csrf_token": "a_valid_csrf_token_example"}, 
         "extra_headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "sessionid=user1_session_id"}},
        
        # Potentially vulnerable to token replay (AI would extract "item_id_token")
        {"url": "[http://test-csrf-target.com/delete_item](http://test-csrf-target.com/delete_item)", "method": "DELETE", 
         "body_params": {"item_id": 123, "item_id_token": "token_for_item_123"}, 
         "extra_headers": {"Content-Type": "application/json", "Cookie": "sessionid=user1_session_id"}},
        
        # GET request, should be ignored by method filter
        {"url": "[http://test-csrf-target.com/view_profile](http://test-csrf-target.com/view_profile)", "method": "GET", "body_params": {}, "extra_headers": {"Cookie": "sessionid=test_session_id"}} 
    ]

    for ep_data in dummy_endpoints_data:
        try:
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
    # Pass dummy headers for two users for testing cross-user token scenarios
    csrf(session=test_session, scan_id=test_scan_id, headers1=headers_user1, headers2=headers_user2)
    
    print(f"{BLUE}[+] Verifying CSRF results from database...{NC}")
    retrieved_vulns = test_session.query(Vulnerability).filter_by(scan_id=test_scan_id).all()
    for vuln in retrieved_vulns:
        print(f"   Vulnerability Found: {vuln.vulnerability_type} at {vuln.url} (Severity: {vuln.severity})")
        print(f"     Full Data: {vuln.vulnerability_data}")

    test_session.close()
    
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