import json
import requests
import os
from urllib.parse import urlparse, urlencode, parse_qs
import logging
import re
from sqlalchemy.exc import IntegrityError
from tools.database import Vulnerability, Endpoint # Import Vulnerability and Endpoint models
from tools.ai_assistant import gemini ,clean_gemini_response
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

def send_request(req_data):
    """
    Sends an HTTP request based on the provided request data.
    """
    method = req_data.get("method", "GET").upper()
    url = req_data["url"]
    headers = req_data.get("extra_headers", {})
    body = req_data.get("body_params", None)

    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            # Attempt to construct absolute URL if relative
            host = headers.get("Host")
            if not host:
                return {"error": "Missing 'Host' header for relative URL"}
            scheme = "https" # Default to https
            url = f"{scheme}://{host}{url}"

        # Convert dict body to form-urlencoded string if Content-Type is set
        if isinstance(body, dict):
            content_type = headers.get("Content-Type", "").lower()
            if "application/x-www-form-urlencoded" in content_type:
                body = urlencode(body)
            elif "application/json" in content_type:
                body = json.dumps(body)

        response = None
        if method == "GET":
            response = requests.get(url, headers=headers, allow_redirects=False)
        elif method == "POST":
            response = requests.post(url, headers=headers, data=body, allow_redirects=False)
        elif method == "PUT":
            response = requests.put(url, headers=headers, data=body, allow_redirects=False)
        elif method == "PATCH":
            response = requests.patch(url, headers=headers, data=body, allow_redirects=False)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, data=body, allow_redirects=False)
        
        if response:
            return {
                "url": url,
                "status": response.status_code,
                "response_body": response.text,
                "headers": dict(response.headers)
            }
        else:
            return {"error": f"Unsupported HTTP method: {method}"}

    except requests.exceptions.RequestException as e:
        logger.error(f"Request error for {url} ({method}): {str(e)}")
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"General error sending request to {url} ({method}): {str(e)}")
        return {"error": str(e)}

def bac_check_with_ai(original_request_data, modified_request_data_user2):
    """
    Uses AI to analyze the original request (user 1) and the same request
    sent with user 2's session (user 1's request with user 2's headers)
    to determine Broken Access Control.
    This function is called ONLY if User 2's response status is not 401/403.
    """
    print(f"{BLUE}[*] AI Analyzing for Broken Access Control for {original_request_data.get('url', 'N/A')}{NC}")

    prompt = f"""
    You are an expert in web security, specifically identifying Broken Access Control (BAC).

    Here is an original HTTP request made by User 1:
    {json.dumps(original_request_data, indent=2)}

    Here is the response received by User 1 for their original request:
    {json.dumps(original_request_data.get('response', {}), indent=2)}

    Here is the exact same request, but sent with User 2's session/headers:
    {json.dumps(modified_request_data_user2, indent=2)}

    Here is the response received when User 2's session was used:
    {json.dumps(modified_request_data_user2.get('response', {}), indent=2)}

    Based on these two requests and their responses, determine if there is a Broken Access Control vulnerability.
    Crucially, User 2's response status was NOT 401 or 403, which suggests potential unauthorized access.
    Consider the following for a vulnerability:
    1. User 2's request should ideally have been denied (e.g., 401 Unauthorized, 403 Forbidden, redirect to login). Since it wasn't, we need to check the content.
    2. If User 2's request gets a 200 OK or similar success code AND the content returned appears to be User 1's data or privileged data (that User 2 should not see), it's a vulnerability.
    3. Look for discrepancies in content or functionality that expose User 1's private information or allow unauthorized actions from User 2.
    4. If the content for User 1 and User 2 is identical for what should be private data, it's a vulnerability.
    5. Be cautious of responses that indicate generic 'not found' but are indistinguishable from 'forbidden' (e.g., returning 200 with empty data when it should be 403).

    Return ONLY a JSON object with the following structure:
    {{
        "vulnerable": true/false,
        "severity": "high" | "medium" | "low" | "info",
        "reason": "Brief explanation of why it is or isn't vulnerable, citing status codes or content differences/similarities. Indicate if User 2 successfully accessed User 1's data or performed an unauthorized action.",
        "original_request_summary": {{ "url": "...", "method": "...", "status": "..." }},
        "user2_request_summary": {{ "url": "...", "method": "...", "status": "..." }},
        "vulnerable_resource_path": "Path of the resource that was improperly accessed",
        "evidence": "Snippet of response that shows unauthorized access (e.g., 'email': 'user1@example.com')"
    }}
    """
    gemini_output = gemini(prompt)
    gemini_output = clean_gemini_response(gemini_output)

    try:
        ai_analysis = json.loads(gemini_output)
        return ai_analysis
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse AI response for BAC check for {original_request_data.get('url', 'N/A')}: {str(e)}")
        logger.error(f"Raw response was: {gemini_output}")
        return {
            "vulnerable": False,
            "severity": "low",
            "reason": f"AI analysis failed to parse: {str(e)}. Raw AI response: {gemini_output[:200]}...",
            "original_request_summary": {"url": original_request_data.get('url', 'N/A'), "method": original_request_data.get('method', 'N/A')},
            "user2_request_summary": {"url": modified_request_data_user2.get('url', 'N/A'), "method": modified_request_data_user2.get('method', 'N/A')}
        }
    except Exception as e:
        logger.error(f"Error during BAC AI check for {original_request_data.get('url', 'N/A')}: {str(e)}")
        return {
            "vulnerable": False,
            "severity": "low",
            "reason": f"Unexpected error during AI analysis: {str(e)}",
            "original_request_summary": {"url": original_request_data.get('url', 'N/A'), "method": original_request_data.get('method', 'N/A')},
            "user2_request_summary": {"url": modified_request_data_user2.get('url', 'N/A'), "method": modified_request_data_user2.get('method', 'N/A')}
        }

def process_single_endpoint_for_bac(endpoint_obj, session, scan_id, headers1, headers2):
    """
    Processes a single endpoint to test for Broken Access Control.
    It takes an Endpoint object, sends the request with headers1 (user 1's session)
    and then with headers2 (user 2's session), and uses AI to compare the responses.
    """
    url = endpoint_obj.url
    method = endpoint_obj.method
    # Safely load JSON strings from DB fields, defaulting to empty dict if null/malformed
    body_params = {}
    if endpoint_obj.body_params:
        try:
            body_params = json.loads(endpoint_obj.body_params) if isinstance(endpoint_obj.body_params, str) else endpoint_obj.body_params
        except json.JSONDecodeError:
            logger.warning(f"Failed to decode body_params JSON for {url} for BAC. Attempting parse_qs.")
            body_params = parse_qs(endpoint_obj.body_params)
        if not isinstance(body_params, dict):
            body_params = {}

    # Initial request by User 1 (headers1)
    original_request_data = {
        "url": url,
        "method": method,
        "body_params": body_params,
        "extra_headers": headers1 # Headers for User 1
    }
    print(f"{CYAN}--- Testing BAC for URL: {url} (Method: {method}) ---{NC}")
    print(f"{BLUE}[*] Sending original request with User 1 headers...{NC}")
    res_user1 = send_request(original_request_data)
    original_request_data["response"] = res_user1

    if res_user1.get("error"):
        logger.error(f"Failed to get response for original request ({url}): {res_user1['error']}. Skipping BAC test for this endpoint.")
        return

    # Request by User 2 (headers2)
    # The request content (URL, method, body) is the same as User 1's
    modified_request_data_user2 = {
        "url": url,
        "method": method,
        "body_params": body_params,
        "extra_headers": headers2 # Headers for User 2
    }
    print(f"{BLUE}[*] Sending same request with User 2 headers...{NC}")
    res_user2 = send_request(modified_request_data_user2)
    modified_request_data_user2["response"] = res_user2

    if res_user2.get("error"):
        logger.error(f"Failed to get response for User 2 request ({url}): {res_user2['error']}. Skipping BAC test for this endpoint.")
        return

    # Simplified logic for detection: Check User 2's response status first
    user2_status = res_user2.get("status")
    if user2_status in [403, 401]:
        print(f"{GREEN}   [+] Access correctly blocked for User 2 ({user2_status}) for: {url}{NC}")
        # No need to store anything if access is correctly blocked
        return
    else:
        # If status is not 403/401, then use AI to decide if it's a BAC vulnerability
        print(f"{YELLOW}   [!] User 2 received status {user2_status} for {url}. Sending to AI for detailed analysis...{NC}")
        ai_analysis_result = bac_check_with_ai(original_request_data, modified_request_data_user2)

        if ai_analysis_result and ai_analysis_result.get("vulnerable") is True:
            vuln_data = {
                "vulnerability": "Broken Access Control",
                "severity": ai_analysis_result.get("severity", "medium"),
                "url": url,
                "method": method,
                "description": ai_analysis_result.get("reason", "Broken Access Control detected."),
                "evidence": ai_analysis_result.get("evidence", "No specific evidence provided by AI."),
                "original_response_status": res_user1.get("status"),
                "user2_response_status": res_user2.get("status"),
                "vulnerable_resource_path": ai_analysis_result.get("vulnerable_resource_path", urlparse(url).path),
                "ai_analysis": ai_analysis_result # Store full AI analysis for context
            }
            try_save_vulnerability(vuln_data, session, scan_id)
            print(f"{RED}   [!!!] Broken Access Control vulnerability stored for: {url} (Severity: {vuln_data['severity']}){NC}")
        else:
            print(f"{GREEN}   [+] No Broken Access Control vulnerability detected by AI for: {url}{NC}")

def bac_scan(session, scan_id, headers1, headers2, max_workers=4):
    """
    Initiates the Broken Access Control scan.
    Fetches all endpoints, then sends requests with two different user sessions.
    Uses AI to compare responses and identify BAC.
    """
    print(f"{YELLOW}[+] Starting Broken Access Control scan...{NC}")

    if not session or scan_id is None:
        print(f"{RED}[!] Database session or scan_id not provided. Cannot perform BAC scan.{NC}")
        return []
    
    if not headers1 or not headers2:
        print(f"{RED}[!] Both headers1 (User 1) and headers2 (User 2) are required for Broken Access Control scan. Skipping.{NC}")
        return []

    # Fetch all endpoints from the database for the current scan
    # BAC can apply to any method that accesses resources.
    endpoints_to_test = session.query(Endpoint).filter_by(scan_id=scan_id).all()

    if not endpoints_to_test:
        print(f"{YELLOW}[!] No endpoints found in the database for scan_id {scan_id} to test for Broken Access Control.{NC}")
        return []

    # Filter out static files (heuristic)
    filtered_endpoints = []
    for ep in endpoints_to_test:
        if not re.search(r'\.(css|js|ico|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|map|txt|xml|pdf)$', urlparse(ep.url).path, re.IGNORECASE):
            filtered_endpoints.append(ep)
    
    if not filtered_endpoints:
        print(f"{YELLOW}[!] No suitable endpoints found for BAC testing after filtering static files.{NC}")
        return []

    # Process endpoints sequentially (no threading)
    for ep in filtered_endpoints:
        try:
            process_single_endpoint_for_bac(ep, session, scan_id, headers1, headers2)
        except Exception as e:
            logger.error(f"Error processing endpoint {ep.url}: {e}")


    print(f"{GREEN}[+] Broken Access Control scan completed. Results stored in database.{NC}")
    # Return vulnerabilities found (optional, since they are already saved to DB)
    return session.query(Vulnerability).filter_by(scan_id=scan_id, vulnerability_type="Broken Access Control").all()

# Example usage for direct testing of the module
if __name__ == "__main__":
    from tools.database import init_db, get_session, Base, ScanHistory, Endpoint # For local testing

    temp_db_engine = init_db('sqlite:///test_bac.db')
    test_session = get_session(temp_db_engine)
    
    test_domain = "test-bac-target.com"
    test_scan = test_session.query(ScanHistory).filter_by(domain=test_domain).first()
    if not test_scan:
        test_scan = ScanHistory(domain=test_domain)
        test_session.add(test_scan)
        test_session.commit()
    test_scan_id = test_scan.id

    # Dummy headers representing two different users (e.g., different session cookies)
    # In a real scenario, these would come from authenticated sessions.
    user1_headers = {"User-Agent": "BAC-Tester", "Cookie": "sessionid=user1_session_abc; auth=user1_token"}
    user2_headers = {"User-Agent": "BAC-Tester", "Cookie": "sessionid=user2_session_xyz; auth=user2_token"}
    # Or, for unauthenticated access testing (if headers2 is empty or contains no auth)
    # user2_headers = {"User-Agent": "BAC-Tester"} 

    # Add some dummy endpoints to the database for BAC testing
    dummy_endpoints_data = [
        # Scenario 1: Profile page accessible by ID
        {"url": "[http://test-bac-target.com/profile/user/123](http://test-bac-target.com/profile/user/123)", "method": "GET", "body_params": {}, "extra_headers": {}},
        # Scenario 2: Admin panel (should be restricted)
        {"url": "[http://test-bac-target.com/admin/dashboard](http://test-bac-target.com/admin/dashboard)", "method": "GET", "body_params": {}, "extra_headers": {}},
        # Scenario 3: Update privileged setting (POST request)
        {"url": "[http://test-bac-target.com/settings/update_privileged](http://test-bac-target.com/settings/update_privileged)", "method": "POST", "body_params": {"setting_id": "confidential_setting", "value": "new_value"}, "extra_headers": {"Content-Type": "application/json"}},
        # Static file, should be filtered out
        {"url": "[http://test-bac-target.com/css/style.css](http://test-bac-target.com/css/style.css)", "method": "GET", "body_params": {}, "extra_headers": {}}, 
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

    print(f"{BLUE}[+] Running Broken Access Control test with database integration...{NC}")
    # Note: `gemini` function from `ai_assistant.py` must be configured and accessible.
    bac_scan(session=test_session, scan_id=test_scan_id, headers1=user1_headers, headers2=user2_headers)
    
    print(f"{BLUE}[+] Verifying BAC results from database...{NC}")
    retrieved_vulns = test_session.query(Vulnerability).filter_by(scan_id=test_scan_id, vulnerability_type="Broken Access Control").all()
    for vuln in retrieved_vulns:
        print(f"   BAC Found: {vuln.url} (Severity: {vuln.severity})")
        print(f"     Full Data: {vuln.vulnerability_data}")

    test_session.close()
    
    if os.path.exists('test_bac.db'):
        os.remove('test_bac.db')
    print(f"{GREEN}[+] Broken Access Control test completed.{NC}")
