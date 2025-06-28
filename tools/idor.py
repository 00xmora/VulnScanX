import json
import requests
import os
from urllib.parse import urlparse, urljoin, urlencode
from concurrent.futures import ThreadPoolExecutor
import logging
from sqlalchemy.exc import IntegrityError
from tools.database import Vulnerability, Endpoint # Import Vulnerability and Endpoint models
from tools.ai_assistant import gemini # Assuming ai_assistant is available and works as intended
import re

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

def clean_gemini_response(raw_text):
    """
    Removes markdown JSON code block wrappers like ```json ... ```
    to ensure the string is valid JSON for parsing.
    """
    if raw_text.startswith("```json"):
        raw_text = raw_text[len("```json"):].strip()
    if raw_text.endswith("```"):
        raw_text = raw_text[:-3].strip()
    return raw_text

def send_modified_request(req_data):
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
            "response_body": res.text
        }

    except Exception as e:
        logger.error(f"Error sending modified request to {url}: {str(e)}")
        return {"error": str(e)}

def process_single_request(base_request_data, session, scan_id):
    """
    Process a single base request: generate modified requests, send them, and analyze results.
    Store vulnerabilities directly to the database.
    """
    try:
        # Generate prompt for Gemini to create modified requests
        prompt = f"""
        You're an expert penetration tester testing for Insecure Direct Object Reference (IDOR).

        Here is an HTTP request:

        {json.dumps(base_request_data, indent=2)}

        Suggest 2 modified versions for the request to test for IDOR vulnerabilities.
        For each modified version, specifically target common IDOR patterns by changing numerical or identifiable object IDs in the URL path, query parameters, or JSON/form body. For example, if the original URL is /api/v1/users/123, suggest /api/v1/users/124. If a parameter is 'userId=123', suggest 'userId=124'. If the request body is '{{ "item_id": 456 }}', suggest '{{ "item_id": 457 }}'.

        Return ONLY a JSON array of modified request objects without Markdown formatting.
        Do not include ```json or ``` markers.
        Each object must include:
        - url
        - method
        - body_params (if applicable, can be an empty dict)
        - extra_headers (can be an empty dict)
        - description (a brief explanation of the test)
        """

        # Send prompt to Gemini
        gemini_output = gemini(prompt)
        gemini_output = clean_gemini_response(gemini_output)

        # Parse Gemini's response
        try:
            test_requests = json.loads(gemini_output)
            if not isinstance(test_requests, list):
                raise ValueError("Gemini didn't return a list of requests")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gemini response for request {base_request_data.get('url', 'N/A')}: {str(e)}")
            logger.error(f"Raw response was: {gemini_output}")
            return []

        # Send modified requests and collect responses
        responses = []
        for i, req in enumerate(test_requests, 1):
            if 'url' in req:
                # Ensure modified URL is absolute by joining with original base URL if relative
                parsed_req_url = urlparse(req['url'])
                if not parsed_req_url.netloc: # If netloc is empty, it's likely a relative URL
                    original_base_url_parsed = urlparse(base_request_data["url"])
                    req['url'] = urljoin(f"{original_base_url_parsed.scheme}://{original_base_url_parsed.netloc}", req['url'])

            res = send_modified_request(req)
            responses.append({
                "test_case_description": req.get("description", f"Test {i}"),
                "request": req,
                "response": res
            })

        # Analyze results with Gemini
        analysis_prompt = f"""
Analyze these IDOR test results:

{json.dumps(responses, indent=2)}

For each response, determine if it indicates an Insecure Direct Object Reference (IDOR).
An IDOR is indicated if:
1. The request successfully accessed a resource that should not be accessible to the current user (e.g., accessing another user's data).
2. The response status code is not 401, 403, or a similar access denied code.
3. The response content shows data belonging to a different user/entity than the one implied by the original request.

For each response, return a JSON object with:
- vulnerable: true or false
- url: the request URL
- method: the HTTP method
- body_params: the request body parameters (if any)
- extra_headers: the request headers
- severity: "high" (if confirmed IDOR with sensitive data like personal info), "medium" (if less sensitive data), "low" (if minimal impact), or "none" (if not vulnerable). Default to "medium" if unsure but potentially vulnerable.
- vulnerable_parameter: the parameter modified to test IDOR (e.g., "studentId", "Authorization", or URL path segment like "users/123")
- payload: the modified value used (e.g., "20200759", "another_user_id")
- evidence: a brief explanation of why the response is marked vulnerable or not (e.g., "Response contains email of user 20200759", "Same user data returned", "403 Forbidden - access denied as expected")

Return a JSON array of these objects.
"""

        final_analysis = gemini(analysis_prompt)
        final_analysis = clean_gemini_response(final_analysis)
    
        # Parse analysis and store vulnerabilities in the database
        try:
            vulnerable_results = json.loads(final_analysis)
            
            for v in vulnerable_results:
                if v.get("vulnerable") is True:
                    url = v.get("url")
                    method = v.get("method")
                    body_params = v.get("body_params")
                    headers = v.get("extra_headers")
                    severity = v.get("severity", "medium")
                    vulnerable_parameter = v.get("vulnerable_parameter", "unknown")
                    payload = v.get("payload", "unknown")
                    evidence = v.get("evidence", "No specific evidence provided by AI.")

                    vuln_data = {
                        "vulnerability": "IDOR",
                        "severity": severity,
                        "url": url,
                        "method": method,
                        "vulnerable_parameter": vulnerable_parameter,
                        "payload": payload,
                        "evidence": evidence
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
                        print(f"{GREEN}   [+] IDOR vulnerability stored for: {url} (Parameter: {vulnerable_parameter}, Payload: {payload}){NC}")
                    except IntegrityError:
                        session.rollback()
                        logger.info(f"Duplicate IDOR vulnerability found and skipped for URL: {url}")
                    except Exception as db_e:
                        session.rollback()
                        logger.error(f"Error saving IDOR vulnerability to DB: {db_e}")
                else:
                    logger.info(f"   [-] Not vulnerable to IDOR: {v.get('url')} - {v.get('evidence', 'No vulnerability detected.')}")

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse final Gemini analysis for request {base_request_data.get('url', 'N/A')}: {str(e)}")
            logger.error(f"Raw analysis response was: {final_analysis}")
            return []

    except Exception as e:
        logger.error(f"Error during processing of request {base_request_data.get('url', 'N/A')}: {str(e)}")
        return []

def idor(url_directory, session, scan_id, max_workers=4):
    """
    Process requests from the Endpoint database table concurrently for IDOR testing.
    """
    print(f"{YELLOW}[+] Starting IDOR scan...{NC}")

    if not session or scan_id is None:
        print(f"{RED}[!] Database session or scan_id not provided. Cannot perform IDOR scan.{NC}")
        return []

    # Fetch base requests (endpoints) from the database for the current scan
    base_requests_from_db = session.query(Endpoint).filter_by(scan_id=scan_id).all()

    if not base_requests_from_db:
        print(f"{RED}[!] No endpoints found in the database for scan_id {scan_id} to test for IDOR.{NC}")
        return []

    # Convert Endpoint objects to dictionary format expected by process_single_request
    # Also filter out endpoints that are not typically suitable for IDOR testing (e.g., static files)
    requests_to_process = []
    for ep in base_requests_from_db:
        # Simple heuristic to exclude static files - can be improved
        if not re.search(r'\.(css|js|ico|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|map|txt|xml|pdf)$', urlparse(ep.url).path, re.IGNORECASE):
            requests_to_process.append({
                "url": ep.url,
                "method": ep.method,
                "body_params": ep.body_params if ep.body_params else {},
                "extra_headers": ep.extra_headers if ep.extra_headers else {}
            })
    
    if not requests_to_process:
        print(f"{YELLOW}[!] No suitable endpoints found for IDOR testing after filtering static files.{NC}")
        return []

    # Process requests concurrently
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit each request for processing, passing the session and scan_id
        futures = [executor.submit(process_single_request, req_data, session, scan_id) for req_data in requests_to_process]

        # Wait for all futures to complete (results are already stored in DB by process_single_request)
        for future in futures:
            future.result() # Calling result() will re-raise any exceptions that occurred in the thread

    print(f"{GREEN}[+] IDOR scan completed. Results stored in database.{NC}")
    # Return vulnerabilities found (optional, since they are already saved to DB)
    return session.query(Vulnerability).filter_by(scan_id=scan_id, vulnerability_type="IDOR").all()

# Example usage for direct testing of the module
if __name__ == "__main__":
    # This is for testing purposes only. In production, this is called from VulnScanX.py.
    # You would need to set up a dummy session and scan_id for testing.
    from tools.database import init_db, get_session, Base, ScanHistory, Endpoint # For local testing
    
    # Initialize a temporary database for testing
    temp_db_engine = init_db('sqlite:///test_idor.db')
    test_session = get_session(temp_db_engine)
    
    # Create a dummy ScanHistory record for testing
    test_domain = "test-idor-target.com"
    test_scan = test_session.query(ScanHistory).filter_by(domain=test_domain).first()
    if not test_scan:
        test_scan = ScanHistory(domain=test_domain)
        test_session.add(test_scan)
        test_session.commit()
    test_scan_id = test_scan.id

    dummy_output_dir = "test_idor_output"
    os.makedirs(dummy_output_dir, exist_ok=True)

    # Add some dummy endpoints to the database for IDOR testing
    # These would normally come from autorecon.py
    dummy_endpoints_data = [
        {"url": "[http://test-idor-target.com/api/v1/users/123](http://test-idor-target.com/api/v1/users/123)", "method": "GET", "body_params": {}, "extra_headers": {"Authorization": "Bearer token123"}},
        {"url": "[http://test-idor-target.com/api/v1/orders?orderId=ABC001](http://test-idor-target.com/api/v1/orders?orderId=ABC001)", "method": "GET", "body_params": {}, "extra_headers": {}},
        {"url": "[http://test-idor-target.com/profile/edit](http://test-idor-target.com/profile/edit)", "method": "POST", "body_params": {"userId": 12345}, "extra_headers": {"Content-Type": "application/json"}},
        {"url": "[http://test-idor-target.com/static/image.png](http://test-idor-target.com/static/image.png)", "method": "GET", "body_params": {}, "extra_headers": {}} # Should be filtered out
    ]

    for ep_data in dummy_endpoints_data:
        try:
            new_endpoint = Endpoint(
                scan_id=test_scan_id,
                url=ep_data["url"],
                method=ep_data["method"],
                body_params=ep_data["body_params"],
                extra_headers=ep_data["extra_headers"]
            )
            test_session.add(new_endpoint)
            test_session.commit()
        except IntegrityError:
            test_session.rollback()
            logger.info(f"Duplicate endpoint added for testing: {ep_data['url']}")
        except Exception as db_e:
            test_session.rollback()
            logger.error(f"Error adding dummy endpoint to DB: {db_e}")

    print(f"{BLUE}[+] Running IDOR test with database integration...{NC}")
    # Note: ai_assistant.gemini needs to be properly configured and accessible for this to work
    # in a real environment. This example will likely fail if gemini() is not defined or configured.
    idor(dummy_output_dir, session=test_session, scan_id=test_scan_id)
    
    print(f"{BLUE}[+] Verifying IDOR results from database...{NC}")
    retrieved_vulns = test_session.query(Vulnerability).filter_by(scan_id=test_scan_id, vulnerability_type="IDOR").all()
    for vuln in retrieved_vulns:
        print(f"   IDOR Found: {vuln.url} (Severity: {vuln.severity})")
        print(f"     Full Data: {vuln.vulnerability_data}")

    test_session.close()
    
    # Clean up test files and directory
    if os.path.exists('test_idor.db'):
        os.remove('test_idor.db')
    
    try:
        # Check if directory is empty before removing it
        if os.path.exists(dummy_output_dir) and not os.listdir(dummy_output_dir):
            os.rmdir(dummy_output_dir)
        else:
            print(f"{YELLOW}[!] Directory {dummy_output_dir} not empty, skipping rmdir. (Tools might leave temp files){NC}")
    except OSError as e:
        print(f"{RED}Error removing directory {dummy_output_dir}: {e}{NC}")

    print(f"{GREEN}[+] IDOR test completed.{NC}")