import os
import requests
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Custom exception for Gemini API rate limits
class GeminiRateLimitExceeded(Exception):
    """Custom exception raised when Gemini API rate limit is exceeded."""
    pass

def gemini(prompt):
    """
    Calls the Gemini API to generate content.
    Raises GeminiRateLimitExceeded if a rate limit error is detected.
    """
    api_key = os.getenv("GEMINI_API_KEY", "") # Ensure API key is loaded from environment or config
    if not api_key:
        logger.error("GEMINI_API_KEY not found. Please set the environment variable.")
        # Return a structured error that can be checked by calling functions
        return json.dumps({"error": "GEMINI_API_KEY not configured."})

    chat_history = [{ "role": "user", "parts": [{ "text": prompt }] }]
    payload = { "contents": chat_history }

    # Using the direct API URL for gemini-2.0-flash
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"

    try:
        response = requests.post(api_url, headers={'Content-Type': 'application/json'}, json=payload)
        
        # Check for HTTP 429 status code
        if response.status_code == 429:
            error_message = f"HTTP 429 Too Many Requests: {response.text}"
            logger.error(f"Gemini API rate limit exceeded: {error_message}")
            raise GeminiRateLimitExceeded(error_message)

        result = response.json()

        # Also check for "RESOURCE_EXHAUSTED" in the response body, which indicates quota issues
        if result and "error" in result and "message" in result["error"] and "RESOURCE_EXHAUSTED" in result["error"]["message"]:
            error_message = result["error"]["message"]
            logger.error(f"Gemini API rate limit exceeded (RESOURCE_EXHAUSTED): {error_message}")
            raise GeminiRateLimitExceeded(error_message)

        response.raise_for_status() # Raise an exception for other HTTP errors (4xx or 5xx)

        if result.get("candidates") and result["candidates"][0].get("content") and result["candidates"][0]["content"].get("parts"):
            return result["candidates"][0]["content"]["parts"][0]["text"]
        else:
            logger.warning(f"Unexpected Gemini API response structure: {result}")
            return json.dumps({"error": "Unexpected Gemini API response structure."})

    except requests.exceptions.RequestException as e:
        logger.error(f"Request to Gemini API failed: {e}")
        return json.dumps({"error": f"Gemini API request failed: {e}"})
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON response from Gemini API: {e}")
        return json.dumps({"error": f"Invalid JSON response from Gemini API: {e}"})
    except Exception as e:
        logger.error(f"An unexpected error occurred during Gemini API call: {e}")
        return json.dumps({"error": f"An unexpected error occurred: {e}"})

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