import os
import requests
import json
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Custom exception for Gemini API rate limits
class GeminiRateLimitExceeded(Exception):
    """Custom exception raised when Gemini API rate limit is exceeded."""
    pass

def gemini(prompt, max_retries=3, retry_delay=5):
    """
    Calls the Gemini API to generate content.
    Retries on HTTP 429 (rate limit) up to max_retries times.
    """
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        logger.error("GEMINI_API_KEY not found. Please set the environment variable.")
        return json.dumps({"error": "GEMINI_API_KEY not configured."})

    chat_history = [{ "role": "user", "parts": [{ "text": prompt }] }]
    payload = { "contents": chat_history }

    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"

    attempt = 0
    while attempt < max_retries:
        try:
            response = requests.post(api_url, headers={'Content-Type': 'application/json'}, json=payload)
            
            if response.status_code == 429:
                logger.warning(f"Attempt {attempt + 1}: Received HTTP 429 Too Many Requests. Retrying after {retry_delay} second(s)...")
                time.sleep(retry_delay)
                attempt += 1
                continue  # Retry

            result = response.json()

            # Check for RESOURCE_EXHAUSTED inside the JSON
            if result and "error" in result and "message" in result["error"] and "RESOURCE_EXHAUSTED" in result["error"]["message"]:
                logger.warning(f"Attempt {attempt + 1}: RESOURCE_EXHAUSTED detected. Retrying after {retry_delay} second(s)...")
                time.sleep(retry_delay)
                attempt += 1
                continue  # Retry

            response.raise_for_status()  # Raise error for other non-2xx responses

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

    # If retries exhausted
    logger.error(f"Gemini API rate limit exceeded after {max_retries} attempts.")
    return json.dumps({"error": f"Gemini API rate limit exceeded after {max_retries} attempts."})

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