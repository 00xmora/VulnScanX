import os
import requests
import time

def gemini(prompt):
    """Sends a request to the Gemini API to generate content based on the provided prompt."""
    api_key =  os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "Error: GEMINI_API_KEY environment variable not set."

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    data = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }

    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        result = response.json()
        ai_text = result["candidates"][0]["content"]["parts"][0]["text"]
        return ai_text
    else:
        return f"Error {response.status_code}: {response.text}"
    

