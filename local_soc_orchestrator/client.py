import os
import requests
import ollama

MISP_URL = os.getenv("MISP_URL", "http://localhost")
MISP_KEY = os.getenv("MISP_KEY", "your_misp_auth_key")
OLLAMA_MODEL = "qwen2.5:32b"  # Fits comfortably in 16GB VRAM at 4-bit quantization

class LocalSOCClient:
    def __init__(self):
        self.misp_headers = {
            "Authorization": MISP_KEY,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def fetch_latest_misp_events(self, limit=5):
        """Fetches recent security events/indicators from local MISP."""
        try:
            url = f"{MISP_URL}/events/restSearch"
            payload = {"limit": limit, "published": 1}
            response = requests.post(url, json=payload, headers=self.misp_headers, verify=False)
            if response.status_code == 200:
                return response.json().get("response", [])
            print(f"[!] MISP fetch failed with status: {response.status_code}")
            return []
        except Exception as e:
            print(f"[!] Connection to MISP failed: {e}")
            return []

    def query_local_llm(self, prompt: str) -> str:
        """Queries the local Ollama instance running on the RTX 4080 SUPER."""
        try:
            response = ollama.chat(
                model=OLLAMA_MODEL,
                messages=[{"role": "user", "content": prompt}]
            )
            return response['message']['content']
        except Exception as e:
            return f"[!] Local LLM inference failed: {e}"