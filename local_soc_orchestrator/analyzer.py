from client import LocalSOCClient

class ThreatAnalyzer:
    def __init__(self):
        self.client = LocalSOCClient()

    def analyze_indicator_batch(self, raw_events):
        if not raw_events:
            return "No raw telemetry or MISP events provided for analysis."

        prompt = f"""
        You are an elite autonomous local Threat Hunting and Security Operations Center (SOC) agent.
        Review the following raw threat indicators extracted from our MISP database:

        {raw_events}

        Provide a structured threat evaluation containing:
        1. Executive Threat Summary (2 sentences).
        2. Threat Severity Ranking (Low, Medium, High, Critical).
        3. Associated MITRE ATT&CK Tactics & Techniques.
        4. Recommended Local Containment Steps (e.g., firewall block rules, host quarantine).

        Keep the response clear, technical, and formatted cleanly in Markdown.
        """

        print("[*] Dispatching prompt to local Ollama (Qwen 2.5 32B via RTX 4080)...")
        analysis_result = self.client.query_local_llm(prompt)
        return analysis_result