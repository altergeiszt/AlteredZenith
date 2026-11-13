import json
from client import LocalSOCClient
from analyzer import ThreatAnalyzer

def run_local_pipeline():
    print("========================================")
    print(" LAUNCHING LOCAL SOAR / THREAT PIPELINE ")
    print("========================================")
    
    soc_client = LocalSOCClient()
    analyzer = ThreatAnalyzer()

    # 1. Gather recent indicators from local MISP
    print("[*] Querying local MISP container for active threat feeds...")
    events = soc_client.fetch_latest_misp_events(limit=3)

    if not events:
        print("[!] No active events returned from MISP. Using sample fallback event.")
        events = [{
            "Event": {
                "id": "999",
                "info": "Sample APT29 Phishing Campaign Staging",
                "date": "2026-06-06",
                "Attribute": [{"type": "ip-dst", "value": "198.51.100.45"}]
            }
        }]

    # 2. Format event data for local AI analysis
    event_summary = json.dumps(events, indent=2)

    # 3. Run Local AI Triage
    report = analyzer.analyze_indicator_batch(event_summary)

    # 4. Output Results Locally
    print("\n" + "="*45)
    print(" LOCAL AI THREAT TRIAGE REPORT ")
    print("="*45 + "\n")
    print(report)

if __name__ == "__main__":
    run_local_pipeline()