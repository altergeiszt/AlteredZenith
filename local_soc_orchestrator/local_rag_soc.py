import os
import chromadb
from chromadb.utils import embedding_functions
import ollama

# ==========================================
# CONFIGURATION
# ==========================================
CHROMA_DIR = "./local_chroma_db"
OLLAMA_MODEL = "qwen2.5:32b"  # Fits in 16GB VRAM

class LocalThreatRAG:
    def __init__(self):
        print("[*] Initializing local ChromaDB vector store...")
        self.client = chromadb.PersistentClient(path=CHROMA_DIR)
        
        # Default embedding function runs locally via ONNX/CPU without external calls
        self.embedding_fn = embedding_functions.DefaultEmbeddingFunction()
        
        self.collection = self.client.get_or_create_collection(
            name="security_playbooks",
            embedding_function=self.embedding_fn
        )

    def seed_playbooks(self):
        """Seeds sample threat hunting playbooks and incident response templates into ChromaDB."""
        playbooks = [
            {
                "id": "playbook_powershell_bypasses",
                "text": "Incident Response for PowerShell Process Injection & Encoded Commands: 1. Isolate the host network interface immediately. 2. Collect memory dump using Volatility. 3. Check event log Windows PowerShell 4104 for script block logging. 4. Revoke active user kerberos tickets.",
                "metadata": {"category": "Execution", "mitre_id": "T1059.001", "severity": "High"}
            },
            {
                "id": "playbook_lateral_movement",
                "text": "Incident Response for Lateral Movement via PsExec/SMB: 1. Identify source and destination IP addresses. 2. Terminate anomalous administrative shares (ADMIN$, IPC$). 3. Block SMB ports (445) at the host firewall level. 4. Rotate service account credentials involved in authentication.",
                "metadata": {"category": "Lateral Movement", "mitre_id": "T1021.002", "severity": "Critical"}
            },
            {
                "id": "playbook_credential_dumping",
                "text": "Incident Response for LSASS Credential Dumping: 1. Isolate process access violations targeting lsass.exe. 2. Force a global password reset for affected users. 3. Review registry for unauthorized debugging or credential provider modifications.",
                "metadata": {"category": "Credential Access", "mitre_id": "T1003.001", "severity": "Critical"}
            }
        ]

        # Add documents if collection is empty
        if self.collection.count() == 0:
            print("[+] Seeding local security playbooks into ChromaDB...")
            for pb in playbooks:
                self.collection.add(
                    ids=[pb["id"]],
                    documents=[pb["text"]],
                    metadatas=[pb["metadata"]]
                )
        else:
            print("[+] Playbooks already loaded in ChromaDB.")

    def query_relevant_playbooks(self, anomaly_description: str, n_results=1):
        """Retrieves the most contextually relevant security playbooks."""
        results = self.collection.query(
            query_texts=[anomaly_description],
            n_results=n_results
        )
        return results

    def generate_rag_triage(self, incoming_alert: str):
        """Performs RAG: Retrieves context and passes it along with the alert to Ollama."""
        print(f"\n[*] Incoming Security Alert: {incoming_alert}")
        
        # 1. Retrieve matching historical playbooks from ChromaDB
        search_results = self.query_relevant_playbooks(incoming_alert, n_results=1)
        retrieved_playbook = ""
        metadata = {}
        
        if search_results and search_results["documents"]:
            retrieved_playbook = search_results["documents"][0][0]
            metadata = search_results["metadatas"][0][0]
            print(f"[+] Retrieved relevant playbook [{metadata.get('mitre_id')}] from local vector database.")

        # 2. Construct Augmented Prompt for Ollama
        prompt = f"""
        You are an elite autonomous local Threat Hunting and Security Operations Center (SOC) agent.
        
        INCOMING TELEMETRY ALERT:
        {incoming_alert}

        ORGANIZATIONAL INCIDENT RESPONSE PLAYBOOK (RETRIEVED FROM KNOWLEDGE BASE):
        {retrieved_playbook}

        Using the retrieved playbook guidance above, provide a structured triage and mitigation response containing:
        1. Threat Assessment & Severity Rating.
        2. Step-by-step Containment Action Plan (adapting the retrieved playbook steps directly to this alert).
        3. Recommended KQL or Sigma detection query syntax to hunt for secondary persistence.

        Keep the response clear, technical, and formatted cleanly in Markdown.
        """

        # 3. Query Local Ollama Instance (Running on RTX 4080 SUPER)
        print(f"[*] Querying local Ollama model ({OLLAMA_MODEL})...")
        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return response['message']['content']

if __name__ == "__main__":
    # Initialize RAG Pipeline
    rag = LocalThreatRAG()
    rag.seed_playbooks()

    # Simulate an incoming raw telemetry alert from your SIEM or EDR
    simulated_alert = "Detected suspicious PowerShell execution with base64 encoded flags spawning out of a service account process tree on host WS-FINANCE-04."

    # Run RAG Triage
    report = rag.generate_rag_triage(simulated_alert)

    print("\n" + "="*50)
    print(" LOCAL RAG AI THREAT TRIAGE & PLAYBOOK REPORT ")
    print("="*50 + "\n")
    print(report)