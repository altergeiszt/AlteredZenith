from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from local_rag_soc import LocalThreatRAG

# ==========================================
# FASTAPI & RAG INITIALIZATION
# ==========================================
app = FastAPI(
    title="Local AI Threat Intel & RAG SOC API",
    description="Local-first AI security triage pipeline powered by ChromaDB, Ollama, and FastAPI.",
    version="1.0.0"
)

# Initialize and seed the RAG pipeline on startup
print("[*] Initializing local RAG pipeline for API server...")
rag_engine = LocalThreatRAG()
rag_engine.seed_playbooks()

# ==========================================
# PYDANTIC SCHEMAS (Request/Response Models)
# ==========================================
class TelemetryAlertRequest(BaseModel):
    alert_text: str = Field(..., example="Detected suspicious PowerShell execution with base64 encoded flags.")
    source_host: str = Field(default="UNKNOWN-HOST", example="WS-FINANCE-04")
    severity_hint: str = Field(default="Medium", example="High")

class TriageResponse(BaseModel):
    status: str
    source_host: str
    ai_triage_report: str

# ==========================================
# API ENDPOINTS
# ==========================================
@app.get("/")
def health_check():
    """Health check endpoint to verify local SOC API status."""
    return {
        "status": "online",
        "engine": "Ollama + ChromaDB",
        "model": "qwen2.5:32b"
    }

@app.post("/triage", response_model=TriageResponse)
def triage_security_event(payload: TelemetryAlertRequest):
    """
    Accepts an incoming security log/alert, runs local RAG retrieval, 
    and returns a structured LLM threat triage assessment.
    """
    try:
        # Construct enriched context string for the RAG engine
        formatted_query = f"Host: {payload.source_host} | Severity Hint: {payload.severity_hint} | Details: {payload.alert_text}"
        
        # Execute local RAG triage loop
        report = rag_engine.generate_rag_triage(formatted_query)
        
        return TriageResponse(
            status="success",
            source_host=payload.source_host,
            ai_triage_report=report
        )
    except Exception as e:
        raise HTTPException(status_code=500, error=str(e), detail=f"Local RAG inference failed: {str(e)}")