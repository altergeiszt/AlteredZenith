# Local-First AI Threat Intelligence, Hunting & Response Engine

A high-performance, privacy-first Security Operations Center (SOC) assistant and automated threat intelligence pipeline running entirely on local hardware. Powered by **Ollama (Qwen 2.5 32B)** accelerated via an RTX 4080 SUPER, **ChromaDB** for local RAG-based playbook retrieval, **FastAPI**, and a modular **Docker** stack for threat feed ingestion and log telemetry.

---

## Architecture Overview

```
 [ Local Telemetry / SIEM / MISP ] ──┐
                                   ▼
                             ┌───────────┐
                             │ ChromaDB  │ (Semantic Search for IR Playbooks)
                             └─────┬─────┘
                                   │
                                   ▼ (Context + Query)
                             ┌───────────┐
                             │  Ollama   │ (Qwen 2.5 32B via RTX 4080 SUPER)
                             └─────┬─────┘
                                   │
                                   ▼
                         [ Grounded Threat Triage & 
                           Playbook Response Report ]
```

---

## System Requirements & Hardware Specs

Designed to maximize local workstation performance without leaking sensitive security telemetry externally:
* **GPU:** NVIDIA RTX 4080 SUPER (16 GB VRAM) — locks `qwen2.5:32b` (4-bit quantized) directly into VRAM for lightning-fast token generation.
* **RAM:** 64 GB system memory.
* **Storage:** Fast NVMe storage for local vector embeddings and Docker volumes.

---

## Project Directory Structure

```text
local_soc_orchestrator/
├── docker-compose.yml       # Local stack (Ollama, MISP, Wazuh)
├── client.py                # MISP and Ollama API connector
├── analyzer.py              # Standalone threat indicator analyzer
├── main.py                  # Standalone MISP + Ollama pipeline entrypoint
├── local_rag_soc.py         # ChromaDB + Ollama RAG engine
├── api_server.py            # FastAPI REST wrapper service
├── README.md                # Project documentation
└── requirements.txt         # Python dependencies
```

---

## Quick Start Guide

### Step 1: Spin Up the Local Infrastructure
Start Ollama, MISP, and Wazuh using Docker Compose:
```bash
docker compose up -d
```

Pull the required model into Ollama (ensuring full GPU offloading):
```bash
docker exec -it local_ollama ollama run qwen2.5:32b
```

### Step 2: Set Up Your Python Environment
Create a virtual environment and install the required dependencies:
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Running the FastAPI RAG Server

Start the local API wrapper to expose your SOC pipeline over HTTP:
```bash
uvicorn api_server:app --host 127.0.0.1 --port 8000 --reload
```

Once running:
* **Interactive API Docs:** Navigate to `http://127.0.0.1:8000/docs` to test payloads directly via Swagger UI.
* **Health Check:** `curl http://127.0.0.1:8000/`

### Example API Request (Threat Triage)

You can send raw security telemetry or log alerts to the local `/triage` endpoint:

```bash
curl -X 'POST' \
  'http://127.0.0.1:8000/triage' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "alert_text": "Anomalous lateral movement detected via SMB administrative shares connecting multiple workstation nodes.",
  "source_host": "DC-PROD-01",
  "severity_hint": "Critical"
}'
```
