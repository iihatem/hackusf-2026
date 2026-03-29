# MalwareScope

Autonomous critical infrastructure threat detection and response system built for HackUSF 2026.

Targets two hackathon challenges simultaneously:
- **NextEra Energy** — Malware Analysis Challenge
- **Google Cloud** — Building a Self-Healing World with ADK

---

## What It Does

Drop any suspected malware file into the UI. MalwareScope runs a fully autonomous multi-agent pipeline that:

1. **Static analysis** — hashes, entropy, YARA rules, PE parsing, IOC extraction
2. **Behavioral simulation** — projects realistic execution scenario grounded in the static artifacts
3. **Parallel forensic analysis** — four specialized agents run simultaneously:
   - Network forensics (C2 detection, DGA, exfiltration)
   - Filesystem analysis (droppers, persistence, credential theft)
   - Registry/system analysis (privilege escalation, rootkits, backdoors)
   - Threat intelligence correlation (malware family, APT attribution)
4. **Critic review** — red-team agent challenges every finding, adjusts confidence, flags false positive risks
5. **Threat report** — executive summary for CISOs with MITRE ATT&CK mapping, IOCs, and remediation steps
6. **Autonomous response** (for confirmed high/critical threats):
   - BlocklistAgent pushes all network IOCs to the perimeter firewall
   - AlertAgent dispatches a structured SOC alert with SLA and escalation path
   - TicketAgent creates an incident ticket with remediation checklist
   - VerificationAgent loop confirms all actions completed (exits early on success, escalates to human after 3 failed iterations)

Everything runs autonomously after you click upload. No human intervention required.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Monitoring (monitoring_service/)                   │
│  NetworkFeedMonitor + EndpointFeedMonitor + ThreatIntelMonitor │
│  → TriageAgent → A2A escalation to port 8001                 │
└─────────────────────────────────────────────────────────────┘
                          ↓ escalate
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: Analysis Pipeline (analysis_service/ + api/)       │
│  StaticAnalysisAgent → ScenarioBuilderAgent                  │
│    → ParallelAgent[Network, Filesystem, Registry, Intel]     │
│    → CriticAgent → ReportWriterAgent                         │
└─────────────────────────────────────────────────────────────┘
                          ↓ confirmed threat
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Autonomous Response (response_service/)            │
│  ParallelAgent[BlocklistAgent, AlertAgent, TicketAgent]      │
│    → LoopAgent[VerificationAgent, max_iterations=3]          │
└─────────────────────────────────────────────────────────────┘
```

**Tech stack:** Python 3.11, FastAPI, Google ADK, LiteLLM → Claude Opus, React 18, Tailwind CSS

---

## Quick Start

**Prerequisites:** Python 3.11+, Node.js 18+, an Anthropic API key.

```bash
# 1. Clone and install
git clone <repo>
cd hackusf-2026
pip install -r requirements.txt
cd frontend && npm install && cd ..

# 2. Configure
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY

# 3. Start everything
./start.sh
```

Open **http://localhost:3000**, drop a malware sample into the upload zone, and watch the pipeline run.

---

## Manual Start (if start.sh doesn't work)

```bash
# Terminal 1 — FastAPI backend (main entry point)
uvicorn api.main:app --host 0.0.0.0 --port 9000

# Terminal 2 — Analysis A2A service (for monitoring escalation)
uvicorn analysis_service.agent:a2a_app --host 0.0.0.0 --port 8001

# Terminal 3 — Response A2A service
uvicorn response_service.agent:a2a_app --host 0.0.0.0 --port 8002

# Terminal 4 — React frontend
cd frontend && npm start
```

API docs: **http://localhost:9000/docs**

---

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/analyze` | POST | Upload a file, returns `{"job_id": "uuid"}` |
| `/status/{job_id}` | GET | Full job state including per-agent progress, polled every 2s |
| `/export/{job_id}` | GET | Download final report as JSON |
| `/health` | GET | Health check |

---

## Environment Variables

```env
ANTHROPIC_API_KEY=sk-ant-...        # Required
VIRUSTOTAL_API_KEY=...              # Optional — falls back to simulated data
ABUSEIPDB_API_KEY=...               # Optional — falls back to simulated data
DOCKER_SOCKET=/var/run/docker.sock  # Optional — for sandbox execution
```

---

## Project Structure

```
hackusf-2026/
├── api/
│   └── main.py              # FastAPI backend — job orchestration
├── analysis_service/
│   ├── agent.py             # ADK 8-agent analysis pipeline
│   └── static_analyzer.py  # YARA, PE, entropy, IOC extraction
├── response_service/
│   └── agent.py             # ADK response pipeline with LoopAgent
├── monitoring_service/
│   └── agent.py             # ADK monitoring agents + triage
├── simulation/
│   ├── network_stream.py    # Simulated network event generator
│   └── endpoint_stream.py  # Simulated endpoint event generator
├── frontend/
│   └── src/
│       ├── App.jsx          # Main layout, tab navigation
│       ├── api/client.js    # API calls
│       ├── hooks/useAnalysis.js  # Polling hook
│       └── components/      # PipelineFlow, AgentStatus, ReportPanel,
│                            # ResponsePanel, Timeline, IOCTable
├── yara_rules/
│   └── malware_generic.yar  # YARA detection rules
├── tests/                   # pytest test suite
├── .env.example
├── requirements.txt
└── start.sh                 # One-command startup script
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Demo Flow

1. Start services with `./start.sh`
2. Open http://localhost:3000
3. Drop `6108674530.JS.malicious` (included in repo) into the upload zone
4. Watch the pipeline flow diagram update in real time as each agent runs
5. Check the **Agents** tab for per-agent findings
6. Check the **Timeline** tab for the event log
7. Check the **IOCs** tab for extracted indicators
8. Check the **Response** tab — for high/critical threats, all response actions execute automatically
9. Click **Export JSON** in the header to download the full report
