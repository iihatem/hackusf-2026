# MalwareScope — Claude Code Context

## What This Project Is

MalwareScope is an autonomous critical infrastructure threat detection
and response system built for a hackathon. It has three layers:

1. **Continuous Monitoring** — agents watching simulated network,
   endpoint, and threat intel streams for anomalies
2. **Deep Analysis Pipeline** — multi-agent malware analysis triggered
   when the triage agent escalates an anomaly
3. **Autonomous Response** — parallel agents that act on confirmed
   threats (blocklist, alert, ticket) followed by a verification loop

The project targets two hackathon challenges simultaneously:

- NextEra Energy: Malware Analysis Challenge (primary)
- Google Cloud: Building a Self-Healing World with ADK (secondary)

For the demo, all external integrations (firewall, Slack, Jira) are
simulated in-memory. The AI analysis is real.

---

## Tech Stack

**Backend:** Python 3.11, FastAPI, Anthropic SDK
**Frontend:** React 18, Tailwind CSS, plain fetch (no axios)
**Sandbox:** Docker SDK for Python, REMnux base image
**AI:** Anthropic API (claude-opus-4-5 for all agents)
**Simulation:** Custom Python stream generators (no external deps)

---

## Architecture — Read This Before Touching Any Agent File

### The Agent Model

Every agent follows this exact pattern:

````python
class XxxAgent:
    def __init__(self):
        self.client = anthropic.Anthropic()

    def run(self, payload: dict) -> dict:
        response = self.client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1500,
            system="...",  # specialized system prompt
            messages=[{
                "role": "user",
                "content": f"Analyze and respond in JSON only:\n{json.dumps(payload)}"
            }]
        )
        raw = response.content[0].text.strip()
        raw = raw.removeprefix("```json").removesuffix("```").strip()
        return json.loads(raw)
````

Never deviate from this pattern without a strong reason. Consistency
across agents makes the codebase navigable.

### The Three-Layer Flow

```
Monitoring Agents (loop)
  → anomaly detected
  → TriageAgent.evaluate()
  → decision: escalate
  → MalwareAnalysisPipeline.run()
    → StaticAgent → ScenarioBuilder
    → [NetworkMonitor + Filesystem + Registry + ThreatIntel] (parallel)
    → CriticAgent → ReportAgent
  → if confirmed threat:
    → [BlocklistAgent + AlertAgent + TicketAgent] (parallel)
    → VerificationLoopAgent (loop until verified or escalate)
```

### Parallelism

Parallel agents use ThreadPoolExecutor + asyncio.gather. Never use
threading.Thread directly. See orchestrator.py for the pattern.

### Progress Callbacks

The analysis pipeline accepts an optional `progress_callback` function.
Every agent calls it when it starts and completes:

```python
if self.progress_callback:
    self.progress_callback(agent_name="static", status="running", percent=0)
    # ... do work ...
    self.progress_callback(agent_name="static", status="complete", percent=100)
```

The FastAPI backend stores these in a job dict that the frontend polls.

---

## Environment Variables

Required in .env (see .env.example):

```
ANTHROPIC_API_KEY=sk-ant-...
VIRUSTOTAL_API_KEY=...          # optional, falls back to mock data
ABUSEIPDB_API_KEY=...           # optional, falls back to mock data
DOCKER_SOCKET=/var/run/docker.sock
```

If VirusTotal or AbuseIPDB keys are missing, the ThreatIntelAgent
must fall back to returning plausible mock data rather than failing.
Never let a missing optional key crash the pipeline.

---

## API Contract

### POST /analyze

- Input: multipart form, field name "file"
- Returns: {"job_id": "uuid"}

### GET /status/{job_id}

- Returns the full job dict (see models.py for schema)
- Polled every 2 seconds by the frontend
- The "progress" key contains per-agent status and findings

### GET /export/{job_id}

- Returns the final report as JSON

The frontend never receives errors — if something fails, the job
status becomes "error" with a message, the frontend shows it gracefully.

---

## Frontend Conventions

- All API calls go through `src/api/client.js` — never fetch directly
  from components
- Polling logic lives in `src/hooks/useAnalysis.js` — no polling in
  components
- Components are purely presentational — they receive props, they do
  not call APIs
- The UI design is already built (malwarescope_v2.html). When building
  React components, match that design exactly. Colors, spacing, fonts,
  and component structure are defined there.

---

## Simulation Layer

For the demo, real malware execution is replaced with simulated data
streams. The simulation layer lives in /simulation and generates
realistic events with periodic anomalies injected.

When writing or modifying simulation code:

- Keep event schemas consistent with what the analysis agents expect
- Anomalies should be injected at a rate that makes the demo watchable
  (roughly one meaningful anomaly per 30-60 seconds of demo time)
- Every simulated event must be traceable to a realistic real-world
  equivalent

---

## Testing

Run tests with: `pytest tests/ -v`

Each agent has a corresponding test that:

1. Mocks the Anthropic API call
2. Verifies the agent returns the correct JSON schema
3. Verifies error handling (missing keys, malformed API response)

When adding a new agent, add its test file before considering the
agent complete.

---

## What "Done" Looks Like For Each Component

**A monitoring agent is done when:**

- It runs in a background thread without blocking
- It correctly calls the triage callback with a well-formed anomaly dict
- It has a stop() method that cleanly terminates the loop

**An analysis agent is done when:**

- It follows the agent pattern above exactly
- Its system prompt is specific and domain-focused
- It returns a validated JSON response matching the schema in models.py
- It calls progress_callback at start and completion

**A response agent is done when:**

- It takes a threat_report dict and returns an action_result dict
- It logs what it did to stdout clearly (for demo visibility)
- Its "action" is visible somewhere in the UI or terminal

**The API is done when:**

- All three routes work
- Jobs persist in memory for the duration of the process
- The status endpoint returns the full progress dict including all
  agent findings as they arrive

**The frontend is done when:**

- It matches the malwarescope_v2.html design
- It polls correctly and updates in real time
- All panels have working empty states
- The demo flows without any manual intervention after clicking Analyze

---

## Hackathon Priorities

If time runs short, complete in this order:

1. Analysis pipeline (Layer 2) — this is the NextEra deliverable
2. FastAPI backend wired to the pipeline
3. Frontend wired to the backend
4. Response agents (Layer 3) — this is the Google differentiator
5. Monitoring agents (Layer 1) — adds depth but not critical for demo
6. Verification loop — explicitly required for Google LoopAgent rubric
7. Tests — write if time permits, skip if not

Never sacrifice a working demo for architectural completeness.
A polished, working subset beats a broken full system every time.

---

## Common Mistakes to Avoid

- Do not use `threading.Thread` directly — use ThreadPoolExecutor
- Do not let optional API keys cause crashes — always have fallbacks
- Do not put business logic in FastAPI route handlers — keep routes thin
- Do not poll the Anthropic API more than necessary — batch where possible
- Do not hardcode the model string anywhere except a single constant:
  `CLAUDE_MODEL = "claude-opus-4-5"` defined in analysis/agents/**init**.py
- Do not create new files outside the structure above without a clear reason
- Do not modify the frontend design — implement it, don't redesign it
