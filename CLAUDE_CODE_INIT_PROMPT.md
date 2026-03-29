# MalwareScope — Claude Code Build Initiation Prompt

---

You are being brought into a hackathon project called **MalwareScope** — an autonomous critical infrastructure threat detection and response system. This is not a toy project. We are competing for two separate prizes simultaneously and the quality of what we build directly determines whether we win. Read everything in this prompt carefully before writing a single line of code.

---

## Step 1 — Read These Files First

Before doing anything else, read the following files in the project root in this order:

1. `CLAUDE.md` — project architecture, conventions, agent patterns, priorities
2. `AGENTS.md` — every agent's input/output schema
3. `ADK_A2A_REFERENCE.md` — Google ADK and A2A protocol documentation (live-fetched)

Do not proceed until you have read all three. After reading them, confirm your understanding by stating:
- The three-layer architecture in one sentence each
- Which agents run in parallel and why
- How `output_key` and `{placeholder}` work together
- What the `exit_loop` tool does and when to call it
- What `root_agent` means to ADK's tooling

If anything in those files is ambiguous or contradictory, flag it now before we start building. Do not make assumptions mid-build that you could clarify upfront.

---

## Step 2 — Understand What We Are Building

MalwareScope has three layers that map onto Google ADK primitives exactly:

**Layer 1 — Continuous Monitoring** (`monitoring_service/`)
Three monitoring agents watch simulated data streams (network traffic, endpoint events, threat intel feeds) on a continuous loop. When they detect anomalies, a Triage agent evaluates severity and decides whether to escalate to deep analysis. This layer runs independently as a service.

**Layer 2 — Deep Analysis Pipeline** (`analysis_service/`)
Triggered by the Triage agent via A2A when an anomaly is escalated. A SequentialAgent runs: StaticAgent → ScenarioBuilderAgent → ParallelAgent[NetworkMonitor, FilesystemMonitor, RegistryMonitor, ThreatIntelAgent] → CriticAgent → ReportAgent. This is the core of the NextEra challenge deliverable. Exposed as an A2A service via `to_a2a()`.

**Layer 3 — Autonomous Response** (`response_service/`)
Triggered by the Analysis pipeline via A2A when a threat is confirmed. A SequentialAgent runs: ParallelAgent[BlocklistAgent, AlertAgent, TicketAgent] → LoopAgent[VerificationAgent with exit_loop tool]. This layer demonstrates Google's "actionability" and LoopAgent requirements. Exposed as an A2A service via `to_a2a()`.

The three services communicate via the A2A protocol. The Analysis service runs on port 8001. The Response service runs on port 8002. The Monitoring service runs via `adk web` on port 8000. A separate FastAPI app on port 9000 serves the React frontend.

---

## Step 3 — Technology Constraints

**Never deviate from these without explicit instruction:**

- All agents use `LiteLlm(model="anthropic/claude-opus-4-5")` as the model. Not Gemini. Not any other Claude model. This exact string.
- All agents follow the pattern documented in `CLAUDE.md`. No exceptions.
- State is shared between agents exclusively via `output_key` and `{placeholder}` syntax in instructions. Not by passing dicts between Python objects.
- Parallelism uses `ParallelAgent` from `google.adk.agents`. Not `ThreadPoolExecutor`. Not `asyncio.gather` directly.
- The verification loop uses `LoopAgent` with `max_iterations=3` and an `exit_loop` tool that sets `tool_context.actions.escalate = True`. This is the ADK-native pattern.
- `root_agent` must be the literal variable name for the top-level agent in each service's `agent.py`. ADK's CLI looks for this name.
- Every agent's `instruction` uses single-brace `{key_name}` placeholders for state substitution — not f-strings, not double braces.
- A2A exposure uses `to_a2a(root_agent, port=XXXX)` stored in a variable called `a2a_app`. Services start with `uvicorn service_name.agent:a2a_app`.
- Install with `pip install google-adk[a2a]` — the `[a2a]` extra is required. LiteLLM must be pinned to a safe version per the security advisory in `ADK_A2A_REFERENCE.md`.

---

## Step 4 — Build Order and Priorities

Build in this exact order. Complete and verify each item before moving to the next. A working subset beats a broken full system.

### Priority 1 — Analysis Pipeline (NextEra deliverable)

**`analysis_service/agent.py`**

Build the full SequentialAgent pipeline:
- `StaticAnalysisAgent` — reads `sample_path` from session state, returns `static_analysis_result`
- `ScenarioBuilderAgent` — reads `static_analysis_result`, returns `behavioral_scenario`
- `ParallelAgent` containing:
  - `NetworkMonitorAgent` — reads `behavioral_scenario`, returns `network_findings`
  - `FilesystemMonitorAgent` — reads `behavioral_scenario`, returns `filesystem_findings`
  - `RegistryMonitorAgent` — reads `behavioral_scenario`, returns `registry_findings`
  - `ThreatIntelAgent` — reads `static_analysis_result`, returns `intel_findings`
- `CriticAgent` — reads all four findings, returns `critic_review`
- `ReportWriterAgent` — reads all findings + critic review, returns `final_report`

The root_agent is the SequentialAgent. Expose it: `a2a_app = to_a2a(root_agent, port=8001)`.

All agent instructions must end with "Return ONLY valid JSON" and specify the exact keys expected. JSON parsing cannot fail silently — add try/except around any JSON parsing and log failures clearly.

**`analysis_service/static_analyzer.py`**

The non-AI artifact extraction module. This runs before the agent pipeline and provides the raw file data:
- `compute_hashes(file_path)` → MD5, SHA256, SHA1
- `compute_entropy(file_path)` → float 0-8
- `extract_strings(file_path, min_len=6)` → list of printable strings
- `parse_pe_headers(file_path)` → dict or None if not a PE file
- `run_yara(file_path, rules_dir="yara_rules/")` → list of match strings
- `analyze(file_path)` → combined dict matching the `static_analysis_result` schema in `AGENTS.md`

Dependencies: `pefile`, `yara-python`, `python-magic`, `hashlib` (stdlib)

### Priority 2 — FastAPI Backend

**`api/main.py`**

Three endpoints:
- `POST /analyze` — accepts multipart file upload, saves to `/tmp/{job_id}_{filename}`, starts analysis as background task, returns `{"job_id": "uuid"}`
- `GET /status/{job_id}` — returns the full job dict including per-agent progress and findings
- `GET /export/{job_id}` — returns final_report as JSON

The job dict schema:
```python
{
    "job_id": str,
    "status": "queued|running|complete|error",
    "progress": {
        "static": {"status": "idle|running|complete|error", "percent": int, "findings": dict},
        "scenario": {...},
        "network": {...},
        "filesystem": {...},
        "registry": {...},
        "intel": {...},
        "critic": {...},
        "report": {...}
    },
    "result": None  # populated when status == "complete"
}
```

The background task runs the analysis pipeline. It uses a `progress_callback` function that updates the job dict in real time as each agent completes. The frontend polls this every 2 seconds.

The analysis pipeline must call the ADK runner, not call agents directly as Python objects. Use `InMemoryRunner` with the session state pre-populated with `{"sample_path": path_to_uploaded_file}`.

### Priority 3 — Frontend

**`frontend/src/App.jsx`**

The UI design is already built and can be found at `malwarescope_v2.html` in the project root. Implement it as React components. Match the design exactly — do not redesign, do not simplify, do not substitute components.

Component structure:
- `App.jsx` — layout, state management, polling logic via `useAnalysis` hook
- `components/PipelineFlow.jsx` — the ADK pipeline visualization with node states
- `components/AgentStatus.jsx` — the 8 agent cards with running/complete states
- `components/Timeline.jsx` — live-scrolling event feed
- `components/IOCTable.jsx` — extracted indicators table
- `components/ReportPanel.jsx` — final report with severity ring, MITRE, remediation

All API calls go through `src/api/client.js`. Polling lives in `src/hooks/useAnalysis.js`. Components are purely presentational.

### Priority 4 — Response Service

**`response_service/agent.py`**

Build the AutonomousResponsePipeline:
- `ParallelAgent` containing `BlocklistAgent`, `AlertAgent`, `TicketAgent`
- `LoopAgent` containing `VerificationAgent` with `exit_loop` tool, `max_iterations=3`
- Root SequentialAgent wrapping both
- Expose: `a2a_app = to_a2a(root_agent, port=8002)`

The VerificationAgent must check that all three parallel response agents completed successfully. If verification passes, call `exit_loop`. If it fails after max_iterations, set a `escalation_required` flag in session state.

### Priority 5 — Monitoring Service

**`monitoring_service/agent.py`**

Three monitoring agents running on continuous loops watching simulated streams, feeding into a Triage agent. The Triage agent uses a `RemoteA2aAgent` pointing to the Analysis service at `http://localhost:8001/.well-known/agent-card.json` to escalate confirmed threats.

The simulation layer in `simulation/` generates realistic events. Network events should include a realistic anomaly injection rate — one meaningful anomaly per 45-60 seconds of demo time.

### Priority 6 — Verification Loop Robustness

Ensure the LoopAgent's `VerificationAgent` handles edge cases:
- What happens if `blocklist_result` is missing from state (agent failed)?
- What happens at `max_iterations` without exit_loop being called?
- Log every iteration clearly to stdout with `[VERIFICATION Loop N/3]` prefix

### Priority 7 — Tests

One test file per agent. Each test:
1. Mocks the LiteLLM call
2. Verifies the agent returns JSON matching the schema in `AGENTS.md`
3. Verifies graceful handling of malformed LLM response

---

## Step 5 — What Done Looks Like

The project is complete when all of the following are true:

**Functional:**
- `uvicorn analysis_service.agent:a2a_app --port 8001` starts without errors
- `uvicorn response_service.agent:a2a_app --port 8002` starts without errors
- `adk web monitoring_service/` opens the ADK Dev UI at `localhost:8000`
- `uvicorn api.main:app --port 9000` starts without errors
- Uploading any file to `POST /analyze` returns a job_id
- Polling `GET /status/{job_id}` shows per-agent progress updating in real time
- The frontend at `localhost:3000` shows the pipeline running and completing
- The ADK Dev UI at `localhost:8000` shows the parallel agent execution trace

**Demo-critical:**
- When the ParallelAgent runs, all four agent cards in the UI transition to "running" simultaneously — not sequentially
- The Timeline tab streams events as they arrive, not all at once at the end
- The right panel populates with the final report only after the ReportWriterAgent completes
- The severity ring animates on appearance
- The LoopAgent's verification iterations are visible in the terminal output

**Google ADK rubric:**
- `ParallelAgent` is used in both the analysis pipeline and the response pipeline
- `LoopAgent` with `exit_loop` tool is used in the response pipeline
- At least one `RemoteA2aAgent` connection exists (monitoring → analysis via A2A)
- The ADK Dev UI shows "thoughts" and parallel actions visually
- The system takes a real-world action beyond generating a report (blocklist, alert, ticket)

---

## Step 6 — How to Handle Ambiguity

If you encounter a decision point not covered by this prompt or `CLAUDE.md`:

1. Check `AGENTS.md` for the relevant schema
2. Check `ADK_A2A_REFERENCE.md` section 13 (Gotchas) for ADK-specific issues
3. Default to the simpler implementation that keeps the demo working
4. Never sacrifice a working demo for architectural purity
5. If genuinely stuck between two approaches, implement the simpler one and leave a `# TODO: [describe tradeoff]` comment

Do not ask for clarification on things that are clearly specified. Do ask if something is genuinely ambiguous and the wrong choice would require significant rework.

---

## Begin

Start with Priority 1. Read the three files, confirm your understanding as described in Step 1, flag any ambiguities, then begin building `analysis_service/agent.py` followed by `analysis_service/static_analyzer.py`.

When each file is complete, run any relevant tests, verify the output matches the schema in `AGENTS.md`, and confirm before moving to the next file. State clearly when you are done with each file and what you are moving to next.

Do not skip steps. Do not combine steps. Build sequentially, verify at each step, and maintain the quality bar throughout. This is a competition. The output needs to be excellent.
