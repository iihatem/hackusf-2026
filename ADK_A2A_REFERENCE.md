# Google ADK & A2A Protocol — Reference Documentation

### For use with Claude Code when building MalwareScope

### Fetched directly from google.github.io/adk-docs — March 2026

---

## CRITICAL SECURITY ADVISORY (Read First)

**LiteLLM Supply Chain Compromise (March 24, 2026):**
Unauthorized code was identified in LiteLLM versions 1.82.7 and 1.82.8 on PyPI.

- Do NOT use `pip install litellm` without pinning to a safe version
- If using ADK Python with `eval` or `extensions` extras, check the ADK security advisory
- We use LiteLLM to run Claude through ADK — pin the version explicitly in requirements.txt
- See: https://github.com/google/adk-python/issues/5005

---

## 1. What ADK Is

Agent Development Kit (ADK) is Google's open-source, code-first framework for building,
evaluating, and deploying AI agents. Key facts:

- **Model-agnostic** — works with Gemini, Claude (via LiteLLM), and others
- **Framework-agnostic** — designed to interoperate with other agent frameworks
- **Current Python version:** 0.x (still early, APIs may shift)
- **Install:** `pip install google-adk`
- **Install with A2A support:** `pip install google-adk[a2a]`
- **Docs:** https://google.github.io/adk-docs/
- **Machine-readable docs (for MCP):** https://google.github.io/adk-docs/llms.txt

The three core primitives:

1. **Agent** — the worker unit (LlmAgent, or workflow agents)
2. **Tool** — gives agents abilities beyond conversation
3. **Runner** — executes agents and manages session state

---

## 2. Agent Types

### 2.1 LlmAgent (the AI-powered agent)

The standard agent type. Backed by an LLM. Can reason, plan, use tools, and
respond dynamically.

```python
from google.adk.agents import LlmAgent

agent = LlmAgent(
    name="my_agent",           # Required: unique name
    model="gemini-2.0-flash",  # Required: model string or model object
    instruction="You are...",  # System prompt / persona
    description="What this agent does",  # Used by orchestrators for routing
    tools=[my_tool],           # List of tools the agent can call
    output_key="result_key",   # If set, writes final response to session state
)
```

### 2.2 Workflow Agents (deterministic orchestration)

These are NOT LLM-powered — they are deterministic controllers that orchestrate
other agents. They don't reason; they execute a fixed pattern.

#### SequentialAgent

Runs sub-agents one after another in order.

```python
from google.adk.agents import SequentialAgent

pipeline = SequentialAgent(
    name="MyPipeline",
    sub_agents=[agent_a, agent_b, agent_c],  # Executes in this order
    description="Runs A then B then C"
)
```

#### ParallelAgent

Runs all sub-agents CONCURRENTLY. Use when tasks are independent.

```python
from google.adk.agents import ParallelAgent

parallel = ParallelAgent(
    name="ParallelAnalysis",
    sub_agents=[network_agent, filesystem_agent, registry_agent, intel_agent],
    description="Runs all four agents simultaneously"
)
```

IMPORTANT about ParallelAgent:

- Sub-agents run in independent branches — NO automatic state sharing between them
- Each sub-agent should use `output_key` to write results to shared session state
- The orchestrator collects results after all branches complete
- Order of results is NOT guaranteed to be deterministic
- To share state between parallel agents, use shared InvocationContext or external state

#### LoopAgent

Runs sub-agents repeatedly until a termination condition is met.

```python
from google.adk.agents import LoopAgent

loop = LoopAgent(
    name="VerificationLoop",
    sub_agents=[check_agent, fix_agent],  # Runs in sequence, repeated
    max_iterations=3  # Hard cap — ALWAYS set this to prevent infinite loops
)
```

IMPORTANT about LoopAgent:

- Does NOT decide when to stop on its own — you MUST implement termination
- Termination strategies:
  1. Set `max_iterations` (simplest — always do this as a safety net)
  2. Sub-agent calls `exit_loop` tool (sets `tool_context.actions.escalate = True`)
  3. Sub-agent sets a flag in shared session state that another agent checks
- The `exit_loop` tool pattern is the most explicit and readable

**exit_loop tool pattern:**

```python
from google.adk.tools.tool_context import ToolContext

def exit_loop(tool_context: ToolContext):
    """Call this ONLY when the verification confirms all actions are complete."""
    tool_context.actions.escalate = True
    tool_context.actions.skip_summarization = True
    return {}

# The agent inside the loop uses this tool:
verifier_agent = LlmAgent(
    name="VerifierAgent",
    model="gemini-2.0-flash",
    instruction="""Check if all response actions completed successfully.
    If yes, call exit_loop. If not, describe what failed.""",
    tools=[exit_loop],
    output_key="verification_result"
)

loop = LoopAgent(
    name="ResponseVerificationLoop",
    sub_agents=[verifier_agent],
    max_iterations=3
)
```

### 2.3 Custom Agents (extend BaseAgent)

For complex conditional logic not covered by the workflow agents above.

```python
from google.adk.agents import BaseAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event
from typing import AsyncGenerator
from typing_extensions import override

class TriageAgent(BaseAgent):
    def __init__(self, name: str, on_escalate_agent: BaseAgent, **kwargs):
        super().__init__(name=name, **kwargs)
        self.on_escalate_agent = on_escalate_agent

    @override
    async def _run_async_impl(
        self, ctx: InvocationContext
    ) -> AsyncGenerator[Event, None]:
        # Custom logic here
        # Access session state: ctx.session.state
        # Yield events to communicate results

        anomaly = ctx.session.state.get("latest_anomaly")
        if anomaly and anomaly.get("severity") == "high":
            # Delegate to escalation agent
            async for event in self.on_escalate_agent.run_async(ctx):
                yield event
        else:
            # Dismiss
            yield Event(author=self.name, content="Anomaly dismissed")
```

---

## 3. Tools

Tools give agents abilities beyond text generation.

### 3.1 Function Tools (most common)

```python
def analyze_file(file_path: str, tool_context: ToolContext) -> dict:
    """
    Analyze a file and extract key artifacts.

    Args:
        file_path: Path to the file to analyze
        tool_context: ADK tool context (injected automatically, don't pass manually)

    Returns:
        dict with keys: hashes, entropy, strings, pe_info
    """
    # The docstring is CRITICAL — the LLM reads it to know when/how to use this tool
    result = perform_analysis(file_path)
    return result

agent = LlmAgent(
    name="StaticAnalysisAgent",
    model="gemini-2.0-flash",
    tools=[analyze_file]  # Pass the function directly
)
```

### 3.2 Using Other Agents as Tools (AgentTool)

```python
from google.adk.tools import agent_tool

# Wrap an agent to use it as a tool
analysis_tool = agent_tool.AgentTool(agent=analysis_pipeline_agent)

orchestrator = LlmAgent(
    name="Orchestrator",
    model="gemini-2.0-flash",
    tools=[analysis_tool]
)
```

---

## 4. Session State — How Agents Share Data

Session state is the primary mechanism for sharing data between agents in a pipeline.

```python
# An agent writes to state using output_key:
agent_a = LlmAgent(
    name="AgentA",
    model="gemini-2.0-flash",
    instruction="Analyze the sample. Output only the JSON result.",
    output_key="static_analysis_result"  # Writes to state["static_analysis_result"]
)

# A downstream agent reads from state using {placeholder} syntax in instruction:
agent_b = LlmAgent(
    name="AgentB",
    model="gemini-2.0-flash",
    instruction="""You receive static analysis results and build a behavioral scenario.

    Static analysis results:
    {static_analysis_result}

    Based on these artifacts, project what would happen if this malware executed.""",
    output_key="behavioral_scenario"
)
```

State placeholders (`{key_name}`) in instructions are automatically substituted
with values from `ctx.session.state` before the LLM sees them.

---

## 5. Running Agents

### 5.1 InMemoryRunner (for development and demos)

```python
from google.adk.runners import InMemoryRunner
from google.genai import types

APP_NAME = "malwarescope"
USER_ID = "analyst_01"
SESSION_ID = "analysis_session_001"

async def run_analysis(sample_path: str):
    runner = InMemoryRunner(agent=root_agent, app_name=APP_NAME)

    session = await runner.session_service.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        state={"sample_path": sample_path}  # Initial state
    )

    content = types.Content(
        role="user",
        parts=[types.Part(text=f"Analyze the malware sample at {sample_path}")]
    )

    async for event in runner.run_async(
        user_id=USER_ID,
        session_id=session.id,
        new_message=content
    ):
        if event.is_final_response():
            print("Final response:", event.content)
```

### 5.2 ADK API Server (for FastAPI-style deployment)

```bash
# Start the ADK API server (auto-generates FastAPI endpoints)
adk api_server ./agents_folder/

# Or with A2A support:
adk api_server --a2a ./agents_folder/
```

### 5.3 ADK Dev UI (for debugging — shows agent thoughts and parallel actions)

```bash
adk web ./agents_folder/
# Opens at http://localhost:8000
# CRITICAL for demo: shows the literal "thoughts" and parallel actions of agents
# This is what Google's rubric calls "The Visualization"
```

---

## 6. Using Claude (Anthropic) Models in ADK

### Option A: LiteLLM wrapper (Python — recommended for us)

```python
from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm

# Set ANTHROPIC_API_KEY environment variable first

agent = LlmAgent(
    model=LiteLlm(model="anthropic/claude-opus-4-5"),
    name="malware_analyst",
    instruction="You are an expert malware analyst...",
)
```

**Install:** `pip install litellm` (pin to safe version — see security advisory above)
**Env var:** `ANTHROPIC_API_KEY=sk-ant-...`

### Option B: Via Vertex AI (if using Google Cloud)

```python
# Anthropic Claude models are available on Vertex AI
# Set GOOGLE_CLOUD_PROJECT and authenticate with gcloud
agent = LlmAgent(
    model="claude-opus-4-5@20251101",  # Vertex AI model string format
    name="malware_analyst",
)
```

### Option C: Java SDK only (not relevant for our Python stack)

The native `Claude` wrapper class only exists in the Java ADK SDK.
For Python, always use LiteLLM.

---

## 7. A2A Protocol — Agent-to-Agent Communication

A2A is the standard protocol for agents to communicate across network boundaries.
It is separate from ADK but integrates with it.

### 7.1 When to Use A2A vs Local Sub-Agents

**Use local sub-agents when:**

- Agents run within the same Python process
- They share memory and state directly
- Performance is critical (no network overhead)
- Simple code organization

**Use A2A when:**

- Agents run as separate services (different ports/servers)
- Agents are maintained by different teams
- Agents are written in different languages
- You need a formal API contract between components
- You want to demonstrate cross-service agent communication (Google's rubric!)

### 7.2 Exposing an Agent via A2A

**Method 1: `to_a2a()` function (simplest — auto-generates agent card)**

```python
# In your agent file (e.g., analysis_agent/agent.py)
from google.adk.agents import LlmAgent, SequentialAgent
from google.adk.a2a.utils.agent_to_a2a import to_a2a

# Define your agent normally
root_agent = SequentialAgent(
    name="MalwareAnalysisPipeline",
    sub_agents=[static_agent, scenario_agent, parallel_analysis, critic_agent, report_agent],
    description="Full malware analysis pipeline"
)

# Expose it via A2A — auto-generates agent card
a2a_app = to_a2a(root_agent, port=8001)

# Start with: uvicorn analysis_agent.agent:a2a_app --host localhost --port 8001
```

**Method 2: `adk api_server --a2a` (with manual agent.json)**

```bash
adk api_server --a2a ./agents_folder/
```

Requires an `agent.json` (agent card) in each agent folder. Auto-exposes all
agents that have an agent card via A2A on the same server.

**Checking your agent is running:**

```bash
curl http://localhost:8001/.well-known/agent-card.json
```

### 7.3 Consuming a Remote A2A Agent

```python
from google.adk.agents import LlmAgent
from google.adk.a2a.remote_a2a_agent import RemoteA2aAgent

# The consuming agent connects to the remote service
remote_analysis_agent = RemoteA2aAgent(
    name="RemoteMalwareAnalyzer",
    # Points to the agent card of the remote service
    agent_card_url="http://localhost:8001/.well-known/agent-card.json",
    description="Remote malware analysis pipeline running as a separate service"
)

# Use it exactly like a local agent or tool
root_agent = LlmAgent(
    name="InfrastructureProtectionOrchestrator",
    model="gemini-2.0-flash",
    instruction="You coordinate infrastructure monitoring and malware analysis.",
    tools=[agent_tool.AgentTool(agent=remote_analysis_agent)]
)
```

### 7.4 A2A for MalwareScope — Our Architecture

In our system, we use A2A to separate the monitoring layer from the analysis pipeline:

```
Monitoring Service (port 8000 — adk web or adk api_server)
  └── MonitoringOrchestratorAgent
        ├── NetworkFeedAgent (local sub-agent)
        ├── EndpointFeedAgent (local sub-agent)
        ├── ThreatIntelFeedAgent (local sub-agent)
        └── TriageAgent (local sub-agent)
              │
              │ A2A call when escalating
              ▼
Analysis Service (port 8001 — uvicorn via to_a2a())
  └── MalwareAnalysisPipeline (exposed via A2A)
        ├── StaticAgent
        ├── ScenarioBuilderAgent
        ├── ParallelAgent [NetworkMonitor, Filesystem, Registry, ThreatIntel]
        ├── CriticAgent
        └── ReportAgent
              │
              │ A2A call with confirmed threat report
              ▼
Response Service (port 8002 — uvicorn via to_a2a())
  └── AutonomousResponsePipeline (exposed via A2A)
        ├── ParallelAgent [BlocklistAgent, AlertAgent, TicketAgent]
        └── LoopAgent [VerificationAgent] (with exit_loop tool)
```

This three-service architecture is exactly what Google's A2A rubric rewards:

- Separate services communicating via A2A protocol
- Each service independently deployable
- "Agent Handshake" (A2A connection) is demonstrable in the ADK Dev UI

---

## 8. Complete Working Example for MalwareScope

This is how our analysis pipeline maps to ADK primitives:

```python
# analysis_service/agent.py
import os
from google.adk.agents import LlmAgent, SequentialAgent, ParallelAgent
from google.adk.models.lite_llm import LiteLlm
from google.adk.a2a.utils.agent_to_a2a import to_a2a

CLAUDE_MODEL = LiteLlm(model="anthropic/claude-opus-4-5")

# ── Static Analysis Agent ──────────────────────────────────────────
static_agent = LlmAgent(
    name="StaticAnalysisAgent",
    model=CLAUDE_MODEL,
    instruction="""You are an expert in binary static analysis.
    Analyze the file at the path provided in session state key 'sample_path'.
    Extract: SHA256 hash, file entropy (0-8), suspicious strings,
    PE header imports (if applicable), and YARA rule matches.

    Return ONLY valid JSON with keys:
    hashes, entropy, strings, pe_info, yara_matches, file_type
    """,
    description="Performs static analysis on a malware sample without executing it.",
    output_key="static_analysis_result"
)

# ── Scenario Builder Agent ─────────────────────────────────────────
scenario_agent = LlmAgent(
    name="ScenarioBuilderAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a malware behavior simulation expert.

    Static analysis results:
    {static_analysis_result}

    Project a realistic behavioral scenario. Every event you generate
    MUST be cited back to a specific artifact from the static analysis.

    Return ONLY valid JSON with keys:
    network_traffic (list of events), filesystem_events (list),
    system_state_changes (list). Each event must have a 'source_artifact' field.
    """,
    description="Projects behavioral simulation from static artifacts.",
    output_key="behavioral_scenario"
)

# ── Parallel Analysis Agents ───────────────────────────────────────
network_monitor = LlmAgent(
    name="NetworkMonitorAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a network forensics specialist.

    Simulated network traffic to analyze:
    {behavioral_scenario}

    Identify: C2 communication, DNS beaconing patterns, DGA indicators,
    data exfiltration, lateral movement attempts.

    Return ONLY valid JSON with keys:
    c2_detected, c2_indicators, dns_queries, dga_suspected,
    exfiltration_detected, connections, mitre_techniques
    """,
    description="Analyzes simulated network traffic for C2 and exfiltration.",
    output_key="network_findings"
)

filesystem_monitor = LlmAgent(
    name="FilesystemMonitorAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a malware filesystem behavior analyst.

    Simulated filesystem events:
    {behavioral_scenario}

    Identify: dropped payloads, persistence mechanisms, credential access,
    log tampering, staging directories.

    Return ONLY valid JSON with keys:
    dropped_files, persistence_paths, sensitive_files_accessed,
    log_tampering, staging_directories, mitre_techniques
    """,
    description="Analyzes simulated filesystem events for dropper and persistence behavior.",
    output_key="filesystem_findings"
)

registry_monitor = LlmAgent(
    name="RegistryMonitorAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a Linux/Windows system persistence analyst.

    Simulated system state changes:
    {behavioral_scenario}

    Identify: persistence mechanisms, privilege escalation, rootkit indicators,
    backdoor installation.

    Return ONLY valid JSON with keys:
    persistence_mechanisms, privilege_escalation, escalation_method,
    rootkit_indicators, backdoor_installed, mitre_techniques
    """,
    description="Analyzes simulated system state changes for persistence and privesc.",
    output_key="registry_findings"
)

threat_intel_agent = LlmAgent(
    name="ThreatIntelAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a threat intelligence analyst.

    Static analysis results including hashes and extracted IOCs:
    {static_analysis_result}

    Cross-reference against known threat intelligence. Identify malware family,
    threat actor attribution, campaign indicators.

    Return ONLY valid JSON with keys:
    malicious_votes, total_engines, family, first_seen,
    threat_actor, campaign, ip_reputation
    """,
    description="Correlates findings against threat intelligence databases.",
    output_key="intel_findings"
)

# Run all four simultaneously
parallel_analysis = ParallelAgent(
    name="ParallelAnalysisAgents",
    sub_agents=[network_monitor, filesystem_monitor, registry_monitor, threat_intel_agent],
    description="Runs four specialist analysis agents concurrently."
)

# ── Critic Agent ───────────────────────────────────────────────────
critic_agent = LlmAgent(
    name="CriticAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a skeptical red-team analyst.

    Network findings: {network_findings}
    Filesystem findings: {filesystem_findings}
    Registry findings: {registry_findings}
    Intel findings: {intel_findings}

    Challenge the findings. Look for: false positive risks, correlation gaps
    (e.g., C2 detected but no dropper found — suspicious inconsistency),
    missing expected indicators, alternative benign explanations.

    Return ONLY valid JSON with keys:
    overall_verdict (confirmed_malicious|likely_malicious|uncertain|likely_benign),
    false_positive_risks, correlation_gaps, confidence_adjustments,
    missing_indicators
    """,
    description="Cross-validates all agent findings and reduces false positives.",
    output_key="critic_review"
)

# ── Report Writer Agent ────────────────────────────────────────────
report_agent = LlmAgent(
    name="ReportWriterAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a senior cybersecurity report writer.

    All findings:
    Static: {static_analysis_result}
    Network: {network_findings}
    Filesystem: {filesystem_findings}
    Registry: {registry_findings}
    Intel: {intel_findings}
    Critic review: {critic_review}

    Synthesize into a final threat report. Incorporate critic's confidence
    adjustments. Note contested findings.

    Return ONLY valid JSON with keys:
    executive_summary, malware_type, malware_family, confidence,
    severity (critical|high|medium|low), severity_score (0-10),
    iocs (ips, domains, files, hashes),
    mitre_attack (list of {id, tactic, technique}),
    at_risk (systems, data_types, ics_relevant),
    remediation (immediate, short_term, long_term — each a list of strings)
    """,
    description="Synthesizes all findings into the final threat report.",
    output_key="final_report"
)

# ── Full Pipeline ──────────────────────────────────────────────────
analysis_pipeline = SequentialAgent(
    name="MalwareAnalysisPipeline",
    sub_agents=[
        static_agent,
        scenario_agent,
        parallel_analysis,   # <-- ParallelAgent (hits Google rubric)
        critic_agent,
        report_agent
    ],
    description="Complete malware analysis pipeline from static artifacts to final report."
)

root_agent = analysis_pipeline

# Expose via A2A for the response service to consume
a2a_app = to_a2a(root_agent, port=8001)

# Start with:
# uvicorn analysis_service.agent:a2a_app --host localhost --port 8001
```

---

## 9. Response Service with LoopAgent

```python
# response_service/agent.py
from google.adk.agents import LlmAgent, ParallelAgent, LoopAgent, SequentialAgent
from google.adk.models.lite_llm import LiteLlm
from google.adk.tools.tool_context import ToolContext
from google.adk.a2a.utils.agent_to_a2a import to_a2a

CLAUDE_MODEL = LiteLlm(model="anthropic/claude-opus-4-5")

# ── exit_loop tool ─────────────────────────────────────────────────
def exit_loop(tool_context: ToolContext):
    """Call this ONLY when verification confirms all response actions completed."""
    tool_context.actions.escalate = True
    tool_context.actions.skip_summarization = True
    return {}

# ── Response Agents (run in parallel) ─────────────────────────────
blocklist_agent = LlmAgent(
    name="BlocklistAgent",
    model=CLAUDE_MODEL,
    instruction="""Extract all network IOCs from the threat report and
    push them to the firewall blocklist.

    Threat report: {final_report}

    Return ONLY valid JSON:
    {"blocked_ips": [], "blocked_domains": [], "actions_taken": 0, "status": "success"}
    """,
    description="Extracts IOCs and pushes them to the simulated firewall.",
    output_key="blocklist_result"
)

alert_agent = LlmAgent(
    name="AlertAgent",
    model=CLAUDE_MODEL,
    instruction="""Compose a SOC alert for the security team.

    Threat report: {final_report}

    Return ONLY valid JSON:
    {"subject": "", "body": "", "severity": "",
     "requires_human_action": true, "human_actions": []}
    """,
    description="Composes and sends an alert to the SOC team.",
    output_key="alert_result"
)

ticket_agent = LlmAgent(
    name="TicketAgent",
    model=CLAUDE_MODEL,
    instruction="""Create a structured incident ticket.

    Threat report: {final_report}

    Return ONLY valid JSON:
    {"ticket_id": "INC-XXXXX", "title": "", "severity": "",
     "summary": "", "affected_systems": [], "sla_hours": 4}
    """,
    description="Opens an incident ticket in the simulated ticketing system.",
    output_key="ticket_result"
)

# All three response actions run simultaneously
parallel_response = ParallelAgent(
    name="ParallelResponseAgents",
    sub_agents=[blocklist_agent, alert_agent, ticket_agent],
    description="Executes blocklist, alert, and ticket actions concurrently."
)

# ── Verification Loop Agent ────────────────────────────────────────
verifier_agent = LlmAgent(
    name="VerificationAgent",
    model=CLAUDE_MODEL,
    instruction="""Verify all response actions completed successfully.

    Blocklist result: {blocklist_result}
    Alert result: {alert_result}
    Ticket result: {ticket_result}
    Threat report: {final_report}

    Check that:
    1. All C2 IPs and domains are in the blocklist result
    2. Alert was sent with correct severity
    3. Ticket was created with the right information

    If ALL checks pass: call exit_loop immediately.
    If anything failed: describe what failed so it can be retried.
    """,
    description="Verifies response actions and exits loop when complete.",
    tools=[exit_loop],
    output_key="verification_result"
)

verification_loop = LoopAgent(
    name="ResponseVerificationLoop",
    sub_agents=[verifier_agent],
    max_iterations=3  # <-- Always set max_iterations
)

# ── Full Response Pipeline ─────────────────────────────────────────
response_pipeline = SequentialAgent(
    name="AutonomousResponsePipeline",
    sub_agents=[parallel_response, verification_loop],
    description="Executes containment actions and verifies completion."
)

root_agent = response_pipeline
a2a_app = to_a2a(root_agent, port=8002)

# Start with:
# uvicorn response_service.agent:a2a_app --host localhost --port 8002
```

---

## 10. Startup Commands

```bash
# Terminal 1 — Analysis Service (A2A server on port 8001)
uvicorn analysis_service.agent:a2a_app --host localhost --port 8001

# Terminal 2 — Response Service (A2A server on port 8002)
uvicorn response_service.agent:a2a_app --host localhost --port 8002

# Terminal 3 — Monitoring + Orchestration (ADK Dev UI on port 8000)
adk web ./monitoring_service/
# Open http://localhost:8000 — this is the main interface
# The ADK Dev UI shows agent thoughts and parallel actions — CRITICAL for demo

# Terminal 4 — FastAPI backend for the React frontend
uvicorn api.main:app --host 0.0.0.0 --port 9000
```

---

## 11. Environment Variables

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_GENAI_USE_VERTEXAI=FALSE  # Use Anthropic directly, not through Vertex

# Optional (ADK uses Gemini by default for its own orchestration logic)
# If you want ADK's built-in features to also use Gemini:
GOOGLE_API_KEY=your-google-ai-studio-key

# Our agents use Claude via LiteLLM — no Google key needed for agent LLM calls
# Google key only needed if using Google Search tool or Vertex AI features
```

---

## 12. Adding ADK Docs to Claude Code via MCP

The ADK documentation team provides an official MCP server for Claude Code.
Run this command to give Claude Code live access to ADK docs:

```bash
claude mcp add adk-docs --transport stdio -- uvx --from mcpdoc mcpdoc \
  --urls AgentDevelopmentKit:https://google.github.io/adk-docs/llms.txt \
  --transport stdio
```

This is preferable to static documentation because ADK is actively developed
and the docs are updated frequently. With MCP connected, Claude Code can
look up current API signatures directly.

---

## 13. Key Gotchas and Things Claude Code Must Know

1. **`output_key` is how agents communicate** — the string you set becomes the
   session state key. The next agent reads it via `{key_name}` in its instruction.
   Miss this and agents are blind to each other's outputs.

2. **ParallelAgent sub-agents cannot read each other's state** during execution.
   They run independently. Use SequentialAgent to chain a ParallelAgent with a
   synthesis agent that reads all outputs via state placeholders.

3. **LoopAgent ALWAYS needs `max_iterations`** — without it, a bug in the exit
   condition causes an infinite loop. Set it even when you have an exit tool.

4. **`root_agent` is the magic name** — ADK's tooling (`adk web`, `adk api_server`)
   looks for a variable literally named `root_agent` in the agent.py file.
   Always name your top-level agent `root_agent`.

5. **LiteLLM model string format** — use `"anthropic/claude-opus-4-5"` not just
   `"claude-opus-4-5"`. The `anthropic/` prefix tells LiteLLM which provider to use.

6. **A2A requires `pip install google-adk[a2a]`** — the base `google-adk` package
   does NOT include A2A support. The `[a2a]` extra is required.

7. **`to_a2a()` auto-generates the agent card** — you don't need to write agent.json
   manually when using `to_a2a()`. It reads the agent's name, description, and tools.

8. **ADK Dev UI is NOT for production** — use it only for development and demos.
   The judge demo should run `adk web` to show the parallel agent execution trace.

9. **LiteLLM security advisory** — pin the LiteLLM version in requirements.txt.
   Do not `pip install litellm` without specifying a version known to be safe.
   Check https://github.com/google/adk-python/issues/5005 for safe versions.

10. **State placeholder syntax** — use `{key_name}` (single braces) in LlmAgent
    instructions, NOT `{{key_name}}`. Double braces are Python f-string escapes
    and will NOT be substituted by ADK.
