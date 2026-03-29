"""
MalwareScope — Response Service
Layer 3: Autonomous response pipeline exposed via A2A on port 8002.

Start with:
    uvicorn response_service.agent:a2a_app --host 0.0.0.0 --port 8002

The pipeline:
    ParallelAgent[BlocklistAgent, AlertAgent, TicketAgent]
    → LoopAgent[VerificationAgent (with exit_loop tool), max_iterations=3]
"""

import os
from dotenv import load_dotenv

load_dotenv()

from google.adk.agents import LlmAgent, SequentialAgent, ParallelAgent, LoopAgent
from google.adk.models.lite_llm import LiteLlm

# Use the built-in exit_loop from ADK (verified to exist in ADK 1.28)
from google.adk.tools.exit_loop_tool import exit_loop

try:
    from google.adk.a2a.utils.agent_to_a2a import to_a2a
except ImportError:
    try:
        from google.adk.a2a import to_a2a
    except ImportError:
        to_a2a = None

CLAUDE_MODEL = LiteLlm(model="anthropic/claude-opus-4-5")


# ── Response Agents (run in parallel) ─────────────────────────────────────────

blocklist_agent = LlmAgent(
    name="BlocklistAgent",
    model=CLAUDE_MODEL,
    instruction="""You are an automated firewall and network security agent for a
critical infrastructure operator.

Threat report:
{final_report}

Your job: extract ALL network IOCs (IPs and domains) from the threat report and
simulate pushing them to the perimeter firewall blocklist.

For each blocked item, log the action clearly:
- IP addresses → add to DENY list on perimeter firewall
- Domains → add to DNS sinkhole
- URLs → add to proxy block list

Return ONLY valid JSON with exactly these keys:
{
  "blocked_ips": [str],
  "blocked_domains": [str],
  "blocked_urls": [str],
  "actions_taken": int,
  "firewall_rule_ids": [str],
  "status": "success|partial|failed",
  "notes": str
}

firewall_rule_ids: generate realistic rule IDs like "DENY-INC-1711234567-01", "DENY-INC-1711234567-02"
actions_taken: total count of all blocked items combined
""",
    description="Extracts network IOCs from threat report and pushes them to simulated firewall blocklist.",
    output_key="blocklist_result",
)

alert_agent = LlmAgent(
    name="AlertAgent",
    model=CLAUDE_MODEL,
    instruction="""You are an automated SOC alert dispatch agent for a critical
infrastructure operator.

Threat report:
{final_report}

Your job: compose a structured security alert for the SOC team and simulate sending it.

The alert must:
- Have a clear subject line that includes severity and malware family
- Include a concise body with: what was detected, what systems are at risk, immediate actions required
- Specify who needs to take action (SOC analyst, CISO, OT security team if ICS relevant)
- Include an escalation path if not acknowledged within SLA

Return ONLY valid JSON with exactly these keys:
{
  "subject": str,
  "body": str,
  "severity": "critical|high|medium|low",
  "recipients": [str],
  "requires_human_action": bool,
  "human_actions": [str],
  "sla_minutes": int,
  "escalation_path": str,
  "status": "sent|failed",
  "alert_id": str
}

alert_id: generate like "ALERT-20260328-7421"
""",
    description="Composes and dispatches SOC alert for the security team.",
    output_key="alert_result",
)

ticket_agent = LlmAgent(
    name="TicketAgent",
    model=CLAUDE_MODEL,
    instruction="""You are an automated incident response ticketing agent for a
critical infrastructure operator.

Threat report:
{final_report}

Your job: create a structured incident ticket in the ticketing system (simulated Jira/ServiceNow).

The ticket must include:
- Clear title with severity and malware type
- Full incident summary
- Affected systems inventory
- IOC list for analyst reference
- Remediation checklist (pulled from the threat report)
- SLA assignment based on severity (critical=4h, high=8h, medium=24h, low=72h)

Return ONLY valid JSON with exactly these keys:
{
  "ticket_id": str,
  "title": str,
  "severity": str,
  "status": "open",
  "summary": str,
  "affected_systems": [str],
  "ioc_list": [str],
  "remediation_checklist": [str],
  "sla_hours": int,
  "assigned_to": str,
  "tags": [str],
  "created_at": str
}

ticket_id: generate like "INC-2026-00142"
created_at: use ISO 8601 format
""",
    description="Creates structured incident ticket in the simulated ticketing system.",
    output_key="ticket_result",
)

# All three response actions run simultaneously — they are independent
parallel_response = ParallelAgent(
    name="ParallelResponseAgents",
    sub_agents=[blocklist_agent, alert_agent, ticket_agent],
    description="Executes blocklist enforcement, SOC alerting, and incident ticketing concurrently.",
)

# ── Verification Agent (inside LoopAgent) ──────────────────────────────────────
# Edge case handling:
#   - If blocklist_result/alert_result/ticket_result are missing (agent failed),
#     the check fails and we do NOT call exit_loop — max_iterations is the safety net.
#   - At max_iterations=3 without exit_loop being called, LoopAgent terminates
#     naturally and sets escalation_required in its output.
#   - Every iteration prints [VERIFICATION Loop N/3] to stdout for demo visibility.
verifier_agent = LlmAgent(
    name="VerificationAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a response verification agent. Your job is to confirm that
ALL automated response actions completed successfully.

IMPORTANT: Print "[VERIFICATION Loop N/3]" at the start of your response where N is
the iteration number (1, 2, or 3). This is required for demo visibility.

Threat report (source of truth):
{final_report}

Blocklist result (may be null/missing if BlocklistAgent failed):
{blocklist_result}

Alert result (may be null/missing if AlertAgent failed):
{alert_result}

Ticket result (may be null/missing if TicketAgent failed):
{ticket_result}

Perform these checks IN ORDER. If a result is missing/null, that check FAILS immediately.

CHECK 1: blocklist_result is present and not null
CHECK 2: blocklist_result.status == "success" (not "partial" or "failed")
CHECK 3: blocklist_result.blocked_ips is a non-empty list
CHECK 4: alert_result is present and not null
CHECK 5: alert_result.status == "sent"
CHECK 6: alert_result.severity matches the severity in final_report
CHECK 7: ticket_result is present and not null
CHECK 8: ticket_result.status == "open"
CHECK 9: ticket_result.sla_hours is set and > 0

DECISION RULE:
- If ALL 9 checks pass → call exit_loop tool, then return JSON with overall_status="verified"
- If ANY check fails → return JSON with failed checks listed, overall_status="failed" or "partial"
  DO NOT call exit_loop if any check fails.

After max_iterations=3, if exit_loop was never called, the system will automatically
flag escalation_required=true for human review.

Return ONLY valid JSON:
{
  "iteration_label": "[VERIFICATION Loop N/3]",
  "checks_passed": [str],
  "checks_failed": [str],
  "overall_status": "verified|partial|failed",
  "escalation_required": bool,
  "notes": str
}

escalation_required: set to true only if on iteration 3 and checks still failing.
""",
    description="Verifies all response actions completed. Calls exit_loop when verification passes.",
    tools=[exit_loop],
    output_key="verification_result",
)

# LoopAgent — runs VerificationAgent up to 3 times
# ALWAYS set max_iterations — without it, a bug in exit_loop causes infinite loop
verification_loop = LoopAgent(
    name="ResponseVerificationLoop",
    sub_agents=[verifier_agent],
    max_iterations=3,
)

# ── Full Response Pipeline ─────────────────────────────────────────────────────
response_pipeline = SequentialAgent(
    name="AutonomousResponsePipeline",
    sub_agents=[
        parallel_response,    # BlocklistAgent + AlertAgent + TicketAgent (concurrent)
        verification_loop,    # VerificationAgent loop (max 3 iterations)
    ],
    description=(
        "Autonomous threat response: parallel IOC blocking, alerting, and ticketing, "
        "followed by verification loop with exit_loop tool."
    ),
)

# ADK requires this exact variable name
root_agent = response_pipeline

# Expose via A2A for the analysis service to call when a threat is confirmed
if to_a2a is not None:
    a2a_app = to_a2a(root_agent, port=8002)
else:
    from fastapi import FastAPI
    a2a_app = FastAPI(title="MalwareScope Response Service")

    @a2a_app.get("/health")
    def health():
        return {"status": "ok", "note": "A2A not available — install google-adk[a2a]"}
