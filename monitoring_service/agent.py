"""
MalwareScope — Monitoring Service
Layer 1: Continuous monitoring agents watching simulated data streams.

The TriageAgent escalates confirmed threats to the Analysis Service via A2A.

Start with:
    adk web monitoring_service/
    # Opens ADK Dev UI at http://localhost:8000

Or as API server:
    adk api_server monitoring_service/
"""

import os
from dotenv import load_dotenv

load_dotenv()

from google.adk.agents import LlmAgent, SequentialAgent
from google.adk.models.lite_llm import LiteLlm
from google.adk.tools.tool_context import ToolContext

try:
    from google.adk.tools.agent_tool import AgentTool
    _AGENT_TOOL_AVAILABLE = True
except ImportError:
    _AGENT_TOOL_AVAILABLE = False

CLAUDE_MODEL = LiteLlm(model="anthropic/claude-opus-4-5")

# ── Simulated Stream Reader Tools ──────────────────────────────────────────────
# These tools read from the simulation layer, giving agents real-world-grounded
# event data to analyze.

def read_network_feed(tool_context: ToolContext) -> dict:
    """
    Read the latest batch of network events from the simulated network stream.
    Returns up to 20 recent events including any anomalies detected.
    """
    from simulation.network_stream import (
        _normal_event, _c2_beacon_event, _dns_exfil_event, _lateral_movement_event,
        ANOMALY_GENERATORS
    )
    import random

    events = []
    # Generate a realistic batch: mostly normal, occasionally anomalous
    for _ in range(18):
        events.append(vars(_normal_event()))
    # Add 1-2 suspicious events to make the demo interesting
    for fn in random.sample(ANOMALY_GENERATORS, k=min(2, len(ANOMALY_GENERATORS))):
        events.append(vars(fn()))

    return {"events": events, "total": len(events), "anomalies": sum(1 for e in events if e.get("suspicious"))}


def read_endpoint_feed(tool_context: ToolContext) -> dict:
    """
    Read the latest batch of endpoint events from the simulated endpoint stream.
    Returns process, file, and registry events with any anomalies flagged.
    """
    from simulation.endpoint_stream import (
        _normal_event, _dropper_event, _persistence_event, _lsass_dump_event,
        ANOMALY_GENERATORS
    )
    import random

    events = []
    for _ in range(15):
        events.append(vars(_normal_event()))
    for fn in random.sample(ANOMALY_GENERATORS, k=min(2, len(ANOMALY_GENERATORS))):
        events.append(vars(fn()))

    return {"events": events, "total": len(events), "anomalies": sum(1 for e in events if e.get("suspicious"))}


def read_threat_intel_feed(tool_context: ToolContext) -> dict:
    """
    Read the latest threat intelligence feed updates.
    Returns new IOC additions, malware family updates, and APT activity reports.
    """
    import time, random
    indicators = [
        {"type": "ip", "value": "185.220.101.47", "severity": "high", "family": "Emotet", "added": time.time()},
        {"type": "domain", "value": "update-service.club", "severity": "critical", "family": "Cobalt Strike", "added": time.time()},
        {"type": "hash", "value": "a3f5c2d8e9b1a4f6c8d0e2f4a6b8c0d2", "severity": "high", "family": "QBot", "added": time.time()},
        {"type": "ip", "value": "91.108.4.0", "severity": "medium", "family": "Unknown", "added": time.time()},
    ]
    return {
        "new_indicators": random.sample(indicators, k=random.randint(2, len(indicators))),
        "active_campaigns": ["OilRig Winter 2026", "APT29 Infrastructure Wave"],
        "high_priority_alerts": random.randint(0, 3),
    }


def flag_anomaly_for_escalation(
    anomaly_description: str,
    severity: str,
    source: str,
    tool_context: ToolContext,
) -> dict:
    """
    Flag an anomaly for potential escalation to the deep analysis pipeline.
    Call this when you detect something suspicious that warrants deeper investigation.

    Args:
        anomaly_description: Clear description of what was detected
        severity: 'critical', 'high', 'medium', or 'low'
        source: Which feed detected this ('network', 'endpoint', 'threat_intel')
    """
    import time
    anomaly = {
        "description": anomaly_description,
        "severity": severity,
        "source": source,
        "timestamp": time.time(),
        "escalation_recommended": severity in ("critical", "high"),
    }
    # Write to session state for the TriageAgent to read
    tool_context.state["pending_anomaly"] = anomaly
    return anomaly


# ── Monitoring Agents ──────────────────────────────────────────────────────────

network_monitor_agent = LlmAgent(
    name="NetworkFeedMonitor",
    model=CLAUDE_MODEL,
    instruction="""You are a network security monitoring agent watching live network traffic
for a critical infrastructure operator (energy sector, ICS/SCADA environment).

Use the read_network_feed tool to get the latest network events.

Analyze the events for:
- C2 beaconing patterns (regular interval connections to external IPs)
- DNS tunneling or DGA activity (high-entropy subdomains, unusual query rates)
- Data exfiltration (large outbound transfers, encoded payloads)
- Lateral movement (unusual internal-to-internal connections)
- Known malicious IP connections

If you detect anything suspicious with severity HIGH or CRITICAL:
- Call flag_anomaly_for_escalation with a clear description

Return your findings as JSON:
{
  "anomalies_detected": int,
  "highest_severity": str,
  "summary": str,
  "flagged_events": [str]
}
""",
    description="Monitors simulated network traffic for C2, exfiltration, and lateral movement.",
    tools=[read_network_feed, flag_anomaly_for_escalation],
    output_key="network_monitor_result",
)

endpoint_monitor_agent = LlmAgent(
    name="EndpointFeedMonitor",
    model=CLAUDE_MODEL,
    instruction="""You are an endpoint detection and response (EDR) agent monitoring
process, filesystem, and registry activity on a critical infrastructure network.

Use the read_endpoint_feed tool to get the latest endpoint events.

Analyze the events for:
- Dropper activity (executables written to temp directories)
- Persistence installation (registry Run keys, startup folder modifications)
- Credential access (LSASS dumps, SAM database reads)
- Process injection (unusual parent-child process relationships)
- Living-off-the-land attacks (LOLBins: powershell, wscript, mshta, regsvr32)

If you detect anything suspicious with severity HIGH or CRITICAL:
- Call flag_anomaly_for_escalation with a clear description

Return your findings as JSON:
{
  "anomalies_detected": int,
  "highest_severity": str,
  "summary": str,
  "flagged_events": [str]
}
""",
    description="Monitors endpoint events for dropper, persistence, and credential theft activity.",
    tools=[read_endpoint_feed, flag_anomaly_for_escalation],
    output_key="endpoint_monitor_result",
)

threat_intel_monitor_agent = LlmAgent(
    name="ThreatIntelFeedMonitor",
    model=CLAUDE_MODEL,
    instruction="""You are a threat intelligence analyst monitoring live threat feeds
for indicators relevant to critical infrastructure operators.

Use the read_threat_intel_feed tool to get the latest threat intelligence updates.

Analyze the feed for:
- New IOCs matching patterns seen in current environment
- Active campaign indicators (APT groups targeting energy sector)
- Zero-day or critical CVE exploitation reports
- Ransomware group activity targeting ICS/SCADA

If you identify HIGH or CRITICAL threat intelligence:
- Call flag_anomaly_for_escalation with clear attribution and TTPs

Return your findings as JSON:
{
  "new_threats": int,
  "active_campaigns_relevant": int,
  "highest_severity": str,
  "summary": str,
  "actionable_iocs": [str]
}
""",
    description="Monitors threat intelligence feeds for relevant APT activity and IOC updates.",
    tools=[read_threat_intel_feed, flag_anomaly_for_escalation],
    output_key="threat_intel_monitor_result",
)

# ── A2A Escalation Tool ────────────────────────────────────────────────────────
# In ADK 1.28, remote A2A connections use a function tool wrapping the A2A client.
# This is the correct pattern — RemoteA2aAgent does not exist as a class.

async def escalate_to_analysis_service(
    threat_description: str,
    severity: str,
    tool_context: ToolContext,
) -> dict:
    """
    Escalate a detected threat to the Analysis Service for deep analysis.
    Connects to the MalwareAnalysisPipeline running at localhost:8001 via A2A protocol.

    Args:
        threat_description: Clear description of what was detected
        severity: 'critical', 'high', 'medium', or 'low'
    """
    try:
        import httpx
        from a2a.client import A2AClient
        from a2a.types import Message, TextPart, Role

        async with httpx.AsyncClient(timeout=30.0) as http:
            client = A2AClient(httpx_client=http, url="http://localhost:8001")
            message = Message(
                role=Role.user,
                parts=[TextPart(text=f"Escalated threat (severity={severity}): {threat_description}")],
                messageId=f"monitoring-escalation-{severity}",
            )
            # Send message and collect response
            result = await client.send_message(message)
            return {
                "escalated": True,
                "analysis_service": "http://localhost:8001",
                "response_id": getattr(result, "id", "unknown"),
                "status": "submitted",
            }
    except Exception as exc:
        # A2A service not running — log and continue (demo mode)
        return {
            "escalated": False,
            "error": str(exc),
            "note": "Analysis service not reachable — start uvicorn analysis_service.agent:a2a_app --port 8001",
        }


# ── Triage Agent ───────────────────────────────────────────────────────────────
triage_agent = LlmAgent(
    name="TriageAgent",
    model=CLAUDE_MODEL,
    instruction="""You are the triage decision agent for a critical infrastructure
security operations center.

Network monitor findings: {network_monitor_result}
Endpoint monitor findings: {endpoint_monitor_result}
Threat intel findings: {threat_intel_monitor_result}
Pending anomaly: {pending_anomaly}

Your job: assess the combined findings and decide whether to escalate for deep analysis.

Escalation criteria:
- severity == 'critical' OR severity == 'high' → ALWAYS escalate
- Multiple medium-severity findings corroborating each other → escalate
- Single medium-severity finding with no corroboration → monitor, do not escalate

If escalating: call escalate_to_analysis_service with a clear description and severity.
This connects to the remote MalwareAnalysisPipeline via A2A protocol.

Return ONLY valid JSON:
{
  "decision": "escalate|monitor|dismiss",
  "severity": "critical|high|medium|low",
  "reasoning": str,
  "escalated": bool,
  "escalation_target": "analysis_service|none"
}
""",
    description="Triage agent: evaluates monitor findings and escalates confirmed threats via A2A.",
    tools=[escalate_to_analysis_service],
    output_key="triage_decision",
)

# ── Full Monitoring Pipeline ───────────────────────────────────────────────────
monitoring_pipeline = SequentialAgent(
    name="MonitoringOrchestratorAgent",
    sub_agents=[
        network_monitor_agent,
        endpoint_monitor_agent,
        threat_intel_monitor_agent,
        triage_agent,
    ],
    description=(
        "Continuous monitoring pipeline: reads network, endpoint, and threat intel feeds, "
        "then triages and escalates threats to the analysis service via A2A."
    ),
)

# ADK requires this exact variable name for adk web / adk api_server
root_agent = monitoring_pipeline
