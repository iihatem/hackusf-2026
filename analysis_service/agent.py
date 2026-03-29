"""
MalwareScope — Analysis Service
Layer 2: Deep analysis pipeline exposed via A2A on port 8001.

Start with:
    uvicorn analysis_service.agent:a2a_app --host 0.0.0.0 --port 8001

The pipeline:
    StaticAnalysisAgent → ScenarioBuilderAgent
        → ParallelAgent[NetworkMonitor, FilesystemMonitor, RegistryMonitor, ThreatIntel]
        → CriticAgent → ReportWriterAgent
"""

import os
from dotenv import load_dotenv

load_dotenv()

from google.adk.agents import LlmAgent, SequentialAgent, ParallelAgent
from google.adk.models.lite_llm import LiteLlm

# NOTE: to_a2a import path is google.adk.a2a.utils.agent_to_a2a as of ADK 0.5.x
# If this import fails, check: https://google.github.io/adk-docs/
try:
    from google.adk.a2a.utils.agent_to_a2a import to_a2a
except ImportError:
    try:
        from google.adk.a2a import to_a2a  # alternate path in some versions
    except ImportError:
        to_a2a = None  # A2A optional — pipeline still works standalone

CLAUDE_MODEL = LiteLlm(model="anthropic/claude-opus-4-5")

# ── Static Analysis Agent ──────────────────────────────────────────────────────
# Receives raw_static_data (pre-computed by static_analyzer.py, injected into
# session state by the API before the pipeline runs). Formats it into the
# canonical static_analysis_result schema used by downstream agents.
static_agent = LlmAgent(
    name="StaticAnalysisAgent",
    model=CLAUDE_MODEL,
    instruction="""You are an expert malware binary analyst. You have been given
pre-computed static analysis artifacts for a suspicious file. Your job is to
interpret these artifacts and produce a structured threat assessment.

Raw static analysis data:
{raw_static_data}

Analyze the data above. Pay special attention to:
- Entropy values above 7.0 (packed/encrypted payloads)
- YARA rule matches and what they indicate
- Suspicious string patterns (obfuscation, evasion, C2 URLs, registry keys)
- PE header anomalies (if present): mismatched timestamps, unusual sections, suspicious imports
- Extracted IOCs (IPs, domains, URLs)
- File type vs. filename mismatch (e.g., PE disguised as PDF)

Return ONLY valid JSON with exactly these keys:
{
  "hashes": {"md5": str, "sha256": str, "sha1": str},
  "entropy": float,
  "file_type": str,
  "file_size": int,
  "strings": [str],
  "pe_info": dict_or_null,
  "yara_matches": [str],
  "iocs": {"ips": [str], "domains": [str], "urls": [str]},
  "analyst_notes": str,
  "risk_indicators": [str]
}

analyst_notes should be 2-3 sentences summarizing the most suspicious findings.
risk_indicators should list specific artifacts that raise concern (e.g., "eval() obfuscation detected", "C2 URL pattern in strings").

IMPORTANT: For the "strings" key output, include ONLY the 10-15 most suspicious or interesting strings.
Do NOT echo back benign or redundant strings. Keep all string values under 80 characters.
Keep your entire JSON response under 800 tokens.
""",
    description="Interprets pre-computed static artifacts and produces structured threat assessment.",
    output_key="static_analysis_result",
)

# ── Scenario Builder Agent ─────────────────────────────────────────────────────
# Projects realistic behavioral simulation from static artifacts.
scenario_agent = LlmAgent(
    name="ScenarioBuilderAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a malware behavior simulation expert specializing in
critical infrastructure threats (ICS/SCADA, energy sector, industrial control systems).

Static analysis results:
{static_analysis_result}

Based ONLY on artifacts present in the static analysis, project a realistic behavioral
scenario for what would happen if this sample executed in an enterprise environment.

Every event you generate MUST cite a specific artifact from the static analysis
(use the "source_artifact" field). Do not invent behaviors not grounded in the evidence.

Return ONLY valid JSON with exactly these keys:
{
  "threat_class": str,
  "network_traffic": [
    {
      "event_type": str,
      "src_ip": str,
      "dst_ip": str,
      "dst_port": int,
      "protocol": str,
      "payload_hint": str,
      "source_artifact": str,
      "timestamp_offset_seconds": int
    }
  ],
  "filesystem_events": [
    {
      "event_type": "create|modify|delete|read",
      "path": str,
      "content_hint": str,
      "source_artifact": str,
      "timestamp_offset_seconds": int
    }
  ],
  "system_state_changes": [
    {
      "change_type": "registry|service|scheduled_task|process|privilege",
      "target": str,
      "action": str,
      "source_artifact": str,
      "timestamp_offset_seconds": int
    }
  ]
}

Generate exactly 5 network events, 5 filesystem events, and 5 system state changes — no more.
Keep all string field values under 60 characters. Keep your entire JSON response under 1000 tokens.
""",
    description="Projects behavioral simulation from static artifacts, grounded in evidence.",
    output_key="behavioral_scenario",
)

# ── Parallel Analysis Agents ───────────────────────────────────────────────────
# These four agents run SIMULTANEOUSLY because they are independent analyses.
# They each read from behavioral_scenario and static_analysis_result but
# do not depend on each other's output.

network_monitor = LlmAgent(
    name="NetworkMonitorAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a network forensics specialist focused on malware C2 detection.

Behavioral scenario (simulated traffic):
{behavioral_scenario}

Static analysis results (for cross-referencing IOCs):
{static_analysis_result}

Analyze the simulated network traffic. Identify:
- C2 communication patterns (beaconing intervals, heartbeat)
- DNS-based command and control or DGA (domain generation algorithm)
- Data exfiltration attempts (large outbound payloads, encoded data)
- Lateral movement (internal network connections, SMB, RPC)
- MITRE ATT&CK techniques observed in the traffic

Return ONLY valid JSON with exactly these keys:
{
  "c2_detected": bool,
  "c2_indicators": [str],
  "dns_queries": [str],
  "dga_suspected": bool,
  "dga_evidence": str,
  "exfiltration_detected": bool,
  "exfiltration_volume_estimate": str,
  "connections": [{"src": str, "dst": str, "port": int, "protocol": str, "suspicious": bool}],
  "lateral_movement_detected": bool,
  "mitre_techniques": [{"id": str, "name": str, "tactic": str}]
}

Keep lists to 5 items max. Keep all string values under 80 chars. Keep total JSON under 600 tokens.
""",
    description="Analyzes simulated network traffic for C2, exfiltration, and lateral movement.",
    output_key="network_findings",
)

filesystem_monitor = LlmAgent(
    name="FilesystemMonitorAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a malware filesystem behavior analyst specializing in
dropper and persistence detection.

Behavioral scenario (simulated filesystem events):
{behavioral_scenario}

Static analysis results:
{static_analysis_result}

Analyze the simulated filesystem activity. Identify:
- Dropped payloads (files written to temp, appdata, system directories)
- Persistence mechanisms (startup folders, scheduled tasks created as files)
- Credential access (LSASS dumps, SAM database reads, browser credential files)
- Log tampering (event log clearing, audit log deletion)
- Staging directories (temp exfil staging, encrypted payload storage)

Return ONLY valid JSON with exactly these keys:
{
  "dropped_files": [{"path": str, "purpose": str, "suspicious": bool}],
  "persistence_paths": [str],
  "sensitive_files_accessed": [{"path": str, "reason": str}],
  "log_tampering": bool,
  "log_tampering_evidence": str,
  "staging_directories": [str],
  "mitre_techniques": [{"id": str, "name": str, "tactic": str}]
}

Keep lists to 5 items max. Keep all string values under 80 chars. Keep total JSON under 600 tokens.
""",
    description="Analyzes simulated filesystem events for dropper and persistence behavior.",
    output_key="filesystem_findings",
)

registry_monitor = LlmAgent(
    name="RegistryMonitorAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a system persistence and privilege escalation analyst.

Behavioral scenario (simulated system state changes):
{behavioral_scenario}

Static analysis results:
{static_analysis_result}

Analyze the simulated system state changes. Identify:
- Registry-based persistence (Run keys, Services, COM hijacking)
- Privilege escalation techniques (token impersonation, UAC bypass, DLL injection)
- Rootkit indicators (driver installation, SSDT hooks, hidden processes)
- Backdoor installation (SSH keys added, remote access tools deployed)
- Defense evasion (AV/EDR disabling, firewall rule changes)

Return ONLY valid JSON with exactly these keys:
{
  "persistence_mechanisms": [{"type": str, "target": str, "description": str}],
  "privilege_escalation": bool,
  "escalation_method": str,
  "rootkit_indicators": bool,
  "rootkit_evidence": str,
  "backdoor_installed": bool,
  "backdoor_details": str,
  "defense_evasion": [str],
  "mitre_techniques": [{"id": str, "name": str, "tactic": str}]
}

Keep lists to 5 items max. Keep all string values under 80 chars. Keep total JSON under 600 tokens.
""",
    description="Analyzes system state changes for persistence, privesc, and rootkit indicators.",
    output_key="registry_findings",
)

threat_intel_agent = LlmAgent(
    name="ThreatIntelAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a threat intelligence analyst with access to historical
malware campaign data and threat actor profiles.

Static analysis results (with hashes and IOCs):
{static_analysis_result}

Cross-reference the artifacts against known threat intelligence. Based on the
hashes, IOC patterns, behavior indicators, and YARA matches, identify:
- Known malware families this sample resembles
- Threat actor or APT group attribution possibilities
- Campaign indicators (infrastructure patterns, naming conventions, code signatures)
- Historical context (when similar samples were first seen, targeted sectors)

If exact matches cannot be confirmed, use "Unknown" or "Suspected" with reasoning.
Note: VirusTotal and AbuseIPDB data is simulated based on the artifacts provided.

Return ONLY valid JSON with exactly these keys:
{
  "malicious_votes": int,
  "total_engines": int,
  "family": str,
  "variant": str,
  "first_seen": str,
  "threat_actor": str,
  "threat_actor_confidence": str,
  "campaign": str,
  "targeted_sectors": [str],
  "ip_reputation": {"malicious_ips": [str], "clean_ips": [str]},
  "similar_samples": [str],
  "attribution_notes": str
}

Keep lists to 5 items max. Keep all string values under 100 chars. Keep total JSON under 600 tokens.
""",
    description="Correlates findings against threat intelligence databases and attribution.",
    output_key="intel_findings",
)

# ParallelAgent — all four run simultaneously
parallel_analysis = ParallelAgent(
    name="ParallelAnalysisAgents",
    sub_agents=[network_monitor, filesystem_monitor, registry_monitor, threat_intel_agent],
    description="Runs four specialist analysis agents concurrently — network, filesystem, registry, and threat intel.",
)

# ── Critic Agent ───────────────────────────────────────────────────────────────
critic_agent = LlmAgent(
    name="CriticAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a skeptical red-team analyst whose job is to reduce
false positives and ensure analytical rigor.

Network findings:
{network_findings}

Filesystem findings:
{filesystem_findings}

Registry/System findings:
{registry_findings}

Threat intel findings:
{intel_findings}

Challenge every finding. Look for:
- False positive risks (benign software with similar patterns)
- Correlation gaps (e.g., C2 detected but no dropper — how did it get there?)
- Missing expected indicators (e.g., ransomware without encryption activity)
- Alternative benign explanations for each key finding
- Inconsistencies between agents (e.g., intel says APT28 but TTPs don't match)
- Confidence levels that are too high given the evidence quality

Return ONLY valid JSON with exactly these keys:
{
  "overall_verdict": "confirmed_malicious|likely_malicious|uncertain|likely_benign",
  "confidence_score": float,
  "false_positive_risks": [str],
  "correlation_gaps": [str],
  "confidence_adjustments": [{"finding": str, "original_confidence": str, "adjusted_confidence": str, "reason": str}],
  "missing_indicators": [str],
  "contested_findings": [str],
  "supporting_evidence": [str]
}

Keep every list to 4 items max. Keep all string values under 100 chars.
Keep your entire JSON response under 700 tokens.
""",
    description="Cross-validates all agent findings, identifies false positive risks and correlation gaps.",
    output_key="critic_review",
)

# ── Report Writer Agent ────────────────────────────────────────────────────────
report_agent = LlmAgent(
    name="ReportWriterAgent",
    model=CLAUDE_MODEL,
    instruction="""You are a senior cybersecurity analyst writing an executive threat report
for a critical infrastructure operator (energy sector / ICS/SCADA environment).

All findings:

Static analysis: {static_analysis_result}
Network analysis: {network_findings}
Filesystem analysis: {filesystem_findings}
Registry/System analysis: {registry_findings}
Threat intelligence: {intel_findings}
Critic review: {critic_review}

Synthesize ALL findings into a final threat report. Incorporate the critic's confidence
adjustments. Note contested findings. Weight the report toward what is certain.

Return ONLY valid JSON with exactly these keys:
{
  "executive_summary": str,
  "malware_type": str,
  "malware_family": str,
  "confidence": "high|medium|low",
  "severity": "critical|high|medium|low",
  "severity_score": float,
  "entropy": float,
  "iocs": {
    "ips": [str],
    "domains": [str],
    "files": [str],
    "hashes": [str],
    "urls": [str]
  },
  "mitre_attack": [{"id": str, "tactic": str, "technique": str, "subtechnique": str}],
  "at_risk": {
    "systems": [str],
    "data_types": [str],
    "ics_relevant": bool,
    "ics_risk_description": str
  },
  "remediation": {
    "immediate": [str],
    "short_term": [str],
    "long_term": [str]
  },
  "timeline": [{"offset_seconds": int, "event": str, "severity": str}]
}

executive_summary: 3-4 sentences for a CISO. Lead with severity and immediate risk.
severity_score: 0.0-10.0 (0=clean, 10=critical infrastructure attack).

Keep every list to 5 items max. Keep all string values under 120 chars.
Keep your entire JSON response under 1200 tokens.
""",
    description="Synthesizes all findings into final threat report for critical infrastructure operators.",
    output_key="final_report",
)

# ── Full Pipeline ──────────────────────────────────────────────────────────────
analysis_pipeline = SequentialAgent(
    name="MalwareAnalysisPipeline",
    sub_agents=[
        static_agent,
        scenario_agent,
        parallel_analysis,  # NetworkMonitor + Filesystem + Registry + ThreatIntel (concurrent)
        critic_agent,
        report_agent,
    ],
    description=(
        "Complete malware analysis pipeline: static → scenario → parallel forensics "
        "→ critic → final report. Specialized for critical infrastructure threat assessment."
    ),
)

# ADK requires this exact variable name for adk web / adk api_server
root_agent = analysis_pipeline

# Expose via A2A so the response service and monitoring service can call it
if to_a2a is not None:
    a2a_app = to_a2a(root_agent, port=8001)
else:
    # Fallback: standalone FastAPI app stub (A2A not installed)
    from fastapi import FastAPI
    a2a_app = FastAPI(title="MalwareScope Analysis Service")

    @a2a_app.get("/health")
    def health():
        return {"status": "ok", "note": "A2A not available — install google-adk[a2a]"}
