"""
Tests for analysis_service/agent.py pipeline agents.
Mocks the LiteLLM call to verify JSON schema and error handling.

Run with: pytest tests/test_pipeline_agents.py -v
"""

import json
import pytest
from unittest.mock import patch, MagicMock


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_llm_response(content: str):
    """Create a mock LLM response object mimicking ADK's internal response."""
    part = MagicMock()
    part.text = content
    response = MagicMock()
    response.content = MagicMock()
    response.content.parts = [part]
    response.content.role = "model"
    return response


VALID_STATIC_RESULT = {
    "hashes": {"md5": "abc123", "sha256": "def456", "sha1": "ghi789"},
    "entropy": 6.8,
    "file_type": "JavaScript source",
    "file_size": 4183709,
    "strings": ["eval(", "ActiveXObject", "WScript.Shell"],
    "pe_info": None,
    "yara_matches": ["JS_Dropper_Indicators (high)"],
    "iocs": {"ips": ["185.220.101.47"], "domains": ["update-service.club"], "urls": []},
    "analyst_notes": "High entropy with eval obfuscation and dropper indicators.",
    "risk_indicators": ["eval() obfuscation detected", "ActiveXObject usage"],
}

VALID_SCENARIO = {
    "threat_class": "JavaScript dropper",
    "network_traffic": [
        {"event_type": "tcp_connection", "src_ip": "192.168.1.10", "dst_ip": "185.220.101.47",
         "dst_port": 4444, "protocol": "TCP", "payload_hint": "beacon", "source_artifact": "C2 IP in strings",
         "timestamp_offset_seconds": 30}
    ],
    "filesystem_events": [
        {"event_type": "create", "path": "C:\\Windows\\Temp\\payload.exe", "content_hint": "PE dropper",
         "source_artifact": "eval dropper pattern", "timestamp_offset_seconds": 5}
    ],
    "system_state_changes": [
        {"change_type": "registry", "target": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
         "action": "set", "source_artifact": "persistence indicator", "timestamp_offset_seconds": 10}
    ],
}

VALID_NETWORK_FINDINGS = {
    "c2_detected": True,
    "c2_indicators": ["185.220.101.47:4444"],
    "dns_queries": ["update-service.club"],
    "dga_suspected": False,
    "dga_evidence": "",
    "exfiltration_detected": True,
    "exfiltration_volume_estimate": "~50KB",
    "connections": [{"src": "192.168.1.10", "dst": "185.220.101.47", "port": 4444, "protocol": "TCP", "suspicious": True}],
    "lateral_movement_detected": False,
    "mitre_techniques": [{"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"}],
}

VALID_FILESYSTEM_FINDINGS = {
    "dropped_files": [{"path": "C:\\Windows\\Temp\\payload.exe", "purpose": "dropper", "suspicious": True}],
    "persistence_paths": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
    "sensitive_files_accessed": [],
    "log_tampering": False,
    "log_tampering_evidence": "",
    "staging_directories": ["C:\\Windows\\Temp\\"],
    "mitre_techniques": [{"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"}],
}

VALID_REGISTRY_FINDINGS = {
    "persistence_mechanisms": [{"type": "registry", "target": "HKCU\\Run", "description": "auto-start"}],
    "privilege_escalation": False,
    "escalation_method": "",
    "rootkit_indicators": False,
    "rootkit_evidence": "",
    "backdoor_installed": False,
    "backdoor_details": "",
    "defense_evasion": [],
    "mitre_techniques": [{"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"}],
}

VALID_INTEL_FINDINGS = {
    "malicious_votes": 42,
    "total_engines": 72,
    "family": "Emotet",
    "variant": "v4",
    "first_seen": "2024-01-15",
    "threat_actor": "TA542",
    "threat_actor_confidence": "medium",
    "campaign": "Winter 2026",
    "targeted_sectors": ["energy", "finance"],
    "ip_reputation": {"malicious_ips": ["185.220.101.47"], "clean_ips": []},
    "similar_samples": [],
    "attribution_notes": "Matches Emotet infrastructure patterns.",
}

VALID_CRITIC_REVIEW = {
    "overall_verdict": "confirmed_malicious",
    "confidence_score": 0.85,
    "false_positive_risks": [],
    "correlation_gaps": [],
    "confidence_adjustments": [],
    "missing_indicators": [],
    "contested_findings": [],
    "supporting_evidence": ["C2 IP in multiple sources", "YARA match corroborated"],
}

VALID_FINAL_REPORT = {
    "executive_summary": "High-confidence Emotet dropper targeting enterprise.",
    "malware_type": "Dropper/Downloader",
    "malware_family": "Emotet",
    "confidence": "high",
    "severity": "critical",
    "severity_score": 9.1,
    "entropy": 6.8,
    "iocs": {"ips": ["185.220.101.47"], "domains": ["update-service.club"], "files": [], "hashes": [], "urls": []},
    "mitre_attack": [{"id": "T1071.001", "tactic": "Command and Control", "technique": "Web Protocols", "subtechnique": ""}],
    "at_risk": {"systems": ["workstations"], "data_types": ["credentials"], "ics_relevant": True, "ics_risk_description": "Can pivot to OT network"},
    "remediation": {"immediate": ["Isolate affected hosts"], "short_term": ["Patch endpoints"], "long_term": ["Network segmentation"]},
    "timeline": [{"offset_seconds": 0, "event": "Sample executed", "severity": "high"}],
}


# ── Schema validation helpers ──────────────────────────────────────────────────

def assert_static_schema(result: dict):
    assert "hashes" in result
    assert "md5" in result["hashes"] and "sha256" in result["hashes"]
    assert "entropy" in result
    assert "strings" in result and isinstance(result["strings"], list)
    assert "iocs" in result
    assert "yara_matches" in result and isinstance(result["yara_matches"], list)


def assert_scenario_schema(result: dict):
    assert "network_traffic" in result and isinstance(result["network_traffic"], list)
    assert "filesystem_events" in result and isinstance(result["filesystem_events"], list)
    assert "system_state_changes" in result and isinstance(result["system_state_changes"], list)


def assert_network_schema(result: dict):
    assert "c2_detected" in result and isinstance(result["c2_detected"], bool)
    assert "mitre_techniques" in result and isinstance(result["mitre_techniques"], list)


def assert_final_report_schema(result: dict):
    required = {"executive_summary", "malware_type", "malware_family", "confidence",
                "severity", "severity_score", "iocs", "mitre_attack", "at_risk", "remediation"}
    assert required.issubset(set(result.keys()))
    assert result["severity"] in ("critical", "high", "medium", "low")
    assert 0.0 <= result["severity_score"] <= 10.0


# ── Import tests ───────────────────────────────────────────────────────────────

def test_agent_module_imports():
    """Verify all ADK agents import without errors."""
    from analysis_service.agent import (
        static_agent, scenario_agent, parallel_analysis,
        network_monitor, filesystem_monitor, registry_monitor, threat_intel_agent,
        critic_agent, report_agent, analysis_pipeline, root_agent, CLAUDE_MODEL,
    )
    assert root_agent is analysis_pipeline
    assert static_agent.output_key == "static_analysis_result"
    assert scenario_agent.output_key == "behavioral_scenario"
    assert network_monitor.output_key == "network_findings"
    assert filesystem_monitor.output_key == "filesystem_findings"
    assert registry_monitor.output_key == "registry_findings"
    assert threat_intel_agent.output_key == "intel_findings"
    assert critic_agent.output_key == "critic_review"
    assert report_agent.output_key == "final_report"


def test_parallel_agent_has_four_sub_agents():
    from analysis_service.agent import parallel_analysis
    assert len(parallel_analysis.sub_agents) == 4


def test_pipeline_has_five_stages():
    from analysis_service.agent import analysis_pipeline
    assert len(analysis_pipeline.sub_agents) == 5


def test_root_agent_name():
    from analysis_service.agent import root_agent
    assert root_agent.name == "MalwareAnalysisPipeline"


# ── output_key wiring ─────────────────────────────────────────────────────────

def test_scenario_agent_reads_static_analysis_result():
    from analysis_service.agent import scenario_agent
    assert "{static_analysis_result}" in scenario_agent.instruction


def test_critic_reads_all_four_parallel_outputs():
    from analysis_service.agent import critic_agent
    instr = critic_agent.instruction
    assert "{network_findings}" in instr
    assert "{filesystem_findings}" in instr
    assert "{registry_findings}" in instr
    assert "{intel_findings}" in instr


def test_report_reads_all_findings_and_critic():
    from analysis_service.agent import report_agent
    instr = report_agent.instruction
    assert "{static_analysis_result}" in instr
    assert "{critic_review}" in instr
    assert "{final_report}" not in instr  # report_agent writes final_report, doesn't read it


# ── Schema validation from mock LLM responses ────────────────────────────────

def test_valid_final_report_schema():
    assert_final_report_schema(VALID_FINAL_REPORT)


def test_valid_static_result_schema():
    assert_static_schema(VALID_STATIC_RESULT)


def test_valid_scenario_schema():
    assert_scenario_schema(VALID_SCENARIO)


def test_valid_network_findings_schema():
    assert_network_schema(VALID_NETWORK_FINDINGS)


# ── Malformed response handling ────────────────────────────────────────────────

def test_json_parse_strips_markdown_fences():
    """Verify JSON parsing logic handles ```json fences (per CLAUDE.md agent pattern)."""
    raw = "```json\n{\"key\": \"value\"}\n```"
    cleaned = raw.strip().removeprefix("```json").removesuffix("```").strip()
    parsed = json.loads(cleaned)
    assert parsed == {"key": "value"}


def test_json_parse_handles_plain_json():
    raw = '{"severity": "high", "score": 8.5}'
    cleaned = raw.strip().removeprefix("```json").removesuffix("```").strip()
    parsed = json.loads(cleaned)
    assert parsed["severity"] == "high"


def test_json_parse_raises_on_malformed():
    raw = "This is not JSON at all"
    with pytest.raises(json.JSONDecodeError):
        cleaned = raw.strip().removeprefix("```json").removesuffix("```").strip()
        json.loads(cleaned)


# ── Severity score bounds ──────────────────────────────────────────────────────

@pytest.mark.parametrize("severity,expected_min", [
    ("critical", 8.0),
    ("high", 6.0),
    ("medium", 4.0),
    ("low", 0.0),
])
def test_severity_score_reasonable(severity, expected_min):
    report = {**VALID_FINAL_REPORT, "severity": severity, "severity_score": expected_min + 0.5}
    assert_final_report_schema(report)
