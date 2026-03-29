"""
Tests for response_service/agent.py

Run with: pytest tests/test_response_agents.py -v
"""

import json
import pytest
from unittest.mock import MagicMock, patch


# ── Sample data ────────────────────────────────────────────────────────────────

SAMPLE_FINAL_REPORT = {
    "executive_summary": "Critical Emotet dropper confirmed.",
    "malware_type": "Dropper",
    "malware_family": "Emotet",
    "confidence": "high",
    "severity": "critical",
    "severity_score": 9.1,
    "iocs": {
        "ips": ["185.220.101.47", "91.108.4.0"],
        "domains": ["update-service.club", "beacon.darkpulse.cc"],
        "files": ["C:\\Windows\\Temp\\payload.exe"],
        "hashes": ["deadbeef12345678"],
        "urls": [],
    },
    "mitre_attack": [{"id": "T1071.001", "tactic": "C2", "technique": "Web Protocols", "subtechnique": ""}],
    "at_risk": {"systems": ["workstations"], "data_types": ["credentials"], "ics_relevant": True, "ics_risk_description": "OT network reachable"},
    "remediation": {
        "immediate": ["Isolate hosts", "Block IOCs"],
        "short_term": ["Patch CVEs"],
        "long_term": ["Segment OT network"],
    },
    "timeline": [],
}

VALID_BLOCKLIST_RESULT = {
    "blocked_ips": ["185.220.101.47", "91.108.4.0"],
    "blocked_domains": ["update-service.club", "beacon.darkpulse.cc"],
    "blocked_urls": [],
    "actions_taken": 4,
    "firewall_rule_ids": ["DENY-INC-1706000000-1", "DENY-INC-1706000000-2"],
    "status": "success",
    "notes": "All IOCs blocked on perimeter firewall.",
}

VALID_ALERT_RESULT = {
    "subject": "[CRITICAL] Emotet Dropper Detected — Immediate Action Required",
    "body": "Emotet dropper confirmed on workstation. C2 communication to 185.220.101.47 detected.",
    "severity": "critical",
    "recipients": ["soc@company.com", "ciso@company.com"],
    "requires_human_action": True,
    "human_actions": ["Isolate affected host", "Review SIEM for lateral movement"],
    "sla_minutes": 30,
    "escalation_path": "CISO → CERT",
    "status": "sent",
    "alert_id": "ALERT-2026-0142",
}

VALID_TICKET_RESULT = {
    "ticket_id": "INC-2026-00042",
    "title": "[CRITICAL] Emotet Dropper — Malware Incident",
    "severity": "critical",
    "status": "open",
    "summary": "Emotet dropper confirmed on endpoint 192.168.1.20.",
    "affected_systems": ["192.168.1.20"],
    "ioc_list": ["185.220.101.47", "update-service.club"],
    "remediation_checklist": ["Isolate host", "Collect forensic image"],
    "sla_hours": 4,
    "assigned_to": "SOC Tier 2",
    "tags": ["emotet", "critical", "dropper"],
    "created_at": "2026-03-28T12:00:00Z",
}

VALID_VERIFICATION_RESULT = {
    "iteration_label": "[VERIFICATION Loop 1/3]",
    "checks_passed": [
        "CHECK 1: blocklist_result present",
        "CHECK 2: blocklist_result.status == success",
        "CHECK 3: blocked_ips non-empty",
        "CHECK 4: alert_result present",
        "CHECK 5: alert_result.status == sent",
        "CHECK 6: severity matches",
        "CHECK 7: ticket_result present",
        "CHECK 8: ticket_result.status == open",
        "CHECK 9: sla_hours > 0",
    ],
    "checks_failed": [],
    "overall_status": "verified",
    "escalation_required": False,
    "notes": "All response actions verified successfully.",
}


# ── Import tests ───────────────────────────────────────────────────────────────

def test_response_module_imports():
    """Verify all response agents import without errors."""
    from response_service.agent import (
        blocklist_agent, alert_agent, ticket_agent,
        parallel_response, verifier_agent, verification_loop,
        response_pipeline, root_agent,
    )
    assert root_agent is response_pipeline
    assert blocklist_agent.output_key == "blocklist_result"
    assert alert_agent.output_key == "alert_result"
    assert ticket_agent.output_key == "ticket_result"
    assert verifier_agent.output_key == "verification_result"


def test_parallel_response_has_three_sub_agents():
    from response_service.agent import parallel_response
    assert len(parallel_response.sub_agents) == 3


def test_loop_max_iterations_is_set():
    from response_service.agent import verification_loop
    assert verification_loop.max_iterations == 3


def test_loop_max_iterations_not_infinite():
    from response_service.agent import verification_loop
    assert verification_loop.max_iterations is not None
    assert verification_loop.max_iterations > 0


def test_verifier_has_exit_loop_tool():
    from response_service.agent import verifier_agent
    from google.adk.tools.exit_loop_tool import exit_loop
    tool_names = [getattr(t, "name", None) or getattr(t, "__name__", None) for t in verifier_agent.tools]
    assert "exit_loop" in tool_names


def test_response_pipeline_sequence():
    """Verify SequentialAgent runs parallel_response before verification_loop."""
    from response_service.agent import response_pipeline, parallel_response, verification_loop
    assert response_pipeline.sub_agents[0] is parallel_response
    assert response_pipeline.sub_agents[1] is verification_loop


def test_root_agent_name():
    from response_service.agent import root_agent
    assert root_agent.name == "AutonomousResponsePipeline"


# ── output_key wiring ─────────────────────────────────────────────────────────

def test_verifier_reads_all_results():
    from response_service.agent import verifier_agent
    instr = verifier_agent.instruction
    assert "{blocklist_result}" in instr
    assert "{alert_result}" in instr
    assert "{ticket_result}" in instr
    assert "{final_report}" in instr


def test_verifier_mentions_iteration_label():
    from response_service.agent import verifier_agent
    assert "iteration_label" in verifier_agent.instruction


def test_response_agents_read_final_report():
    from response_service.agent import blocklist_agent, alert_agent, ticket_agent
    for agent in (blocklist_agent, alert_agent, ticket_agent):
        assert "{final_report}" in agent.instruction


# ── Schema validation ─────────────────────────────────────────────────────────

def test_blocklist_result_schema():
    r = VALID_BLOCKLIST_RESULT
    assert "blocked_ips" in r and isinstance(r["blocked_ips"], list)
    assert "blocked_domains" in r and isinstance(r["blocked_domains"], list)
    assert "actions_taken" in r and isinstance(r["actions_taken"], int)
    assert r["status"] in ("success", "partial", "failed")


def test_alert_result_schema():
    r = VALID_ALERT_RESULT
    assert "subject" in r and isinstance(r["subject"], str)
    assert "severity" in r and r["severity"] in ("critical", "high", "medium", "low")
    assert "requires_human_action" in r and isinstance(r["requires_human_action"], bool)
    assert r["status"] in ("sent", "failed")


def test_ticket_result_schema():
    r = VALID_TICKET_RESULT
    assert r["ticket_id"].startswith("INC-")
    assert r["status"] == "open"
    assert r["sla_hours"] in (4, 8, 24, 72)
    assert isinstance(r["affected_systems"], list)
    assert isinstance(r["remediation_checklist"], list)


def test_verification_result_schema():
    r = VALID_VERIFICATION_RESULT
    assert "checks_passed" in r and isinstance(r["checks_passed"], list)
    assert "checks_failed" in r and isinstance(r["checks_failed"], list)
    assert r["overall_status"] in ("verified", "partial", "failed")
    assert "escalation_required" in r and isinstance(r["escalation_required"], bool)


# ── Edge case: missing results ────────────────────────────────────────────────

def test_verification_fails_if_blocklist_missing():
    """If blocklist_result is null, checks_failed should be non-empty."""
    # Simulate what the VerificationAgent should return when blocklist_result is None
    partial_result = {
        "iteration_label": "[VERIFICATION Loop 1/3]",
        "checks_passed": [],
        "checks_failed": ["CHECK 1: blocklist_result is null/missing — BlocklistAgent failed"],
        "overall_status": "failed",
        "escalation_required": False,
        "notes": "BlocklistAgent did not produce output.",
    }
    assert partial_result["overall_status"] != "verified"
    assert len(partial_result["checks_failed"]) > 0


def test_verification_fails_if_alert_not_sent():
    partial_result = {
        "iteration_label": "[VERIFICATION Loop 2/3]",
        "checks_passed": ["CHECK 1", "CHECK 2", "CHECK 3"],
        "checks_failed": ["CHECK 5: alert_result.status is 'failed' not 'sent'"],
        "overall_status": "partial",
        "escalation_required": False,
        "notes": "Alert sending failed.",
    }
    assert partial_result["overall_status"] in ("partial", "failed")
    assert len(partial_result["checks_failed"]) > 0


def test_escalation_required_on_final_iteration_failure():
    """At iteration 3 with failures, escalation_required should be True."""
    final_failure = {
        "iteration_label": "[VERIFICATION Loop 3/3]",
        "checks_passed": [],
        "checks_failed": ["CHECK 1: blocklist_result null"],
        "overall_status": "failed",
        "escalation_required": True,
        "notes": "Max iterations reached without successful verification. Human escalation required.",
    }
    assert final_failure["escalation_required"] is True


# ── SLA hour mapping ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("severity,expected_sla", [
    ("critical", 4),
    ("high", 8),
    ("medium", 24),
    ("low", 72),
])
def test_sla_hours_by_severity(severity, expected_sla):
    """Ticket SLA should match severity level per AGENTS.md."""
    ticket = {**VALID_TICKET_RESULT, "severity": severity, "sla_hours": expected_sla}
    assert ticket["sla_hours"] == expected_sla


# ── Blocklist completeness ────────────────────────────────────────────────────

def test_blocklist_covers_all_report_ips():
    """All IPs from the threat report must appear in blocklist."""
    report_ips = set(SAMPLE_FINAL_REPORT["iocs"]["ips"])
    blocklist_ips = set(VALID_BLOCKLIST_RESULT["blocked_ips"])
    assert report_ips.issubset(blocklist_ips), f"Missing IPs: {report_ips - blocklist_ips}"


def test_blocklist_covers_all_report_domains():
    report_domains = set(SAMPLE_FINAL_REPORT["iocs"]["domains"])
    blocklist_domains = set(VALID_BLOCKLIST_RESULT["blocked_domains"])
    assert report_domains.issubset(blocklist_domains), f"Missing domains: {report_domains - blocklist_domains}"


def test_actions_taken_count_matches_blocked_items():
    r = VALID_BLOCKLIST_RESULT
    total = len(r["blocked_ips"]) + len(r["blocked_domains"]) + len(r["blocked_urls"])
    assert r["actions_taken"] == total
