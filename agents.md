# Agent Schemas

## StaticAgent

Input: {"file_path": str}
Output: {"hashes": {"md5": str, "sha256": str}, "entropy": float,
"strings": [str], "pe_info": dict|null, "yara": [str],
"file_size": int, "file_type": str}

## ScenarioBuilder

Input: static_agent output
Output: {"network_traffic": [...], "filesystem_events": [...],
"system_state_changes": [...]}

## NetworkMonitorAgent

Input: {"simulated_traffic": [...], "static_artifacts": {...}}
Output: {"c2_detected": bool, "c2_indicators": [...],
"dns_queries": [...], "dga_suspected": bool,
"exfiltration_detected": bool, "connections": [...],
"mitre_techniques": [...]}

## FilesystemAgent

Input: {"filesystem_events": [...], "static_artifacts": {...}}
Output: {"dropped_files": [...], "persistence_paths": [...],
"sensitive_files_accessed": [...], "log_tampering": bool,
"mitre_techniques": [...]}

## RegistryAgent

Input: {"system_state_changes": [...], "static_artifacts": {...}}
Output: {"persistence_mechanisms": [...], "privilege_escalation": bool,
"rootkit_indicators": bool, "mitre_techniques": [...]}

## ThreatIntelAgent

Input: {"hashes": {...}, "ips": [...], "domains": [...]}
Output: {"malicious_votes": int, "total_engines": int,
"family": str, "first_seen": str, "ip_reputation": {...}}

## CriticAgent

Input: {"static": {...}, "network": {...}, "filesystem": {...},
"registry": {...}, "intel": {...}}
Output: {"overall_verdict": str, "false_positive_risks": [...],
"confidence_adjustments": [...], "missing_indicators": [...]}

## ReportAgent

Input: {"all_agent_findings": {...}, "critique": {...}}
Output: {"executive_summary": str, "malware_type": str,
"malware_family": str, "confidence": str,
"severity": str, "severity_score": float,
"entropy": float, "iocs": {...}, "mitre_attack": [...],
"at_risk": {...}, "remediation": {...}}

## BlocklistAgent

Input: report_agent output
Output: {"blocked_ips": [...], "blocked_domains": [...],
"actions_taken": int, "status": str}

## AlertAgent

Input: report_agent output
Output: {"subject": str, "body": str, "severity": str,
"requires_human_action": bool, "status": str}

## TicketAgent

Input: report_agent output + triage context
Output: {"ticket_id": str, "title": str, "status": str}
