#!/usr/bin/env python3
"""
FastAPI server connecting the malware analysis pipeline to the Snowflake RAG chat frontend.

Endpoints:
    POST /analyze       — Start analysis pipeline (runs in background)
    GET  /status/{id}   — Check analysis status
    GET  /report/{id}   — Get the analysis report
    POST /chat          — RAG chat (Snowflake + Claude)

Run:
    pip install fastapi uvicorn python-dotenv anthropic snowflake-connector-python cryptography
    uvicorn api_server:app --port 8001 --reload
"""

import asyncio
import json
import os
import uuid
import time
import logging
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
load_dotenv("snowflake_chat_integration/.env")
load_dotenv("malwarescope/.env")

from fastapi import FastAPI, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Import chat router and snowflake tools
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "snowflake_chat_integration", "backend"))
from chat_router import create_chat_router, ingest_job
from snowflake_tools import store_findings_in_snowflake, similarity_search

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="MalwareScope API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Job storage
jobs: dict = {}

# Mount the chat router
app.include_router(create_chat_router(jobs))

WORKSPACE = os.path.abspath("workspace")
SAMPLE_NAME = "6108674530.JS.malicious"


# ---------- Request/Response Models ----------

class AnalyzeRequest(BaseModel):
    sample_path: Optional[str] = None  # defaults to the pre-loaded sample


class ChatRequest(BaseModel):
    job_id: str
    question: str


# ---------- Background Analysis Runner ----------

def run_analysis(job_id: str, sample_path: str):
    """Run the fallback pipeline in a subprocess and capture results."""
    jobs[job_id]["status"] = "running"
    jobs[job_id]["started_at"] = time.time()

    try:
        import subprocess
        # Find the python executable — prefer .venv, fallback to sys.executable
        venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv", "bin", "python")
        python_exe = venv_python if os.path.exists(venv_python) else sys.executable
        result = subprocess.run(
            [python_exe, "fallback_pipeline.py"],
            capture_output=True, text=True, timeout=600,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env={**os.environ, "SAMPLE_NAME": sample_path},
        )

        jobs[job_id]["pipeline_stdout"] = result.stdout[-5000:] if result.stdout else ""
        jobs[job_id]["pipeline_stderr"] = result.stderr[-2000:] if result.stderr else ""

        # Read the findings files
        findings_path = os.path.join(WORKSPACE, "findings.txt")
        deep_path = os.path.join(WORKSPACE, "deep_findings.txt")

        findings = ""
        if os.path.exists(findings_path):
            with open(findings_path) as f:
                findings = f.read()
        if os.path.exists(deep_path):
            with open(deep_path) as f:
                findings += "\n\n--- Deep Analysis ---\n\n" + f.read()

        if not findings:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = "Pipeline produced no findings"
            return

        # Build a report dict from the findings text
        report = build_report_from_findings(findings, job_id)

        jobs[job_id]["status"] = "complete"
        jobs[job_id]["result"] = report
        jobs[job_id]["findings_raw"] = findings
        jobs[job_id]["completed_at"] = time.time()

        # Extract SHA256 from triage
        triage_path = os.path.join(WORKSPACE, "triage.json")
        if os.path.exists(triage_path):
            with open(triage_path) as f:
                triage = json.load(f)
            hashes_str = triage.get("hashes", "")
            sha256 = ""
            for line in hashes_str.split("\n"):
                if line.startswith("sha256:"):
                    sha256 = line.split(":")[1].strip()
            if sha256:
                jobs[job_id].setdefault("progress", {}).setdefault("static", {}).setdefault("findings", {}).setdefault("hashes", {})["sha256"] = sha256

        # Ingest into Snowflake for RAG chat
        try:
            ingest_job(job_id, jobs)
            log.info(f"[{job_id}] Ingested into Snowflake")
        except Exception as e:
            log.warning(f"[{job_id}] Snowflake ingestion failed (non-fatal): {e}")

    except subprocess.TimeoutExpired:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = "Pipeline timed out after 600s"
    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = str(e)
        log.exception(f"[{job_id}] Pipeline failed")


def build_report_from_findings(findings: str, job_id: str) -> dict:
    """Convert raw investigation text into the structured report format the chat router expects."""
    findings_lower = findings.lower()

    report = {
        "executive_summary": findings[:500] if findings else "Analysis completed.",
        "malware_type": "dropper",
        "malware_family": "",
        "severity": "critical" if "critical" in findings_lower else "high",
        "severity_score": "9.0",
        "confidence": "high",
        "mitre_attack": [],
        "iocs": {"ips": [], "domains": [], "urls": [], "files": [], "hashes": []},
        "remediation": {"immediate": [], "short_term": [], "long_term": []},
        "at_risk": {"systems": [], "data_types": [], "ics_relevant": False},
        "timeline": [],
    }

    # Extract IOCs from findings text
    import re

    # IPs
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', findings)
    report["iocs"]["ips"] = list(set(ips))

    # Domains
    domains = re.findall(r'(?:ftp|http)://([a-zA-Z0-9.-]+)', findings)
    report["iocs"]["domains"] = list(set(domains))

    # URLs
    urls = re.findall(r'(?:ftp|http)://[^\s\'"<>]+', findings)
    report["iocs"]["urls"] = list(set(urls))

    # File paths
    file_paths = re.findall(r'C:\\[^\s\'"<>,]+', findings)
    report["iocs"]["files"] = list(set(file_paths))

    # Hashes
    sha256s = re.findall(r'\b[a-f0-9]{64}\b', findings)
    md5s = re.findall(r'\b[a-f0-9]{32}\b', findings)
    report["iocs"]["hashes"] = list(set(sha256s + md5s))

    # MITRE techniques
    mitre_ids = re.findall(r'T\d{4}(?:\.\d{3})?', findings)
    for mid in set(mitre_ids):
        report["mitre_attack"].append({
            "id": mid, "technique": "", "tactic": "", "subtechnique": ""
        })

    # Malware family
    for family in ["AsyncRAT", "VenomRAT", "AgentTesla", "Snake Keylogger", "GootLoader", "SocGholish"]:
        if family.lower() in findings_lower:
            report["malware_family"] = family
            break

    # Basic remediation from findings
    if report["iocs"]["ips"]:
        report["remediation"]["immediate"].append(f"Block {', '.join(report['iocs']['ips'])} at perimeter firewall")
    if report["iocs"]["domains"]:
        report["remediation"]["immediate"].append(f"Block {', '.join(report['iocs']['domains'])} at DNS")
    if "powershell" in findings_lower:
        report["remediation"]["short_term"].append("Enable PowerShell ScriptBlock Logging")
    if "amsi" in findings_lower:
        report["remediation"]["short_term"].append("Monitor for AMSI bypass attempts")

    report["remediation"]["long_term"].append("Restrict wscript.exe/cscript.exe execution via AppLocker")

    return report


# ---------- Endpoints ----------

@app.post("/analyze")
async def analyze(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Accept a file upload, copy it into the Docker container, and start analysis."""
    import subprocess as sp
    filename = file.filename or SAMPLE_NAME

    # Save to workspace
    dest = os.path.join(WORKSPACE, filename)
    with open(dest, "wb") as f:
        f.write(await file.read())

    # Copy into the sandbox container
    sp.run(["docker", "cp", dest, f"malware-sandbox:/sample/{filename}"], check=False)

    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {
        "status": "queued",
        "created_at": time.time(),
        "sample": filename,
    }
    background_tasks.add_task(run_analysis, job_id, filename)
    return {"job_id": job_id, "status": "queued"}


@app.get("/status/{job_id}")
async def status(job_id: str, after: int = 0):
    """Check analysis job status and stream pipeline events."""
    job = jobs.get(job_id)
    if not job:
        return JSONResponse({"error": "Job not found"}, status_code=404)

    result = {
        "job_id": job_id,
        "status": job["status"],
        "created_at": job.get("created_at"),
    }

    if job["status"] == "running":
        result["elapsed"] = time.time() - job.get("started_at", job["created_at"])
    elif job["status"] == "complete":
        result["elapsed"] = job.get("completed_at", 0) - job.get("started_at", 0)
        result["has_report"] = True
    elif job["status"] == "error":
        result["error"] = job.get("error", "Unknown error")

    events_path = os.path.join(WORKSPACE, "pipeline_events.jsonl")
    events = []
    if os.path.exists(events_path):
        try:
            with open(events_path) as f:
                lines = f.readlines()
            for line in lines[after:]:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
    result["events"] = events
    result["event_count"] = after + len(events)

    return result


@app.get("/report/{job_id}")
async def report(job_id: str):
    """Get the full analysis report."""
    job = jobs.get(job_id)
    if not job:
        return JSONResponse({"error": "Job not found"}, status_code=404)
    if job["status"] != "complete":
        return JSONResponse({"error": f"Job status: {job['status']}"}, status_code=400)

    return {
        "job_id": job_id,
        "report": job.get("result", {}),
        "findings_raw": job.get("findings_raw", "")[:10000],
        "indexed": job.get("indexed", False),
    }


@app.get("/jobs")
async def list_jobs():
    """List all analysis jobs."""
    return {
        jid: {
            "status": j["status"],
            "sample": j.get("sample"),
            "created_at": j.get("created_at"),
        }
        for jid, j in jobs.items()
    }


# ---------- Health ----------

@app.get("/health")
async def health():
    """Health check."""
    container_ok = os.system("docker ps -q -f name=malware-sandbox | grep -q .") == 0
    return {
        "status": "ok",
        "container": "running" if container_ok else "not found",
        "workspace": os.path.exists(WORKSPACE),
        "jobs_count": len(jobs),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
