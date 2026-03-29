"""
MalwareScope — FastAPI Backend
Serves the React frontend. Accepts file uploads, runs the analysis pipeline,
streams per-agent progress, and serves results.

Start with:
    uvicorn api.main:app --host 0.0.0.0 --port 9000
"""

import json
import logging
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

load_dotenv()

log = logging.getLogger("malwarescope.api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")

app = FastAPI(title="MalwareScope API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job store — persists for the lifetime of the process
jobs: dict[str, dict] = {}

UPLOAD_DIR = Path("/tmp/malwarescope_uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Maps ADK agent names → job progress keys
AGENT_PROGRESS_MAP = {
    "StaticAnalysisAgent": "static",
    "ScenarioBuilderAgent": "scenario",
    "NetworkMonitorAgent": "network",
    "FilesystemMonitorAgent": "filesystem",
    "RegistryMonitorAgent": "registry",
    "ThreatIntelAgent": "intel",
    "CriticAgent": "critic",
    "ReportWriterAgent": "report",
}

# Maps response agent names → response result keys
RESPONSE_AGENT_MAP = {
    "BlocklistAgent": "blocklist",
    "AlertAgent": "alert",
    "TicketAgent": "ticket",
    "VerificationAgent": "verification",
}

# Approximate percent completion when each agent starts/finishes
AGENT_PERCENTS = {
    "static": (5, 15),
    "scenario": (15, 25),
    "network": (25, 50),
    "filesystem": (25, 50),
    "registry": (25, 50),
    "intel": (25, 50),
    "critic": (55, 75),
    "report": (75, 100),
}


def _make_job(job_id: str) -> dict:
    """Create a fresh job dict with all agent slots initialized."""
    progress = {}
    for key in AGENT_PERCENTS:
        progress[key] = {"status": "idle", "percent": 0, "findings": None}
    return {
        "job_id": job_id,
        "status": "queued",
        "filename": "",
        "progress": progress,
        "result": None,
        "error": None,
        "events": [],
        "response": {
            "status": "idle",  # idle | running | complete | skipped | error
            "blocklist": None,
            "alert": None,
            "ticket": None,
            "verification": None,
            "error": None,
        },
    }


def _trim_static_data(data: dict) -> dict:
    """
    Hard-cap the static analysis blob before injecting into LLM session state.
    Prevents context window overflow on large files (JS, packed binaries, etc.)
    """
    trimmed = dict(data)
    # Strings: max 30, each max 100 chars
    strings = trimmed.get("strings") or []
    trimmed["strings"] = [s[:100] for s in strings[:30]]
    # PE imports: max 5 DLLs × 15 functions
    pe = trimmed.get("pe_info") or {}
    if pe and "imports" in pe:
        trimmed["pe_info"] = dict(pe)
        trimmed["pe_info"]["imports"] = {
            dll: fns[:15]
            for dll, fns in list(pe["imports"].items())[:5]
        }
    # IOCs: max 20 each
    iocs = trimmed.get("iocs") or {}
    if iocs:
        trimmed["iocs"] = {
            k: v[:20] if isinstance(v, list) else v
            for k, v in iocs.items()
        }
    return trimmed


async def _run_pipeline(job_id: str, file_path: str) -> None:
    """
    Background task: runs static analyzer then the ADK analysis pipeline.
    Updates job dict in real time as each agent completes.
    """
    job = jobs[job_id]
    job["status"] = "running"

    # ── Step 1: Static Analysis (Python — no LLM) ──────────────────────────
    log.info(f"[{job_id}] Running static analyzer on {file_path}")
    job["progress"]["static"]["status"] = "running"
    job["progress"]["static"]["percent"] = AGENT_PERCENTS["static"][0]
    _emit_event(job, "static_analyzer", "Static analysis started", "info")

    try:
        from analysis_service.static_analyzer import analyze as static_analyze
        raw_static_data = static_analyze(file_path)
        job["progress"]["static"]["status"] = "complete"
        job["progress"]["static"]["percent"] = AGENT_PERCENTS["static"][1]
        job["progress"]["static"]["findings"] = raw_static_data
        _emit_event(job, "static_analyzer", f"Static analysis complete — entropy={raw_static_data.get('entropy', 'n/a')}, YARA matches={len(raw_static_data.get('yara_matches', []))}", "success")
        log.info(f"[{job_id}] Static analysis complete")
    except Exception as exc:
        log.error(f"[{job_id}] Static analysis failed: {exc}", exc_info=True)
        job["progress"]["static"]["status"] = "error"
        job["progress"]["static"]["findings"] = {"error": str(exc)}
        raw_static_data = {"file_path": file_path, "error": str(exc)}
        _emit_event(job, "static_analyzer", f"Static analysis error: {exc}", "error")

    # ── Step 2: ADK Analysis Pipeline ─────────────────────────────────────
    log.info(f"[{job_id}] Starting ADK analysis pipeline")
    _emit_event(job, "pipeline", "ADK analysis pipeline starting", "info")

    try:
        from google.adk.runners import InMemoryRunner
        from google.genai import types as genai_types
        from analysis_service.agent import root_agent

        runner = InMemoryRunner(agent=root_agent, app_name="malwarescope")

        session = await runner.session_service.create_session(
            app_name="malwarescope",
            user_id="analyst",
            state={
                "sample_path": file_path,
                "raw_static_data": json.dumps(
                    _trim_static_data(raw_static_data), default=str
                ),
            },
        )

        content = genai_types.Content(
            role="user",
            parts=[genai_types.Part(text=(
                f"Analyze the malware sample. The file is at {file_path}. "
                "Raw static analysis data has been pre-loaded into session state as raw_static_data."
            ))],
        )

        async for event in runner.run_async(
            user_id="analyst",
            session_id=session.id,
            new_message=content,
        ):
            _process_adk_event(job, event, session, runner)

        # Pipeline complete — extract final results from session state
        final_session = await runner.session_service.get_session(
            app_name="malwarescope",
            user_id="analyst",
            session_id=session.id,
        )

        _extract_final_results(job, final_session)
        job["status"] = "complete"
        _emit_event(job, "pipeline", "Analysis complete", "success")
        log.info(f"[{job_id}] Pipeline complete")

        # ── Step 3: Autonomous Response (if threat confirmed) ──────────────
        final_report = job.get("result") or {}
        if final_report and _is_threat_confirmed(final_report):
            severity = final_report.get("severity", "unknown").upper()
            _emit_event(job, "response", f"Confirmed {severity} threat — triggering autonomous response", "info")
            await _run_response_pipeline(job_id, final_report)
        else:
            job["response"]["status"] = "skipped"
            _emit_event(job, "response", "Response skipped — no confirmed high/critical threat", "info")
            log.info(f"[{job_id}] Response skipped (severity below threshold)")

    except Exception as exc:
        log.error(f"[{job_id}] Pipeline failed: {exc}", exc_info=True)
        job["status"] = "error"
        job["error"] = str(exc)
        _emit_event(job, "pipeline", f"Pipeline error: {exc}", "error")


def _process_adk_event(job: dict, event: Any, session: Any, runner: Any) -> None:
    """Map ADK events to job progress updates."""
    author = getattr(event, "author", None)
    if not author:
        return

    agent_key = AGENT_PROGRESS_MAP.get(author)
    if not agent_key:
        return

    # Mark agent as running on first event from it
    if job["progress"][agent_key]["status"] == "idle":
        job["progress"][agent_key]["status"] = "running"
        job["progress"][agent_key]["percent"] = AGENT_PERCENTS[agent_key][0]
        _emit_event(job, author, f"{author} started analysis", "running")
        log.info(f"[{job['job_id']}] {author} running")

    # Mark agent complete when it emits a final response
    if hasattr(event, "is_final_response") and event.is_final_response():
        job["progress"][agent_key]["status"] = "complete"
        job["progress"][agent_key]["percent"] = AGENT_PERCENTS[agent_key][1]
        _emit_event(job, author, f"{author} analysis complete", "success")
        log.info(f"[{job['job_id']}] {author} complete")

        # Try to extract findings from event content
        try:
            if event.content and event.content.parts:
                findings = _parse_agent_json(event.content.parts[0].text)
                if isinstance(findings, dict):
                    job["progress"][agent_key]["findings"] = findings
        except Exception:
            pass  # findings will be pulled from session state at the end


def _parse_agent_json(value: Any) -> Any:
    """
    Parse a value that ADK stored as a string in session state.
    Handles LLM outputs that wrap JSON in markdown fences (```json ... ```).
    Returns the original value unchanged if parsing fails.
    """
    if not isinstance(value, str):
        return value
    text = value.strip()
    # Strip markdown code fences — LLMs sometimes include them even in output_key values
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop first line (```json or ```) and last line (```)
        inner = "\n".join(lines[1:-1]) if len(lines) > 2 else text
        text = inner.strip()
    try:
        return json.loads(text)
    except Exception:
        return value  # return as-is; callers must handle str gracefully


def _extract_final_results(job: dict, session: Any) -> None:
    """Pull all agent outputs from final session state into job progress."""
    state = getattr(session, "state", {}) or {}

    key_map = {
        "static_analysis_result": "static",
        "behavioral_scenario": "scenario",
        "network_findings": "network",
        "filesystem_findings": "filesystem",
        "registry_findings": "registry",
        "intel_findings": "intel",
        "critic_review": "critic",
        "final_report": "report",
    }

    for state_key, progress_key in key_map.items():
        value = state.get(state_key)
        if value is None:
            continue
        value = _parse_agent_json(value)
        job["progress"][progress_key]["findings"] = value
        if job["progress"][progress_key]["status"] != "error":
            job["progress"][progress_key]["status"] = "complete"
            job["progress"][progress_key]["percent"] = 100

    # Set the top-level result to the final report
    final_report = _parse_agent_json(state.get("final_report"))
    if final_report:
        job["result"] = final_report


def _is_threat_confirmed(report: Any) -> bool:
    """Return True when the report warrants an autonomous response."""
    if not isinstance(report, dict):
        return False
    severity = (report.get("severity") or "").lower()
    confidence = (report.get("confidence") or "").lower()
    return severity in ("critical", "high") or confidence == "high"


def _process_response_event(job: dict, event: Any) -> None:
    """Map ADK response pipeline events → job response updates."""
    author = getattr(event, "author", None)
    if not author:
        return
    agent_key = RESPONSE_AGENT_MAP.get(author)
    if not agent_key:
        return
    if hasattr(event, "is_final_response") and event.is_final_response():
        try:
            if event.content and event.content.parts:
                parsed = _parse_agent_json(event.content.parts[0].text)
                if isinstance(parsed, dict):
                    job["response"][agent_key] = parsed
        except Exception:
            pass
        _emit_event(job, author, f"{author} response action complete", "success")
        log.info(f"[{job['job_id']}] Response: {author} complete")


def _extract_response_results(job: dict, session: Any) -> None:
    """Pull response agent outputs from final session state."""
    state = getattr(session, "state", {}) or {}
    key_map = {
        "blocklist_result": "blocklist",
        "alert_result": "alert",
        "ticket_result": "ticket",
        "verification_result": "verification",
    }
    for state_key, resp_key in key_map.items():
        value = _parse_agent_json(state.get(state_key))
        if value is not None:
            job["response"][resp_key] = value


async def _run_response_pipeline(job_id: str, final_report: dict) -> None:
    """
    Trigger the autonomous response pipeline for confirmed threats.
    Runs BlocklistAgent + AlertAgent + TicketAgent in parallel,
    then VerificationAgent loop (max 3 iterations).
    """
    job = jobs[job_id]
    job["response"]["status"] = "running"
    _emit_event(job, "response", "Autonomous response pipeline starting", "info")
    log.info(f"[{job_id}] Starting response pipeline")

    try:
        from google.adk.runners import InMemoryRunner
        from google.genai import types as genai_types
        from response_service.agent import root_agent as response_root_agent

        runner = InMemoryRunner(agent=response_root_agent, app_name="malwarescope_response")

        session = await runner.session_service.create_session(
            app_name="malwarescope_response",
            user_id="analyst",
            state={
                "final_report": json.dumps(final_report, default=str),
            },
        )

        content = genai_types.Content(
            role="user",
            parts=[genai_types.Part(text=(
                "A confirmed threat has been detected. Execute the full autonomous response: "
                "block all network IOCs, dispatch the SOC alert, create an incident ticket, "
                "then verify all actions completed successfully. "
                "The final threat report is pre-loaded in session state as final_report."
            ))],
        )

        async for event in runner.run_async(
            user_id="analyst",
            session_id=session.id,
            new_message=content,
        ):
            _process_response_event(job, event)

        final_session = await runner.session_service.get_session(
            app_name="malwarescope_response",
            user_id="analyst",
            session_id=session.id,
        )
        _extract_response_results(job, final_session)
        job["response"]["status"] = "complete"
        _emit_event(job, "response", "All autonomous response actions verified complete", "success")
        log.info(f"[{job_id}] Response pipeline complete")

    except Exception as exc:
        log.error(f"[{job_id}] Response pipeline failed: {exc}", exc_info=True)
        job["response"]["status"] = "error"
        job["response"]["error"] = str(exc)
        _emit_event(job, "response", f"Response pipeline error: {exc}", "error")


def _emit_event(job: dict, source: str, message: str, level: str) -> None:
    """Append a timeline event to the job."""
    import time
    job["events"].append({
        "timestamp": time.time(),
        "source": source,
        "message": message,
        "level": level,
    })


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.post("/analyze")
async def analyze(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """
    Accept a file upload, start the analysis pipeline, return a job_id.
    The frontend polls GET /status/{job_id} every 2 seconds for updates.
    """
    job_id = str(uuid.uuid4())
    safe_name = Path(file.filename).name if file.filename else "sample"
    dest = UPLOAD_DIR / f"{job_id}_{safe_name}"

    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)

    job = _make_job(job_id)
    job["filename"] = safe_name
    jobs[job_id] = job

    background_tasks.add_task(_run_pipeline, job_id, str(dest))

    log.info(f"Job {job_id} created for file {safe_name}")
    return {"job_id": job_id}


@app.get("/status/{job_id}")
async def status(job_id: str):
    """
    Return the full job dict. Polled every 2 seconds by the frontend.
    Never returns a 4xx/5xx — errors are embedded in the job dict.
    """
    job = jobs.get(job_id)
    if not job:
        return JSONResponse({"job_id": job_id, "status": "not_found", "progress": {}, "result": None, "error": "Job not found"})
    return job


@app.get("/export/{job_id}")
async def export(job_id: str):
    """Return the final_report as JSON for download."""
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] != "complete":
        raise HTTPException(status_code=400, detail=f"Job not complete (status={job['status']})")
    return job.get("result") or {}


@app.get("/health")
async def health():
    return {"status": "ok", "jobs": len(jobs)}
