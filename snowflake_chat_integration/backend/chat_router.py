"""
chat_router.py — Drop-in FastAPI router for Snowflake RAG chat.

Usage in your FastAPI app:
    from chat_router import create_chat_router
    app.include_router(create_chat_router(jobs))

Where `jobs` is your dict[str, dict] that holds analysis job state with at least:
    jobs[job_id] = {
        "status": "complete" | "error" | "running" | ...,
        "result": <final report dict>,
        "progress": { "static": { "findings": { "hashes": { "sha256": "..." } } } },
    }

After analysis completes, call `ingest_job(job_id, jobs)` in a background thread
to index the report into Snowflake for RAG retrieval.

Environment variables required (see .env):
    ANTHROPIC_API_KEY
    SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, SNOWFLAKE_PRIVATE_KEY_PATH (or SNOWFLAKE_PASSWORD)
    SNOWFLAKE_DATABASE, SNOWFLAKE_SCHEMA, SNOWFLAKE_WAREHOUSE
"""

import logging
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

log = logging.getLogger(__name__)

# ── Optional dependency guards ──────────────────────────────────────────────

try:
    from anthropic import AsyncAnthropic as _AsyncAnthropic
    _ANTHROPIC_OK = True
except ImportError:
    _ANTHROPIC_OK = False

try:
    from snowflake_tools import store_findings_in_snowflake as _store, similarity_search as _search
    _SNOWFLAKE_OK = True
except ImportError:
    _SNOWFLAKE_OK = False

CHAT_READY = _ANTHROPIC_OK and _SNOWFLAKE_OK


# ── Schema ───────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    question: str
    job_id: str


# ── Report helpers ────────────────────────────────────────────────────────────

def get_sample_sha256(job: dict, job_id: str) -> str:
    """Extract SHA-256 from static analysis findings, or fall back to job_id."""
    hashes = (
        (job.get("progress") or {})
        .get("static", {})
        .get("findings", {})
        .get("hashes", {})
    ) or {}
    return hashes.get("sha256") or job_id


def chunk_report(report: dict, job_id: str) -> list:
    """
    Convert a final analysis report into Snowflake-ready text chunks.

    Adapt the field names here to match your report schema.
    Default mapping targets the MalwareScope ReportWriterAgent output schema:
        executive_summary, malware_type, malware_family, severity, confidence,
        severity_score, mitre_attack[], iocs{ips,domains,urls,files,hashes},
        remediation{immediate,short_term,long_term}, at_risk{systems,data_types,...},
        timeline[{offset_seconds,severity,event}]
    """
    chunks = []

    def add(text: str, chunk_type: str):
        chunks.append({"text": text.strip(), "chunk_type": chunk_type, "metadata": {"job_id": job_id}})

    # Executive overview
    summary = report.get("executive_summary", "")
    if summary:
        add(
            f"Executive Summary: {summary} | "
            f"Type: {report.get('malware_type','')} | Family: {report.get('malware_family','')} | "
            f"Severity: {report.get('severity','')} ({report.get('severity_score','')}) | "
            f"Confidence: {report.get('confidence','')}",
            "blue_team_summary",
        )

    # MITRE ATT&CK
    for m in (report.get("mitre_attack") or []):
        add(
            f"MITRE ATT&CK {m.get('id','')}: {m.get('technique','')} [{m.get('tactic','')}]. "
            f"Subtechnique: {m.get('subtechnique','')}.",
            "mitre_technique",
        )

    # IOCs
    iocs = report.get("iocs") or {}
    for ip in (iocs.get("ips") or []):
        add(f"IOC — IP address: {ip}", "c2_infrastructure")
    for domain in (iocs.get("domains") or []):
        add(f"IOC — Domain: {domain}", "c2_infrastructure")
    for url in (iocs.get("urls") or []):
        add(f"IOC — URL: {url}", "c2_infrastructure")
    for f_ in (iocs.get("files") or []):
        add(f"IOC — File artifact: {f_}", "file_drop")
    for h in (iocs.get("hashes") or []):
        add(f"IOC — Hash: {h}", "file_drop")

    # Remediation
    rem = report.get("remediation") or {}
    for action in (rem.get("immediate") or []):
        add(f"Immediate remediation: {action}", "hunt_query")
    for action in (rem.get("short_term") or []):
        add(f"Short-term remediation: {action}", "hunt_query")
    for action in (rem.get("long_term") or []):
        add(f"Long-term remediation: {action}", "hunt_query")

    # At-risk systems
    at_risk = report.get("at_risk") or {}
    if at_risk:
        add(
            f"At-risk systems: {', '.join(at_risk.get('systems') or [])}. "
            f"Data types at risk: {', '.join(at_risk.get('data_types') or [])}. "
            f"ICS relevant: {at_risk.get('ics_relevant')}. "
            f"{at_risk.get('ics_risk_description', '')}",
            "capability",
        )

    # Kill-chain timeline
    for ev in (report.get("timeline") or []):
        add(
            f"Kill-chain event (T+{ev.get('offset_seconds',0)}s, "
            f"severity={ev.get('severity','')}): {ev.get('event','')}",
            "infection_chain_stage",
        )

    return chunks


# ── Background ingestion ──────────────────────────────────────────────────────

def ingest_job(job_id: str, jobs: dict) -> None:
    """
    Background-thread function. Call after analysis completes:

        import asyncio
        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, ingest_job, job_id, jobs)

    Indexes the final report into Snowflake so the /chat endpoint can answer.
    """
    if not CHAT_READY:
        return
    job = jobs.get(job_id)
    if not job or job.get("status") != "complete":
        return
    report = job.get("result")
    if not isinstance(report, dict):
        return
    try:
        sha256 = get_sample_sha256(job, job_id)
        chunks = chunk_report(report, job_id)
        if chunks:
            _store(chunks_json=chunks, sample_sha256=sha256, run_id=job_id)
            log.info(f"[{job_id}] Indexed {len(chunks)} chunks (sha256={sha256[:12]}…)")
        job["indexed"] = True
    except Exception as exc:
        log.warning(f"[{job_id}] Snowflake ingestion failed (non-fatal): {exc}")
        job["indexed"] = False


# ── Router factory ────────────────────────────────────────────────────────────

def create_chat_router(jobs: dict) -> APIRouter:
    """
    Return a FastAPI APIRouter with a POST /chat endpoint.

    Mount it with:
        app.include_router(create_chat_router(jobs))
    """
    router = APIRouter()

    @router.post("/chat")
    async def chat(req: ChatRequest):
        """RAG chat: search Snowflake findings → answer with Claude."""
        if not CHAT_READY:
            return JSONResponse({"error": "Chat dependencies not installed."}, status_code=503)

        job = jobs.get(req.job_id)
        if not job:
            return JSONResponse({"error": "Job not found."}, status_code=404)
        if job.get("status") not in ("complete", "error"):
            return JSONResponse({"error": "Analysis still running — please wait."}, status_code=400)

        sha256 = get_sample_sha256(job, req.job_id)
        search = _search(req.question, sample_sha256=sha256, top_k=6)
        chunks = search.get("chunks", [])

        if chunks:
            context = "\n\n---\n\n".join(
                f"[{c['chunk_type'].replace('_', ' ')}]\n{c['content']}"
                for c in chunks
            )
        else:
            # Fallback: use raw report fields as context
            report = job.get("result") or {}
            context = (
                f"Executive summary: {report.get('executive_summary', 'N/A')}\n"
                f"Malware type: {report.get('malware_type', 'N/A')} / {report.get('malware_family', 'N/A')}\n"
                f"Severity: {report.get('severity', 'N/A')} | Confidence: {report.get('confidence', 'N/A')}\n"
                f"MITRE: {[m.get('id') for m in (report.get('mitre_attack') or [])]}\n"
                f"IOCs: {report.get('iocs', {})}"
            )

        client = _AsyncAnthropic()
        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=(
                "You are a malware analyst assistant. "
                "Answer the analyst's question using ONLY the provided analysis context. "
                "Be concise and precise. Reference specific IOCs, MITRE technique IDs, "
                "severity levels, and remediation steps when relevant. "
                "If the context is insufficient, say so clearly."
            ),
            messages=[{
                "role": "user",
                "content": f"Question: {req.question}\n\nAnalysis context:\n{context}",
            }],
        )

        return JSONResponse({
            "answer": response.content[0].text,
            "sources": chunks[:4],
            "method": search.get("method", "none"),
        })

    return router
