# Snowflake RAG Chat Integration

Portable drop-in kit that adds a **floating analyst chat** to any malware analysis web app.
Answers questions about analysis results using **Snowflake vector search** as a RAG backend and **Claude** as the LLM.

---

## Package contents

```
snowflake_chat_integration/
├── .env                   ← Snowflake + Anthropic credentials (update key path)
├── rsa_key.p8             ← RSA private key for Snowflake service account
├── backend/
│   ├── snowflake_tools.py ← Storage + similarity-search helpers (no dependencies on app framework)
│   ├── chat_router.py     ← Drop-in FastAPI APIRouter: POST /chat + ingestion helpers
│   └── requirements.txt   ← Python dependencies
└── frontend/
    ├── ChatPanel.jsx      ← React component — floating chat panel with markdown rendering
    └── sendChat.js        ← API client helper (one function, paste into your client module)
```

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Python      | ≥ 3.10  |
| Node / npm  | ≥ 18    |
| FastAPI app | any     |
| React app   | ≥ 18    |

---

## Setup

### 1. Copy backend files

```bash
cp backend/snowflake_tools.py  /your-project/
cp backend/chat_router.py      /your-project/
```

Both files must live in the **same directory** (or ensure `snowflake_tools` is importable).

### 2. Install Python dependencies

```bash
pip install -r backend/requirements.txt
```

### 3. Set environment variables

Copy `.env` to your project root and update `SNOWFLAKE_PRIVATE_KEY_PATH` to the absolute path of `rsa_key.p8`.

```bash
cp .env /your-project/.env
cp rsa_key.p8 /your-project/rsa_key.p8
# then edit .env:
SNOWFLAKE_PRIVATE_KEY_PATH=/your-project/rsa_key.p8
```

Load it with python-dotenv or your preferred method.

### 4. Mount the chat router in FastAPI

```python
# In your main FastAPI file (e.g. main.py)
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from chat_router import create_chat_router, ingest_job

app = FastAPI()

# `jobs` is your existing dict[str, dict] that tracks analysis jobs
jobs = {}

app.include_router(create_chat_router(jobs))
```

### 5. Trigger ingestion after analysis completes

Call `ingest_job` in a background thread immediately after an analysis job finishes:

```python
import asyncio
from chat_router import ingest_job

# Inside your existing "analysis complete" handler:
loop = asyncio.get_running_loop()
loop.run_in_executor(None, ingest_job, job_id, jobs)
```

The job dict must have this shape:
```python
jobs[job_id] = {
    "status": "complete",       # required
    "result": { ... },          # final report dict — see "Report schema" below
    "progress": {               # optional, used to extract SHA-256
        "static": {
            "findings": {
                "hashes": { "sha256": "abc123..." }
            }
        }
    }
}
```

### 6. Add the React component

Install peer dependencies:
```bash
npm install react-markdown remark-gfm
```

Copy `frontend/ChatPanel.jsx` to `src/components/ChatPanel.jsx`.

Add `sendChat` from `frontend/sendChat.js` to your API client:
```js
// src/api/client.js
export async function sendChat(jobId, question) {
  const res = await fetch(`/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ job_id: jobId, question }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `Chat failed: ${res.status}`);
  }
  return res.json();
}
```

Render the panel in your root component:
```jsx
import ChatPanel from "./components/ChatPanel";

// jobId  — string ID of the active analysis job (or null)
// isDone — boolean, true when analysis pipeline completed
<ChatPanel jobId={jobId} isDone={isDone} />
```

The button is invisible/greyed-out until `isDone` is `true`.

---

## Report schema

`chat_router.py`'s `chunk_report()` function reads these fields from your report dict:

| Field | Type | Notes |
|-------|------|-------|
| `executive_summary` | string | Overview chunk |
| `malware_type` / `malware_family` / `severity` / `confidence` / `severity_score` | string | Merged into summary chunk |
| `mitre_attack[]` | `{id, technique, tactic, subtechnique}` | One chunk per entry |
| `iocs.ips/domains/urls/files/hashes` | string[] | One chunk per IOC |
| `remediation.immediate/short_term/long_term` | string[] | One chunk per action |
| `at_risk.systems/data_types/ics_relevant/ics_risk_description` | mixed | Combined chunk |
| `timeline[]` | `{offset_seconds, severity, event}` | One chunk per event |

Adapt `chunk_report()` in `chat_router.py` to match your own report schema if needed.

---

## Snowflake database

The integration uses table `RAVEN_DB.ANALYSIS.ANALYSIS_FINDINGS` (auto-created on first ingest).

| Column | Type |
|--------|------|
| `chunk_id` | VARCHAR PK |
| `run_id` | VARCHAR |
| `sample_sha256` | VARCHAR |
| `chunk_type` | VARCHAR |
| `content` | TEXT |
| `metadata` | VARIANT |
| `created_at` | TIMESTAMP |

Similarity search uses `SNOWFLAKE.CORTEX.SIMILARITY` when available, falling back to keyword matching automatically.

---

## Fallback behaviour

If Snowflake is unreachable or not configured, all data is stored/searched locally at `/tmp/raven_chunks.json` using simple keyword matching. No code changes required — the fallback is transparent.

---

## Credentials

| Variable | Value |
|----------|-------|
| `SNOWFLAKE_ACCOUNT` | `PKDKALG-NZC49646` |
| `SNOWFLAKE_USER` | `raven_service` |
| `SNOWFLAKE_DATABASE` | `RAVEN_DB` |
| `SNOWFLAKE_SCHEMA` | `ANALYSIS` |
| `SNOWFLAKE_WAREHOUSE` | `RAVEN_WH` |
| Auth method | RSA key-pair (`rsa_key.p8`) |
