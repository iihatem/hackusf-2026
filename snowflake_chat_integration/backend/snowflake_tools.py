"""
snowflake_tools.py — Snowflake RAG storage and similarity search helpers.

Drop-in module. Copy to your project root or any importable location.
Used by chat_router.py for ingestion and retrieval.
"""

import json
import os
import re
import sqlite3
from pathlib import Path

_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "workspace", "raven_findings.db")


def _is_snowflake_configured() -> bool:
    account = os.environ.get("SNOWFLAKE_ACCOUNT", "").strip()
    user = os.environ.get("SNOWFLAKE_USER", "").strip()
    has_key = bool(os.environ.get("SNOWFLAKE_PRIVATE_KEY_PATH", "").strip())
    has_password = bool(os.environ.get("SNOWFLAKE_PASSWORD", "").strip())
    return bool(account and user and (has_key or has_password))


def _get_snowflake_connection():
    import snowflake.connector
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.backends import default_backend

    account = os.environ["SNOWFLAKE_ACCOUNT"]
    user = os.environ["SNOWFLAKE_USER"]
    database = os.environ.get("SNOWFLAKE_DATABASE", "RAVEN_DB")
    schema = os.environ.get("SNOWFLAKE_SCHEMA", "ANALYSIS")
    warehouse = os.environ.get("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH")

    key_path = os.environ.get("SNOWFLAKE_PRIVATE_KEY_PATH", "").strip()

    if key_path:
        with open(key_path, "rb") as f:
            private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        private_key_bytes = private_key.private_bytes(
            encoding=Encoding.DER, format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        return snowflake.connector.connect(
            account=account, user=user, private_key=private_key_bytes,
            database=database, schema=schema, warehouse=warehouse,
        )
    else:
        return snowflake.connector.connect(
            account=account, user=user, password=os.environ["SNOWFLAKE_PASSWORD"],
            database=database, schema=schema, warehouse=warehouse,
        )


def _get_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analysis_findings (
            chunk_id TEXT PRIMARY KEY,
            run_id TEXT,
            sample_sha256 TEXT,
            chunk_type TEXT,
            content TEXT,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_run ON analysis_findings(run_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_sha ON analysis_findings(sample_sha256)")
    conn.commit()
    return conn


def chunk_and_embed_findings(report_json: str) -> dict:
    """
    Parse a Raven-format report JSON and create semantic chunks.
    Returns: {chunks: list[{text, chunk_type, metadata}], count: int}
    """
    try:
        report = report_json if isinstance(report_json, dict) else json.loads(report_json)
    except (json.JSONDecodeError, TypeError) as e:
        return {"chunks": [], "count": 0, "error": f"Failed to parse report JSON: {e}"}

    chunks = []
    metadata = report.get("report_metadata", {})
    sample_sha256 = metadata.get("sample_sha256", "unknown")
    malware_family = metadata.get("malware_family", "unknown")

    def make_chunk(text: str, chunk_type: str, extra_meta: dict = None) -> dict:
        return {
            "text": text,
            "chunk_type": chunk_type,
            "metadata": {
                "sample_sha256": sample_sha256,
                "malware_family": malware_family,
                **(extra_meta or {}),
            },
        }

    for stage in report.get("infection_chain", []):
        text = (
            f"Stage {stage.get('stage', '?')}: {stage.get('file', '')} "
            f"({stage.get('type', '')}). Action: {stage.get('action', '')}. "
            f"Drops: {stage.get('drops', 'nothing')}."
        )
        chunks.append(make_chunk(text, "infection_chain_stage", {"stage": stage.get("stage")}))

    for cap in report.get("capabilities", []):
        text = (
            f"Capability: {cap.get('name', '')}. "
            f"Description: {cap.get('description', '')}. "
            f"MITRE: {cap.get('mitre_id', '')} - {cap.get('mitre_name', '')}. "
            f"Evidence: {cap.get('evidence', '')}."
        )
        chunks.append(make_chunk(text, "capability", {"mitre_id": cap.get("mitre_id")}))

    for tech in report.get("mitre_techniques", []):
        text = (
            f"MITRE ATT&CK {tech.get('id', '')}: {tech.get('name', '')} "
            f"[{tech.get('tactic', '')}]. {tech.get('description', '')}"
        )
        chunks.append(make_chunk(text, "mitre_technique", {"mitre_id": tech.get("id")}))

    c2 = report.get("c2_infrastructure", {})
    if c2 and c2.get("host"):
        text = (
            f"C2 Infrastructure: host={c2.get('host')}, port={c2.get('port')}, "
            f"protocol={c2.get('protocol')}, encryption={c2.get('encryption')}."
        )
        chunks.append(make_chunk(text, "c2_infrastructure"))

    for drop in report.get("file_drops", []):
        text = (
            f"File Drop: {drop.get('path', '')}. "
            f"Purpose: {drop.get('purpose', '')}. "
            f"Persistence: {drop.get('persistence_mechanism', 'none')}."
        )
        chunks.append(make_chunk(text, "file_drop"))

    family = report.get("malware_family", {})
    if isinstance(family, dict) and family.get("name"):
        text = (
            f"Malware Family: {family.get('name')} "
            f"(confidence: {family.get('confidence', 'unknown')}). "
            f"{family.get('rationale', '')}"
        )
        chunks.append(make_chunk(text, "malware_family"))

    for i, rule in enumerate(report.get("sigma_rules", [])):
        rule_text = rule if isinstance(rule, str) else json.dumps(rule)
        chunks.append(make_chunk(f"Sigma Detection Rule {i+1}:\n{rule_text[:1000]}", "sigma_rule", {"rule_index": i}))

    yara = report.get("yara_rule", "")
    if yara and yara.strip():
        chunks.append(make_chunk(f"YARA Rule:\n{yara[:1000]}", "yara_rule"))

    hunt = report.get("hunt_queries", {})
    for q in hunt.get("splunk_spl", []):
        chunks.append(make_chunk(f"Splunk Hunt Query: {q}", "hunt_query", {"query_type": "splunk"}))
    for q in hunt.get("kql", []):
        chunks.append(make_chunk(f"KQL Hunt Query: {q}", "hunt_query", {"query_type": "kql"}))

    summary = report.get("blue_team_summary", "")
    if summary and summary.strip():
        chunks.append(make_chunk(f"Blue Team Summary: {summary}", "blue_team_summary"))

    rta = report.get("red_team_analysis", {})
    if rta:
        text = (
            f"Red Team Analysis. Operational goal: {rta.get('operational_goal', '')}. "
            f"Target sector: {rta.get('target_sector', '')}. "
            f"Chain rationale: {rta.get('chain_complexity_rationale', '')}."
        )
        chunks.append(make_chunk(text, "red_team_analysis"))

    return {"chunks": chunks, "count": len(chunks)}


def store_findings_in_snowflake(chunks_json, sample_sha256: str, run_id: str) -> dict:
    """
    Store analysis chunks in Snowflake ANALYSIS_FINDINGS table.
    Falls back to /tmp/raven_chunks.json if Snowflake is not configured.
    Returns: {stored_count, table, status, run_id}
    """
    if isinstance(chunks_json, list):
        chunks = chunks_json
    elif isinstance(chunks_json, dict):
        chunks = chunks_json.get("chunks", [])
    else:
        try:
            parsed = json.loads(chunks_json)
            chunks = parsed.get("chunks", []) if isinstance(parsed, dict) else parsed
        except (json.JSONDecodeError, TypeError) as e:
            return {"stored_count": 0, "status": "failed", "error": f"Failed to parse chunks: {e}"}

    if not _is_snowflake_configured():
        conn = _get_db()
        stored = 0
        for i, chunk in enumerate(chunks):
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO analysis_findings (chunk_id, run_id, sample_sha256, chunk_type, content, metadata) VALUES (?, ?, ?, ?, ?, ?)",
                    (f"{run_id}_{i}", run_id, sample_sha256, chunk.get("chunk_type", "unknown"), chunk.get("text", ""), json.dumps(chunk.get("metadata", {}))),
                )
                stored += 1
            except Exception:
                continue
        conn.commit()
        conn.close()
        return {
            "stored_count": stored,
            "table": "analysis_findings",
            "status": "sqlite",
            "run_id": run_id,
            "db_path": _DB_PATH,
        }

    try:
        conn = _get_snowflake_connection()
        cursor = conn.cursor()
        database = os.environ.get("SNOWFLAKE_DATABASE", "raven_db")
        schema = os.environ.get("SNOWFLAKE_SCHEMA", "analysis")
        table = f"{database}.{schema}.ANALYSIS_FINDINGS"

        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                chunk_id   VARCHAR PRIMARY KEY,
                run_id     VARCHAR,
                sample_sha256 VARCHAR,
                chunk_type VARCHAR,
                content    TEXT,
                metadata   VARIANT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
            )
        """)

        stored_count = 0
        for i, chunk in enumerate(chunks):
            try:
                cursor.execute(
                    f"INSERT INTO {table} (chunk_id, run_id, sample_sha256, chunk_type, content, metadata) "
                    f"SELECT %s, %s, %s, %s, %s, PARSE_JSON(%s)",
                    (f"{run_id}_{i}", run_id, sample_sha256,
                     chunk.get("chunk_type", "unknown"), chunk.get("text", ""),
                     json.dumps(chunk.get("metadata", {}))),
                )
                stored_count += 1
            except Exception:
                continue

        conn.commit()
        cursor.close()
        conn.close()
        return {"stored_count": stored_count, "table": table, "status": "success", "run_id": run_id}
    except Exception as e:
        return {"stored_count": 0, "table": "unknown", "status": "failed", "run_id": run_id, "error": str(e)}


def similarity_search(query_text: str, sample_sha256: str = None, top_k: int = 8) -> dict:
    """
    Vector similarity search over stored analysis findings.
    Falls back to keyword search if Snowflake is not configured.
    Returns: {chunks: list[{content, chunk_type, confidence, similarity}], method}
    """
    if not _is_snowflake_configured():
        conn = _get_db()
        if sample_sha256:
            rows = conn.execute("SELECT content, chunk_type FROM analysis_findings WHERE sample_sha256 = ?", (sample_sha256,)).fetchall()
        else:
            rows = conn.execute("SELECT content, chunk_type FROM analysis_findings").fetchall()
        conn.close()
        query_terms = [t for t in re.split(r'\W+', query_text.lower()) if len(t) > 2]
        scored = []
        for content, chunk_type in rows:
            text = (content + " " + chunk_type).lower()
            hits = sum(1 for t in query_terms if t in text)
            if hits:
                scored.append((hits / max(len(query_terms), 1), content, chunk_type))
        scored.sort(key=lambda x: x[0], reverse=True)
        return {
            "chunks": [
                {"content": c, "chunk_type": ct, "confidence": "medium", "similarity": round(s, 4)}
                for s, c, ct in scored[:top_k]
            ],
            "total_searched": len(rows),
            "method": "sqlite_keyword",
        }

    try:
        conn = _get_snowflake_connection()
        cursor = conn.cursor()
        database = os.environ.get("SNOWFLAKE_DATABASE", "raven_db")
        schema = os.environ.get("SNOWFLAKE_SCHEMA", "analysis")
        table = f"{database}.{schema}.ANALYSIS_FINDINGS"
        where_clause = "WHERE sample_sha256 = %s" if sample_sha256 else ""
        params = [sample_sha256] if sample_sha256 else []

        try:
            cursor.execute(
                f"SELECT content, chunk_type, SNOWFLAKE.CORTEX.SIMILARITY(content, %s) AS similarity "
                f"FROM {table} {where_clause} ORDER BY similarity DESC LIMIT %s",
                [query_text] + params + [top_k],
            )
            rows = cursor.fetchall()
            method = "cortex_similarity"
        except Exception:
            cursor.execute(f"SELECT content, chunk_type FROM {table} {where_clause} LIMIT %s", params + [top_k * 4])
            raw = cursor.fetchall()
            query_terms = [t for t in re.split(r'\W+', query_text.lower()) if len(t) > 2]
            scored = sorted(
                [(sum(1 for t in query_terms if t in (c or "").lower()) / max(len(query_terms), 1), c, ct)
                 for c, ct in raw],
                reverse=True,
            )
            rows = [(c, ct, round(s, 4)) for s, c, ct in scored[:top_k]]
            method = "snowflake_keyword"

        cursor.close()
        conn.close()
        results = []
        for row in rows:
            content, chunk_type, sim = row[0], row[1], float(row[2]) if len(row) > 2 else 0.5
            confidence = "high" if sim > 0.85 else "medium" if sim > 0.7 else "low"
            results.append({"content": content, "chunk_type": chunk_type, "confidence": confidence, "similarity": round(sim, 4)})
        return {"chunks": results, "total_searched": len(rows), "method": method}
    except Exception as e:
        return {"chunks": [], "total_searched": 0, "method": "error", "error": str(e)}
