/**
 * sendChat.js — API helper for the Snowflake RAG chat endpoint.
 *
 * Add this function to your existing API client (e.g. src/api/client.js).
 *
 * Usage:
 *   import { sendChat } from "./api/client";
 *   const { answer, sources, method } = await sendChat(jobId, question);
 *
 * Response shape:
 *   answer  — string  — Claude's markdown-formatted response
 *   sources — array   — up to 4 chunks used as RAG context
 *             [{ content, chunk_type, confidence, similarity }]
 *   method  — string  — "cortex_similarity" | "snowflake_keyword" | "keyword_fallback"
 *
 * Environment:
 *   REACT_APP_API_URL — optional base URL (defaults to "" for same-origin proxy)
 */

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";

export async function sendChat(jobId, question) {
  const res = await fetch(`${BASE_URL}/chat`, {
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
