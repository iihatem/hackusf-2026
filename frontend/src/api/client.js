/**
 * MalwareScope API client.
 * All API calls go through this module — never fetch directly from components.
 */

const BASE_URL = process.env.REACT_APP_API_URL || "";

export async function uploadFile(file) {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE_URL}/analyze`, { method: "POST", body: form });
  if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
  return res.json();
}

export async function getStatus(jobId) {
  const res = await fetch(`${BASE_URL}/status/${jobId}`);
  if (!res.ok) throw new Error(`Status fetch failed: ${res.status}`);
  return res.json();
}

export async function exportReport(jobId) {
  const res = await fetch(`${BASE_URL}/export/${jobId}`);
  if (!res.ok) throw new Error(`Export failed: ${res.status}`);
  return res.json();
}
