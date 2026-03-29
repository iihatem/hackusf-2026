/**
 * useAnalysis — polling hook.
 * All polling logic lives here. Components receive props, they don't poll.
 */

import { useState, useEffect, useRef, useCallback } from "react";
import { uploadFile, getStatus } from "../api/client";

const POLL_INTERVAL = 2000;
const TERMINAL_STATUSES = new Set(["complete", "error", "not_found"]);

export function useAnalysis() {
  const [jobId, setJobId] = useState(null);
  const [job, setJob] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const startPolling = useCallback((id) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      try {
        const data = await getStatus(id);
        setJob(data);
        if (TERMINAL_STATUSES.has(data.status)) {
          stopPolling();
        }
      } catch (err) {
        setError(err.message);
        stopPolling();
      }
    }, POLL_INTERVAL);
  }, [stopPolling]);

  useEffect(() => {
    return () => stopPolling();
  }, [stopPolling]);

  const analyze = useCallback(async (file) => {
    setUploading(true);
    setError(null);
    setJob(null);
    setJobId(null);
    try {
      const { job_id } = await uploadFile(file);
      setJobId(job_id);
      startPolling(job_id);
    } catch (err) {
      setError(err.message);
    } finally {
      setUploading(false);
    }
  }, [startPolling]);

  const reset = useCallback(() => {
    stopPolling();
    setJobId(null);
    setJob(null);
    setError(null);
    setUploading(false);
  }, [stopPolling]);

  return { analyze, reset, jobId, job, uploading, error };
}
