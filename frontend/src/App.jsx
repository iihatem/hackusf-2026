import { useState, useRef, useEffect } from "react";
import { useAnalysis } from "./hooks/useAnalysis";
import { exportReport } from "./api/client";
import ResponsePanel from "./components/ResponsePanel";

// ── Helpers ────────────────────────────────────────────────────────────────────

function getPipelineStep(progress, jobStatus) {
  if (!progress || jobStatus === "queued") return 0;
  if (jobStatus === "complete") return 5;
  const p = progress;
  if (p.report?.status === "running" || p.report?.status === "complete") return 5;
  if (p.critic?.status === "running" || p.critic?.status === "complete") return 4;
  const parallelRunning = ["network","filesystem","registry","intel"].some(k => p[k]?.status === "running" || p[k]?.status === "complete");
  if (parallelRunning) return 3;
  if (p.scenario?.status === "running" || p.scenario?.status === "complete") return 2;
  if (p.static?.status === "running" || p.static?.status === "complete") return 1;
  return 0;
}

function getDisplayAgents(progress, response) {
  if (!progress) return [];
  const p = progress;
  const parallelStatuses = ["network","filesystem","registry","intel"].map(k => p[k]?.status || "idle");
  const parallelStatus =
    parallelStatuses.every(s => s === "complete") ? "complete" :
    parallelStatuses.some(s => s === "error") ? "error" :
    parallelStatuses.some(s => s === "running") ? "running" : "idle";
  const respStatus = response?.status === "complete" ? "complete" :
    response?.status === "running" ? "running" :
    response?.status === "error" ? "error" : "idle";
  return [
    { id: "static",   name: "Static analyst",      desc: "Hashes · PE · Entropy · YARA",        status: p.static?.status   || "idle" },
    { id: "scenario", name: "Scenario builder",     desc: "Behavioral simulation",               status: p.scenario?.status || "idle" },
    { id: "parallel", name: "Parallel analyzers",   desc: "Network · Filesystem · Registry · Intel", status: parallelStatus },
    { id: "critic",   name: "Adversarial critic",   desc: "FP reduction · Validation",           status: p.critic?.status   || "idle" },
    { id: "report",   name: "Report writer",        desc: "MITRE · Remediation · IOCs",          status: p.report?.status   || "idle" },
    { id: "responder",name: "Response agents",      desc: "IOC export · Alerts · Tickets",       status: respStatus },
  ];
}

function getTools(progress) {
  const s = progress?.static;
  const f = s?.findings;
  const done = s?.status === "complete";
  const scen = progress?.scenario?.status === "complete";
  return [
    { name: "Hashing + metadata",   done: done,                            time: done ? "0.1s" : null },
    { name: "File identification",  done: done,                            time: done ? "0.1s" : null },
    { name: "String extraction",    done: done && !!f?.strings?.length,    time: done ? "0.4s" : null },
    { name: "Import recovery",      done: done && !!f?.pe_info,            time: done && f?.pe_info ? "0.2s" : null },
    { name: "Entropy profiler",     done: done && f?.entropy != null,      time: done ? "0.1s" : null },
    { name: "YARA signature scan",  done: done && f?.yara_matches != null, time: done ? "0.2s" : null },
    { name: "IOC extractor",        done: done && !!f?.iocs,               time: done ? "0.3s" : null },
    { name: "Behavioral scenario",  done: scen,                            time: scen ? "0.5s" : null },
  ];
}

async function downloadReport(jobId) {
  try {
    const report = await exportReport(jobId);
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `malwarescope-report-${jobId.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error("Export failed:", err);
  }
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function StatusDot({ status }) {
  const colors = { idle: "#D1D5DB", running: "#1C1917", complete: "#16A34A", error: "#DC2626" };
  return (
    <div style={{ position: "relative", width: 10, height: 10, flexShrink: 0 }}>
      <div style={{ width: 10, height: 10, borderRadius: "50%", backgroundColor: colors[status] || colors.idle }} />
      {status === "running" && (
        <div style={{
          position: "absolute", top: -3, left: -3, width: 16, height: 16, borderRadius: "50%",
          border: "2px solid #1C1917", animation: "ping 1.5s cubic-bezier(0,0,0.2,1) infinite", opacity: 0.4,
        }} />
      )}
    </div>
  );
}

function SeverityBadge({ severity }) {
  const styles = {
    critical: { bg: "#FEF2F2", color: "#991B1B", border: "#FECACA" },
    high:     { bg: "#FFF7ED", color: "#9A3412", border: "#FED7AA" },
    medium:   { bg: "#FFFBEB", color: "#92400E", border: "#FDE68A" },
    low:      { bg: "#F0FDF4", color: "#166534", border: "#BBF7D0" },
    info:     { bg: "#F0F9FF", color: "#075985", border: "#BAE6FD" },
  };
  const s = styles[(severity || "").toLowerCase()] || styles.info;
  return (
    <span style={{
      fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", fontWeight: 500,
      padding: "2px 8px", borderRadius: 4, background: s.bg, color: s.color,
      border: `1px solid ${s.border}`, textTransform: "uppercase", letterSpacing: "0.5px",
    }}>
      {severity || "info"}
    </span>
  );
}

function RiskGauge({ score }) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const capped = Math.min(100, Math.max(0, score));
  const progress = (capped / 100) * circ;
  const color = capped >= 80 ? "#DC2626" : capped >= 60 ? "#EA580C" : capped >= 40 ? "#F59E0B" : "#16A34A";
  return (
    <div style={{ position: "relative", width: 140, height: 140, flexShrink: 0 }}>
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={r} fill="none" stroke="#F3F4F6" strokeWidth="8" />
        <circle cx="70" cy="70" r={r} fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={circ} strokeDashoffset={circ - progress}
          strokeLinecap="round" transform="rotate(-90 70 70)"
          style={{ transition: "stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1)" }} />
      </svg>
      <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)", textAlign: "center" }}>
        <div style={{ fontSize: 32, fontWeight: 600, fontFamily: "'IBM Plex Mono', monospace", color }}>{capped}</div>
        <div style={{ fontSize: 10, fontWeight: 500, textTransform: "uppercase", letterSpacing: 1, color: "#9CA3AF" }}>Risk score</div>
      </div>
    </div>
  );
}

function Card({ children, style }) {
  return (
    <div style={{ background: "#FFFFFF", border: "1px solid #E7E5E4", borderRadius: 12, padding: "20px 24px", ...style }}>
      {children}
    </div>
  );
}

function SectionLabel({ children }) {
  return (
    <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 14 }}>
      {children}
    </div>
  );
}

// ── Section: Overview ──────────────────────────────────────────────────────────

function PipelineBar({ progress, jobStatus }) {
  const STEPS = [
    { id: 1, label: "Ingest",    desc: "Sample intake" },
    { id: 2, label: "Classify",  desc: "Scenario build" },
    { id: 3, label: "Analyze",   desc: "Parallel agents" },
    { id: 4, label: "Reason",    desc: "Critic review" },
    { id: 5, label: "Report",    desc: "Synthesis" },
  ];
  const current = getPipelineStep(progress, jobStatus);
  return (
    <Card style={{ marginBottom: 20 }}>
      <SectionLabel>Analysis pipeline</SectionLabel>
      <div style={{ display: "flex", alignItems: "flex-start" }}>
        {STEPS.map((step, i) => {
          const isActive = current === step.id;
          const isDone = current > step.id;
          return (
            <div key={step.id} style={{ flex: 1, position: "relative" }}>
              <div style={{ display: "flex", alignItems: "center" }}>
                <div style={{
                  width: 40, height: 40, borderRadius: "50%", flexShrink: 0,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, fontWeight: 600,
                  background: isDone ? "#16A34A" : isActive ? "#1C1917" : "#F5F5F4",
                  color: isDone || isActive ? "#fff" : "#A8A29E",
                  transition: "all 0.4s cubic-bezier(0.4,0,0.2,1)", position: "relative", overflow: "hidden",
                }}>
                  {isDone ? "✓" : step.id.toString().padStart(2, "0")}
                  {isActive && (
                    <div style={{
                      position: "absolute", top: 0, left: 0, width: "50%", height: "100%",
                      background: "linear-gradient(90deg,transparent,rgba(255,255,255,0.25),transparent)",
                      animation: "scanline 1.5s linear infinite",
                    }} />
                  )}
                </div>
                {i < STEPS.length - 1 && (
                  <div style={{
                    flex: 1, height: 2,
                    background: isDone ? "#16A34A" : "#E7E5E4",
                    transition: "background 0.4s",
                  }} />
                )}
              </div>
              <div style={{ marginTop: 8, paddingRight: 8 }}>
                <div style={{ fontSize: 13, fontWeight: isActive || isDone ? 600 : 400, color: isActive || isDone ? "#1C1917" : "#A8A29E" }}>
                  {step.label}
                </div>
                <div style={{ fontSize: 11, color: "#A8A29E" }}>
                  {isDone ? "Complete" : isActive ? "Running…" : step.desc}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

function AgentGrid({ progress, response }) {
  const agents = getDisplayAgents(progress, response);
  if (!agents.length) return null;
  const complete = agents.filter(a => a.status === "complete").length;
  return (
    <Card>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
        <SectionLabel>Agent status</SectionLabel>
        <div style={{ fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", color: "#A8A29E", marginBottom: 14 }}>
          {complete}/{agents.length} complete
        </div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
        {agents.map((agent) => (
          <div key={agent.id} style={{
            padding: "12px 14px", borderRadius: 10,
            border: agent.status === "running" ? "1px solid #A8A29E" : "1px solid #F5F5F4",
            background: agent.status === "running" ? "#F7F7F6" : agent.status === "complete" ? "#FAFAF9" : "#fff",
            transition: "all 0.3s",
          }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "#1C1917" }}>{agent.name}</div>
              <StatusDot status={agent.status} />
            </div>
            <div style={{ fontSize: 11, color: "#A8A29E", lineHeight: 1.4 }}>{agent.desc}</div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function SampleOverview({ report, jobStatus }) {
  const score = report ? Math.round((report.severity_score || 0) * 10) : 0;
  const classification = report?.malware_family || report?.malware_type || null;
  const mitre = report?.mitre_attack?.slice(0, 4) || [];
  const running = jobStatus === "running" || jobStatus === "queued";

  return (
    <Card style={{ display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
        <SectionLabel>Sample overview</SectionLabel>
        {report && <SeverityBadge severity={report.severity} />}
      </div>
      {classification ? (
        <div style={{ display: "flex", alignItems: "flex-start", gap: 20, flex: 1 }}>
          <RiskGauge score={score} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 20, fontWeight: 700, letterSpacing: "-0.02em", marginBottom: 4, color: "#1C1917" }}>
              {classification}
            </div>
            <div style={{ fontSize: 12, color: "#78716C", lineHeight: 1.6, marginBottom: 10 }}>
              {report.executive_summary}
            </div>
            {mitre.length > 0 && (
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {mitre.map((t, i) => (
                  <span key={i} style={{
                    fontSize: 11, fontFamily: "'IBM Plex Mono', monospace",
                    padding: "2px 8px", borderRadius: 4, background: "#F0F0EE", color: "#1C1917", fontWeight: 500,
                  }}>{t.id}</span>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "#D6D3D1", fontSize: 13, minHeight: 80 }}>
          {running ? "Analysis in progress…" : "Awaiting sample"}
        </div>
      )}
    </Card>
  );
}

function ReasoningTrace({ events }) {
  const traceRef = useRef(null);
  useEffect(() => {
    if (traceRef.current) traceRef.current.scrollTop = traceRef.current.scrollHeight;
  }, [events]);

  const agentColor = (src) => {
    if (!src) return "#78716C";
    const s = src.toLowerCase();
    if (s.includes("static"))   return "#7C3AED";
    if (s.includes("scenario")) return "#2563EB";
    if (s.includes("network") || s.includes("filesystem") || s.includes("registry") || s.includes("intel")) return "#0891B2";
    if (s.includes("critic"))   return "#059669";
    if (s.includes("report"))   return "#7C3AED";
    if (s.includes("response") || s.includes("blocklist") || s.includes("alert") || s.includes("ticket")) return "#D97706";
    return "#78716C";
  };

  return (
    <Card style={{ maxHeight: 380, display: "flex", flexDirection: "column" }}>
      <SectionLabel>Agent reasoning trace</SectionLabel>
      <div ref={traceRef} style={{ overflow: "auto", flex: 1 }}>
        {!events?.length ? (
          <div style={{ color: "#D6D3D1", fontSize: 13, padding: "20px 0", textAlign: "center" }}>No activity yet</div>
        ) : (
          events.map((e, i) => (
            <div key={i} style={{
              display: "flex", gap: 10, padding: "8px 0",
              borderBottom: i < events.length - 1 ? "1px solid #F5F5F4" : "none",
              animation: "slideIn 0.3s ease",
            }}>
              <span style={{ fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", color: "#A8A29E", flexShrink: 0, marginTop: 2 }}>
                {new Date(e.timestamp * 1000).toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" })}
              </span>
              <div>
                <span style={{ fontSize: 11, fontWeight: 600, textTransform: "uppercase", fontFamily: "'IBM Plex Mono', monospace", color: agentColor(e.source) }}>
                  {e.source}
                </span>
                <p style={{ fontSize: 13, color: "#44403C", marginTop: 2, lineHeight: 1.5 }}>{e.message}</p>
              </div>
            </div>
          ))
        )}
      </div>
    </Card>
  );
}

function IOCList({ iocs }) {
  const flat = [];
  if (iocs) {
    (iocs.ips     || []).forEach(v => flat.push({ type: "IP",     value: v, severity: "high" }));
    (iocs.domains || []).forEach(v => flat.push({ type: "DOMAIN", value: v, severity: "high" }));
    (iocs.urls    || []).forEach(v => flat.push({ type: "URL",    value: v, severity: "critical" }));
    (iocs.hashes  || []).forEach(v => flat.push({ type: "HASH",   value: v, severity: "info" }));
    (iocs.files   || []).forEach(v => flat.push({ type: "FILE",   value: v, severity: "medium" }));
  }

  const typeStyle = (t) => {
    if (t === "URL")    return { bg: "#FEF2F2", color: "#991B1B" };
    if (t === "IP")     return { bg: "#FFF7ED", color: "#9A3412" };
    if (t === "DOMAIN") return { bg: "#F0F0EE", color: "#44403C" };
    if (t === "HASH")   return { bg: "#F0F9FF", color: "#075985" };
    return { bg: "#F5F5F4", color: "#78716C" };
  };

  return (
    <Card style={{ maxHeight: 380, display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
        <SectionLabel>Indicators of compromise</SectionLabel>
        <div style={{ fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", color: "#A8A29E", marginBottom: 14 }}>
          {flat.length} found
        </div>
      </div>
      <div style={{ overflow: "auto", flex: 1 }}>
        {flat.length === 0 ? (
          <div style={{ color: "#D6D3D1", fontSize: 13, padding: "20px 0", textAlign: "center" }}>No indicators extracted yet</div>
        ) : (
          flat.map((f, i) => {
            const ts = typeStyle(f.type);
            return (
              <div key={i} style={{
                display: "flex", alignItems: "center", gap: 10, padding: "8px 0",
                borderBottom: i < flat.length - 1 ? "1px solid #F5F5F4" : "none",
                animation: "fadeUp 0.3s ease",
              }}>
                <span style={{
                  fontSize: 10, fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600,
                  padding: "2px 8px", borderRadius: 4, background: ts.bg, color: ts.color,
                  minWidth: 52, textAlign: "center", flexShrink: 0,
                }}>{f.type}</span>
                <span style={{
                  fontSize: 12, fontFamily: "'IBM Plex Mono', monospace", color: "#1C1917",
                  flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>{f.value}</span>
                <SeverityBadge severity={f.severity} />
              </div>
            );
          })
        )}
      </div>
    </Card>
  );
}

// ── Section: Evidence ──────────────────────────────────────────────────────────

function EvidenceSection({ progress }) {
  const f = progress?.static?.findings;
  if (!f) return (
    <div style={{ color: "#D6D3D1", fontSize: 13, textAlign: "center", paddingTop: 60 }}>
      Run analysis to see static artifacts
    </div>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <Card>
        <SectionLabel>File metadata</SectionLabel>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16 }}>
          {[
            ["File type", f.file_type],
            ["File size", f.file_size ? `${(f.file_size / 1024).toFixed(1)} KB` : "—"],
            ["Entropy", f.entropy != null ? `${f.entropy} / 8.0` : "—"],
            ["MD5", f.hashes?.md5],
            ["SHA-1", f.hashes?.sha1],
            ["SHA-256", f.hashes?.sha256],
          ].map(([label, value]) => (
            <div key={label}>
              <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>{label}</div>
              <div style={{ fontSize: 12, fontFamily: "'IBM Plex Mono', monospace", color: "#1C1917", wordBreak: "break-all" }}>{value || "—"}</div>
            </div>
          ))}
        </div>
      </Card>

      {f.yara_matches?.length > 0 && (
        <Card>
          <SectionLabel>YARA matches ({f.yara_matches.length})</SectionLabel>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {f.yara_matches.map((m, i) => (
              <span key={i} style={{
                fontSize: 12, fontFamily: "'IBM Plex Mono', monospace",
                padding: "4px 10px", borderRadius: 6, background: "#FEF2F2", color: "#991B1B",
                border: "1px solid #FECACA",
              }}>{m}</span>
            ))}
          </div>
        </Card>
      )}

      {f.strings?.length > 0 && (
        <Card>
          <SectionLabel>Extracted strings ({f.strings.length} shown)</SectionLabel>
          <div style={{ maxHeight: 240, overflow: "auto", display: "flex", flexDirection: "column", gap: 2 }}>
            {f.strings.map((s, i) => (
              <div key={i} style={{
                fontSize: 12, fontFamily: "'IBM Plex Mono', monospace", color: "#44403C",
                padding: "3px 8px", borderRadius: 4, background: i % 2 === 0 ? "#FAFAF9" : "#fff",
                wordBreak: "break-all",
              }}>{s}</div>
            ))}
          </div>
        </Card>
      )}

      {f.pe_info && (
        <Card>
          <SectionLabel>PE headers</SectionLabel>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12, marginBottom: 16 }}>
            {[
              ["Machine", f.pe_info.machine_type],
              ["Entry point", f.pe_info.entry_point],
              ["Image base", f.pe_info.image_base],
              ["Is DLL", f.pe_info.is_dll ? "Yes" : "No"],
            ].map(([label, value]) => (
              <div key={label}>
                <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 2 }}>{label}</div>
                <div style={{ fontSize: 12, fontFamily: "'IBM Plex Mono', monospace", color: "#1C1917" }}>{value || "—"}</div>
              </div>
            ))}
          </div>
          {f.pe_info.sections?.length > 0 && (
            <>
              <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>Sections</div>
              {f.pe_info.sections.map((sec, i) => (
                <div key={i} style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  padding: "6px 0", borderBottom: i < f.pe_info.sections.length - 1 ? "1px solid #F5F5F4" : "none",
                }}>
                  <span style={{ fontSize: 12, fontFamily: "'IBM Plex Mono', monospace", color: "#1C1917", fontWeight: 600 }}>{sec.name}</span>
                  <span style={{ fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", color: "#78716C" }}>
                    entropy: {sec.entropy} · raw: {sec.raw_size}B
                  </span>
                </div>
              ))}
            </>
          )}
        </Card>
      )}
    </div>
  );
}

// ── Section: AI Investigation ──────────────────────────────────────────────────

function AgentFindingCard({ label, findings, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen || false);
  if (!findings) return null;
  return (
    <Card style={{ marginBottom: 12 }}>
      <button onClick={() => setOpen(o => !o)} style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        width: "100%", background: "none", border: "none", cursor: "pointer", padding: 0,
      }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: "#1C1917" }}>{label}</div>
        <span style={{ fontSize: 13, color: "#A8A29E" }}>{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <pre style={{
          marginTop: 14, fontSize: 11, fontFamily: "'IBM Plex Mono', monospace",
          color: "#44403C", background: "#FAFAF9", borderRadius: 8, padding: 14,
          overflow: "auto", maxHeight: 320, whiteSpace: "pre-wrap", wordBreak: "break-all",
          border: "1px solid #E7E5E4",
        }}>
          {JSON.stringify(findings, null, 2)}
        </pre>
      )}
    </Card>
  );
}

function InvestigationSection({ progress }) {
  if (!progress) return (
    <div style={{ color: "#D6D3D1", fontSize: 13, textAlign: "center", paddingTop: 60 }}>
      Run analysis to see agent findings
    </div>
  );
  return (
    <div>
      <AgentFindingCard label="Static Analysis"     findings={progress.static?.findings}     defaultOpen />
      <AgentFindingCard label="Behavioral Scenario" findings={progress.scenario?.findings} />
      <AgentFindingCard label="Network Forensics"   findings={progress.network?.findings} />
      <AgentFindingCard label="Filesystem Analysis" findings={progress.filesystem?.findings} />
      <AgentFindingCard label="Registry / System"   findings={progress.registry?.findings} />
      <AgentFindingCard label="Threat Intelligence" findings={progress.intel?.findings} />
      <AgentFindingCard label="Critic Review"       findings={progress.critic?.findings} />
      <AgentFindingCard label="Final Report"        findings={progress.report?.findings} />
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────────

const NAV_ITEMS = [
  { id: "overview",      label: "Overview",         section: "Command center" },
  { id: "evidence",      label: "Evidence",         section: "Static artifacts" },
  { id: "investigation", label: "AI investigation", section: "Agent reasoning" },
  { id: "response",      label: "Response plan",    section: "Containment + export" },
];

export default function App() {
  const { analyze, reset, jobId, job, uploading, error } = useAnalysis();
  const [activeNav, setActiveNav] = useState("overview");
  const [fileName, setFileName] = useState(null);
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef(null);

  const progress   = job?.progress || null;
  const report     = job?.progress?.report?.findings || null;
  const response   = job?.response || null;
  const events     = job?.events || [];
  const iocs       = report?.iocs || progress?.static?.findings?.iocs || null;
  const tools      = getTools(progress);
  const isDone     = job?.status === "complete";
  const isRunning  = job?.status === "running" || job?.status === "queued";
  const isError    = job?.status === "error";

  const handleFilePick = (file) => {
    if (!file) return;
    setFileName(file.name);
    analyze(file);
  };

  const handleReset = () => {
    reset();
    setFileName(null);
    setActiveNav("overview");
  };

  return (
    <div style={{ fontFamily: "'DM Sans', system-ui, sans-serif", minHeight: "100vh", background: "#FAFAF9", color: "#1C1917" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600;9..40,700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');
        @keyframes ping     { 75%,100% { transform: scale(2); opacity: 0; } }
        @keyframes fadeUp   { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes slideIn  { from { opacity: 0; transform: translateX(-10px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes scanline { from { transform: translateX(-100%); } to { transform: translateX(200%); } }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-thumb { background: #D6D3D1; border-radius: 2px; }
        button:focus { outline: none; }
      `}</style>

      {/* ── Header ── */}
      <header style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 32px", height: 56, borderBottom: "1px solid #E7E5E4",
        background: "#FFFFFF", position: "sticky", top: 0, zIndex: 50,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8, background: "#1C1917",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600, fontSize: 13, color: "#fff",
          }}>MS</div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600, letterSpacing: "-0.02em" }}>MalwareScope</div>
            <div style={{ fontSize: 11, color: "#A8A29E", letterSpacing: "0.02em" }}>AI-native threat analysis · Claude + Google ADK</div>
          </div>
        </div>

        <nav style={{ display: "flex", gap: 4 }}>
          {NAV_ITEMS.map((item) => (
            <button key={item.id} onClick={() => setActiveNav(item.id)} style={{
              padding: "6px 14px", fontSize: 13, fontWeight: activeNav === item.id ? 600 : 400,
              color: activeNav === item.id ? "#1C1917" : "#78716C",
              background: activeNav === item.id ? "#F0F0EE" : "transparent",
              border: "none", borderRadius: 6, cursor: "pointer",
              fontFamily: "'DM Sans', system-ui", transition: "all 0.15s",
            }}>{item.label}</button>
          ))}
        </nav>

        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {isRunning && (
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, fontFamily: "'IBM Plex Mono', monospace", color: "#1C1917" }}>
              <StatusDot status="running" />
              Analyzing…
            </div>
          )}
          {isDone && jobId && (
            <button onClick={() => downloadReport(jobId)} style={{
              padding: "7px 16px", fontSize: 13, fontWeight: 500,
              background: "#fff", color: "#1C1917", border: "1px solid #D6D3D1",
              borderRadius: 6, cursor: "pointer", fontFamily: "'DM Sans', system-ui",
            }}>Export JSON</button>
          )}
          {job && (
            <button onClick={handleReset} style={{
              padding: "7px 16px", fontSize: 13, fontWeight: 500,
              background: "transparent", color: "#78716C", border: "1px solid #E7E5E4",
              borderRadius: 6, cursor: "pointer", fontFamily: "'DM Sans', system-ui",
            }}>New analysis</button>
          )}
        </div>
      </header>

      {/* ── Body ── */}
      <div style={{ display: "flex", minHeight: "calc(100vh - 56px)" }}>

        {/* Sidebar */}
        <aside style={{
          width: 220, borderRight: "1px solid #E7E5E4", background: "#FFFFFF",
          padding: "24px 16px", flexShrink: 0, position: "sticky", top: 56,
          height: "calc(100vh - 56px)", overflow: "auto",
        }}>
          <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 12 }}>
            Investigation view
          </div>
          {NAV_ITEMS.map((item) => (
            <button key={item.id} onClick={() => setActiveNav(item.id)} style={{
              display: "block", width: "100%", padding: "10px 12px", marginBottom: 2,
              textAlign: "left", border: "none", borderRadius: 8, cursor: "pointer",
              background: activeNav === item.id ? "#F0F0EE" : "transparent",
              fontFamily: "'DM Sans', system-ui", transition: "all 0.15s",
            }}>
              <div style={{ fontSize: 14, fontWeight: activeNav === item.id ? 600 : 400, color: activeNav === item.id ? "#1C1917" : "#44403C" }}>
                {item.label}
              </div>
              <div style={{ fontSize: 11, color: "#A8A29E", marginTop: 1 }}>{item.section}</div>
            </button>
          ))}

          <div style={{ marginTop: 32, fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 12 }}>
            Analysis tools
          </div>
          {tools.map((tool, i) => (
            <div key={i} style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              padding: "8px 12px", marginBottom: 2, borderRadius: 8,
              background: tool.done ? "#F5F5F4" : "transparent",
              animation: tool.done ? "fadeUp 0.3s ease" : "none",
            }}>
              <div style={{ fontSize: 12, fontWeight: 500, color: "#44403C" }}>{tool.name}</div>
              {tool.done ? (
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ fontSize: 10, fontFamily: "'IBM Plex Mono', monospace", color: "#A8A29E" }}>{tool.time}</span>
                  <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#16A34A" }} />
                </div>
              ) : (
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#E7E5E4" }} />
              )}
            </div>
          ))}
        </aside>

        {/* Main */}
        <main style={{ flex: 1, padding: "28px 32px", overflow: "auto", minWidth: 0 }}>

          {/* Breadcrumb */}
          <div style={{ marginBottom: 8, display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 13, fontWeight: 500, color: "#1C1917" }}>Threat analysis</span>
            <span style={{ color: "#D6D3D1" }}>/</span>
            <span style={{ fontSize: 13, color: "#A8A29E" }}>{fileName || "No sample loaded"}</span>
            {job?.status && (
              <>
                <span style={{ color: "#D6D3D1" }}>/</span>
                <span style={{
                  fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600,
                  textTransform: "uppercase", letterSpacing: "0.05em",
                  color: isDone ? "#16A34A" : isRunning ? "#1C1917" : isError ? "#DC2626" : "#A8A29E",
                }}>{job.status}</span>
              </>
            )}
          </div>

          {/* Title */}
          <h1 style={{ fontSize: 36, fontWeight: 700, letterSpacing: "-0.03em", lineHeight: 1.1, marginBottom: 8, color: "#1C1917" }}>
            {isDone ? "Analysis complete" : isRunning ? "Analyzing threat…" : "Static malware triage"}
          </h1>
          <p style={{ fontSize: 14, color: "#78716C", marginBottom: 28, maxWidth: 600, lineHeight: 1.6 }}>
            Containerized analyzers feed evidence into a multi-model AI pipeline that produces explainable findings, ATT&CK mappings, and remediation guidance.
          </p>

          {/* ── Upload zone ── */}
          <div
            onClick={() => !job && fileInputRef.current?.click()}
            onDrop={(e) => { e.preventDefault(); setDragging(false); if (!job) handleFilePick(e.dataTransfer.files[0]); }}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            style={{
              border: job ? "1px solid #E7E5E4" : dragging ? "2px dashed #1C1917" : "2px dashed #D6D3D1",
              borderRadius: 12, padding: "18px 24px",
              display: "flex", alignItems: "center", justifyContent: "space-between",
              marginBottom: 24, cursor: job ? "default" : "pointer",
              background: dragging && !job ? "#F5F5F4" : "#FFFFFF",
              transition: "all 0.2s",
            }}
          >
            <input ref={fileInputRef} type="file" style={{ display: "none" }} onChange={(e) => handleFilePick(e.target.files[0])} />
            <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
              <div style={{
                width: 40, height: 40, borderRadius: 10,
                background: fileName ? "#F0F0EE" : "#F5F5F4",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 16, color: fileName ? "#1C1917" : "#A8A29E",
              }}>
                {fileName ? "◆" : "↑"}
              </div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 500, color: "#1C1917" }}>
                  {fileName || "Drop malware sample"}
                </div>
                <div style={{ fontSize: 12, color: "#A8A29E" }}>
                  {job ? `Job ${jobId?.slice(0,8)} · ${job.filename}` : "Supports PE, DLL, script, archive, document, or memory artifact"}
                </div>
              </div>
            </div>
            {!job && (
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                {fileName && (
                  <button onClick={(e) => { e.stopPropagation(); setFileName(null); }} style={{
                    padding: "4px 12px", fontSize: 12, background: "transparent",
                    border: "1px solid #D6D3D1", borderRadius: 6, color: "#78716C",
                    cursor: "pointer", fontFamily: "'DM Sans', system-ui",
                  }}>Clear</button>
                )}
                <button
                  onClick={(e) => { e.stopPropagation(); if (fileName) {} }}
                  disabled={!fileName || uploading}
                  style={{
                    padding: "9px 20px", fontSize: 13, fontWeight: 600,
                    background: fileName ? "#1C1917" : "#E7E5E4",
                    color: fileName ? "#fff" : "#A8A29E",
                    border: "none", borderRadius: 8,
                    cursor: fileName && !uploading ? "pointer" : "default",
                    fontFamily: "'DM Sans', system-ui", transition: "all 0.15s",
                    opacity: uploading ? 0.5 : 1,
                  }}
                >
                  {uploading ? "Uploading…" : "Run triage"}
                </button>
              </div>
            )}
            {isError && (
              <div style={{ fontSize: 12, color: "#DC2626", fontFamily: "'IBM Plex Mono', monospace" }}>
                {job.error || "Pipeline error"}
              </div>
            )}
          </div>

          {/* ── Section content ── */}
          {activeNav === "overview" && (
            <>
              {(job || uploading) && (
                <PipelineBar progress={progress} jobStatus={job?.status} />
              )}

              {job && (
                <>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }}>
                    <AgentGrid progress={progress} response={response} />
                    <SampleOverview report={report} jobStatus={job.status} />
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
                    <ReasoningTrace events={events} />
                    <IOCList iocs={iocs} />
                  </div>
                </>
              )}

              {!job && !uploading && (
                <div style={{ textAlign: "center", paddingTop: 60 }}>
                  <div style={{ fontSize: 48, marginBottom: 12 }}>◆</div>
                  <div style={{ fontSize: 16, fontWeight: 500, color: "#78716C" }}>Drop a sample above to begin</div>
                  <div style={{ fontSize: 13, color: "#A8A29E", marginTop: 6 }}>
                    The ADK multi-agent pipeline will run autonomously
                  </div>
                </div>
              )}
            </>
          )}

          {activeNav === "evidence" && <EvidenceSection progress={progress} />}
          {activeNav === "investigation" && <InvestigationSection progress={progress} />}
          {activeNav === "response" && (
            <div style={{ maxWidth: 800 }}>
              <ResponsePanel response={response} />
            </div>
          )}

        </main>
      </div>
    </div>
  );
}
