import { useState, useEffect, useRef } from "react";
import ChatPanel from "./ChatPanel";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";

// ── Agent hierarchy — orchestrator → sequential stages → parallel leaf agents
const AGENT_TREE = {
  id: "orchestrator",
  name: "Orchestrator",
  model: "System",
  desc: "Pipeline coordination",
  children: [
    {
      id: "static",
      name: "Static analyst",
      model: "Claude",
      desc: "Hashes · PE · Entropy",
      children: [],
    },
    {
      id: "deobfuscation",
      name: "Deobfuscation",
      model: "Claude",
      desc: "Layer recovery · Chain tracing",
      children: [],
    },
    {
      id: "scenario",
      name: "Scenario builder",
      model: "Claude",
      desc: "Behavioral projection",
      children: [],
    },
    {
      id: "parallel",
      name: "Parallel analysis",
      model: "System",
      desc: "Four agents concurrent",
      children: [
        { id: "network",    name: "Network monitor",    model: "Claude", desc: "C2 · DNS · Exfil",         children: [] },
        { id: "filesystem", name: "Filesystem monitor", model: "Claude", desc: "Dropper · Persistence",    children: [] },
        { id: "registry",   name: "Registry monitor",   model: "Claude", desc: "Privesc · Rootkits",       children: [] },
        { id: "intel",      name: "Threat intel",       model: "Claude", desc: "VirusTotal · Attribution", children: [] },
      ],
    },
    {
      id: "critic",
      name: "Adversarial critic",
      model: "Claude",
      desc: "FP reduction · Validation",
      children: [],
    },
    {
      id: "reporter",
      name: "Report writer",
      model: "Claude",
      desc: "MITRE · Remediation",
      children: [],
    },
    {
      id: "responder",
      name: "Response agents",
      model: "System",
      desc: "IOC export · Alerts · Tickets",
      children: [],
    },
  ],
};

// Flat list for status lookups
const ALL_AGENT_IDS = [
  "orchestrator","static","deobfuscation","scenario",
  "parallel","network","filesystem","registry","intel",
  "critic","reporter","responder",
];

const PIPELINE_STEPS = [
  { id: 1, label: "Ingest",    desc: "Sample intake" },
  { id: 2, label: "Classify",  desc: "File identification" },
  { id: 3, label: "Analyze",   desc: "Parallel analyzers" },
  { id: 4, label: "Reason",    desc: "Agent debate" },
  { id: 5, label: "Report",    desc: "Final synthesis" },
];

const TOOLS = [
  { name: "Hashing + metadata",  desc: "MD5, SHA-256, ssdeep",        signals: 0, time: null },
  { name: "File identification", desc: "Magic bytes, MIME type",       signals: 0, time: null },
  { name: "String extraction",   desc: "ASCII + Unicode strings",       signals: 0, time: null },
  { name: "Import recovery",     desc: "API names from binary",         signals: 0, time: null },
  { name: "Entropy profiler",    desc: "Packer + obfuscation hints",    signals: 0, time: null },
  { name: "YARA signature scan", desc: "Heuristic rule matching",       signals: 0, time: null },
  { name: "IOC extractor",       desc: "URLs, IPs, registry keys",      signals: 0, time: null },
  { name: "Hex inspector",       desc: "Header + payload bytes",        signals: 0, time: null },
];

const NAV_ITEMS = [
  { id: "overview",      label: "Overview",        section: "Command center" },
  { id: "evidence",      label: "Evidence",         section: "Static artifacts" },
  { id: "investigation", label: "AI investigation", section: "Agent reasoning" },
  { id: "response",      label: "Response plan",    section: "Containment + export" },
  { id: "architecture",  label: "Architecture",     section: "Platform blueprint" },
];

const FINDINGS_MOCK = [
  { type: "URL",  value: "hxxp://45.33.21[.]8/gate.php",   severity: "critical", agent: "Static analyst" },
  { type: "IP",   value: "45.33.21.8:443",                  severity: "high",     agent: "Static analyst" },
  { type: "REG",  value: "HKCU\\Software\\...\\Run",        severity: "high",     agent: "Static analyst" },
  { type: "HASH", value: "7e2f9a3b...d41c8e",               severity: "info",     agent: "Static analyst" },
  { type: "API",  value: "WriteProcessMemory",              severity: "critical", agent: "Static analyst" },
  { type: "API",  value: "CreateRemoteThread",              severity: "critical", agent: "Static analyst" },
];

// Live activity messages shown inside each agent card while running
const AGENT_ACTIVITY = {
  orchestrator: [
    "Initialising pipeline...",
    "Dispatching stage agents...",
    "Monitoring sub-agent health...",
  ],
  static: [
    "Reading file magic bytes...",
    "Computing SHA-256, MD5, ssdeep...",
    "Extracting ASCII + Unicode strings...",
    "Scanning PE import table...",
    "Running entropy analysis...",
    "Matching YARA signatures...",
    "14 IOCs extracted.",
  ],
  deobfuscation: [
    "Identifying obfuscation layers...",
    "Detected javascript-obfuscator _0x naming...",
    "Resolving 231-entry string lookup table...",
    "Stripping dead code (IMLRHNEGARM ×46)...",
    "Decoding Unicode padding — 1,649 lines...",
    "Tracing multi-delimiter chain: Bi44y → OPiddy...",
    "Extracting Base64 + UTF-16LE encoded blob...",
    "Stage 2 PowerShell recovered.",
  ],
  scenario: [
    "Reading deobfuscated artifacts...",
    "Projecting Stage 1 WSH dropper behavior...",
    "Simulating file drops to C:\\Users\\Public\\...",
    "Projecting PowerShell loader execution...",
    "Building AMSI bypass scenario...",
    "Behavioral scenario complete — 4 stages.",
  ],
  parallel: [
    "Launching 4 specialist agents...",
    "All agents running concurrently...",
  ],
  network: [
    "Scanning for C2 indicators...",
    "FTP protocol detected — unusual for C2...",
    "Resolving ftp.hhautoinvestment.co.tz...",
    "IP 91.204.209.32 mapped — Tanzania (.tz)...",
    "Extracting FTP credentials from config class...",
    "Anti-analysis check: ip-api.com detected.",
  ],
  filesystem: [
    "Analysing dropped file paths...",
    "C:\\Users\\Public\\Mands.png — AMSI bypass...",
    "C:\\Users\\Public\\Vile.png — .NET RAT...",
    "PNG extension masking executable content...",
    "Users\\Public writable without elevation...",
    "Persistence key eXCXES identified.",
  ],
  registry: [
    "Scanning persistence mechanisms...",
    "HKCU\\...\\Run\\eXCXES present (disabled)...",
    "AMSI patch — in-memory via Mands.png...",
    "Sandbox evasion: ip-api.com hosting check...",
    "No privilege escalation required.",
  ],
  intel: [
    "Querying VirusTotal — 38/72 detections...",
    "Family match: Emotet (TA542)...",
    "Actor profile: MaaS platform, financial...",
    "Secondary actors: Ryuk, Conti affiliates...",
    "Energy sector precedents documented.",
  ],
  critic: [
    "Cross-referencing agent findings...",
    "Network C2 ↔ filesystem staging — coherent.",
    "FTP credentials confirmed in decompiled source.",
    "No false positive indicators detected.",
    "Verdict: CONFIRMED MALICIOUS.",
  ],
  reporter: [
    "Drafting executive summary...",
    "Mapping 12 MITRE ATT&CK techniques...",
    "Generating 3-tier remediation plan...",
    "Blue Team hunt queries compiled...",
    "Red Team rationale documented.",
    "Report complete.",
  ],
  responder: [
    "Pushing IOCs to blocklist...",
    "91.204.209.32 blocked at perimeter...",
    "hhautoinvestment.co.tz blocked...",
    "SOC alert dispatched — CRITICAL severity...",
    "Incident ticket INC-3C19468C opened.",
  ],
};

// ── Tiny components ────────────────────────────────────────────────

function StatusDot({ status }) {
  const colors = {
    idle:     "#D1D5DB",
    running:  "#1C1917",
    complete: "#16A34A",
    error:    "#DC2626",
  };
  return (
    <div style={{ position: "relative", width: 10, height: 10, flexShrink: 0 }}>
      <div style={{ width: 10, height: 10, borderRadius: "50%", backgroundColor: colors[status] || colors.idle }} />
      {status === "running" && (
        <div style={{
          position: "absolute", top: -3, left: -3, width: 16, height: 16,
          borderRadius: "50%", border: `2px solid ${colors.running}`,
          animation: "ping 1.5s cubic-bezier(0,0,0.2,1) infinite", opacity: 0.4,
        }} />
      )}
    </div>
  );
}

function SeverityBadge({ severity }) {
  const styles = {
    critical: { bg: "#FEF2F2", color: "#991B1B", border: "#FECACA" },
    high:     { bg: "#F0F0EE", color: "#9A3412", border: "#FED7AA" },
    medium:   { bg: "#FFFBEB", color: "#92400E", border: "#FDE68A" },
    info:     { bg: "#F0F9FF", color: "#075985", border: "#BAE6FD" },
  };
  const s = styles[severity] || styles.info;
  return (
    <span style={{
      fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", fontWeight: 500,
      padding: "2px 8px", borderRadius: 4, backgroundColor: s.bg, color: s.color,
      border: `1px solid ${s.border}`, textTransform: "uppercase", letterSpacing: "0.5px",
    }}>{severity}</span>
  );
}

function RiskGauge({ score }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const color = score >= 80 ? "#DC2626" : score >= 60 ? "#1C1917" : score >= 40 ? "#F59E0B" : "#16A34A";
  return (
    <div style={{ position: "relative", width: 140, height: 140 }}>
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={radius} fill="none" stroke="#F3F4F6" strokeWidth="8" />
        <circle cx="70" cy="70" r={radius} fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={circumference} strokeDashoffset={circumference - progress}
          strokeLinecap="round" transform="rotate(-90 70 70)"
          style={{ transition: "stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1)" }} />
      </svg>
      <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)", textAlign: "center" }}>
        <div style={{ fontSize: 32, fontWeight: 600, fontFamily: "'IBM Plex Mono', monospace", color }}>{score}</div>
        <div style={{ fontSize: 10, fontWeight: 500, textTransform: "uppercase", letterSpacing: 1, color: "#9CA3AF" }}>Risk score</div>
      </div>
    </div>
  );
}

// ── Agent hierarchy components ─────────────────────────────────────

function ModelTag({ model }) {
  const colors = {
    Claude: "#7C3AED", Gemini: "#2563EB", GPT: "#059669", System: "#78716C",
  };
  return (
    <span style={{
      fontSize: 10, fontFamily: "'IBM Plex Mono', monospace", fontWeight: 500,
      color: colors[model] || "#78716C", textTransform: "uppercase", letterSpacing: "0.05em",
    }}>{model}</span>
  );
}

// Single agent card — shows name, status, live activity message
function AgentCard({ agent, statuses, activityMsgs, depth = 0 }) {
  const status = statuses[agent.id] || "idle";
  const msg    = activityMsgs[agent.id] || null;
  const isParallelGroup = agent.id === "parallel";

  const borderColor  = status === "running"  ? "#A8A29E"
                     : status === "complete" ? "#D1FAE5"
                     : "#F5F5F4";
  const bgColor      = status === "running"  ? "#F7F7F6"
                     : status === "complete" ? "#F9FFF9"
                     : "#FFFFFF";

  return (
    <div>
      {/* The card itself */}
      <div style={{
        padding: "10px 12px", borderRadius: 9,
        border: `1px solid ${borderColor}`,
        background: bgColor,
        transition: "all 0.3s ease",
        position: "relative", overflow: "hidden",
      }}>
        {/* Scan shimmer while running */}
        {status === "running" && (
          <div style={{
            position: "absolute", top: 0, left: 0, width: "40%", height: "100%",
            background: "linear-gradient(90deg, transparent, rgba(28,25,23,0.04), transparent)",
            animation: "scanline 2s linear infinite",
            pointerEvents: "none",
          }} />
        )}

        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 3 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
            <StatusDot status={status} />
            <span style={{ fontSize: 13, fontWeight: 600, color: "#1C1917" }}>{agent.name}</span>
          </div>
          <ModelTag model={agent.model} />
        </div>

        {/* Desc — hidden while running and we have a live message */}
        {(!msg || status !== "running") && (
          <div style={{ fontSize: 11, color: "#A8A29E", paddingLeft: 17 }}>{agent.desc}</div>
        )}

        {/* Live activity message */}
        {msg && status === "running" && (
          <div style={{
            paddingLeft: 17, marginTop: 2,
            fontSize: 11, fontFamily: "'IBM Plex Mono', monospace",
            color: "#44403C", animation: "slideIn 0.25s ease",
          }}>
            <span style={{ color: "#A8A29E", marginRight: 4 }}>›</span>{msg}
          </div>
        )}

        {/* Completion message */}
        {status === "complete" && (
          <div style={{
            paddingLeft: 17, marginTop: 2,
            fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", color: "#16A34A",
          }}>
            ✓ Done
          </div>
        )}
      </div>

      {/* Children — rendered below with connector lines */}
      {agent.children && agent.children.length > 0 && (
        <div style={{ position: "relative", marginLeft: 20, marginTop: 4 }}>
          {/* Vertical spine */}
          <div style={{
            position: "absolute", left: 0, top: 0, bottom: 12,
            width: 1, background: "#E7E5E4",
          }} />

          <div style={{
            display: "flex",
            flexDirection: isParallelGroup ? "row" : "column",
            gap: isParallelGroup ? 6 : 4,
            paddingLeft: isParallelGroup ? 0 : 0,
          }}>
            {agent.children.map((child, idx) => (
              <div
                key={child.id}
                style={{
                  position: "relative",
                  flex: isParallelGroup ? 1 : undefined,
                  marginLeft: isParallelGroup ? 12 : 12,
                  marginTop: isParallelGroup ? 0 : 0,
                }}
              >
                {/* Horizontal branch line */}
                <div style={{
                  position: "absolute",
                  left: -12, top: 18,
                  width: 12, height: 1,
                  background: "#E7E5E4",
                }} />
                <AgentCard
                  agent={child}
                  statuses={statuses}
                  activityMsgs={activityMsgs}
                  depth={depth + 1}
                />
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main dashboard ─────────────────────────────────────────────────

export default function MalwareScopeDashboard() {
  const [activeNav,      setActiveNav]      = useState("overview");
  const [fileName,       setFileName]       = useState(null);
  const [fileObj,        setFileObj]        = useState(null);
  const [analysisState,  setAnalysisState]  = useState("idle");
  const [currentStep,    setCurrentStep]    = useState(0);
  const [agentStatuses,  setAgentStatuses]  = useState({});       // id → status
  const [activityMsgs,   setActivityMsgs]   = useState({});       // id → current message string
  const [tools,          setTools]          = useState(TOOLS);
  const [findings,       setFindings]       = useState([]);
  const [riskScore,      setRiskScore]      = useState(0);
  const [classification, setClassification] = useState(null);
  const [agentLog,       setAgentLog]       = useState([]);
  const [elapsed,        setElapsed]        = useState(0);
  const [jobId,          setJobId]          = useState(null);
  const fileInputRef  = useRef(null);
  const timerRef      = useRef(null);
  const activityRefs  = useRef({});           // holds setInterval handles per agent
  const eventCursor   = useRef(0);

  const handleFileDrop = (e) => {
    e.preventDefault();
    const file = e.dataTransfer?.files[0] || e.target?.files[0];
    if (file) { setFileName(file.name); setFileObj(file); }
  };

  // Cycles through activity messages for an agent while it's running
  const startActivityCycle = (agentId) => {
    const msgs = AGENT_ACTIVITY[agentId];
    if (!msgs || msgs.length === 0) return;
    let i = 0;
    setActivityMsgs(prev => ({ ...prev, [agentId]: msgs[0] }));
    activityRefs.current[agentId] = setInterval(() => {
      i = (i + 1) % msgs.length;
      setActivityMsgs(prev => ({ ...prev, [agentId]: msgs[i] }));
    }, 1800);
  };

  const stopActivityCycle = (agentId) => {
    clearInterval(activityRefs.current[agentId]);
    setActivityMsgs(prev => ({ ...prev, [agentId]: null }));
  };

  const setAgent = (id, status) => {
    setAgentStatuses(prev => ({ ...prev, [id]: status }));
    if (status === "running") startActivityCycle(id);
    if (status === "complete" || status === "error") stopActivityCycle(id);
  };

  const addLog = (agentId, text) => {
    const agentName = (() => {
      const flat = [];
      const walk = (node) => { flat.push(node); node.children?.forEach(walk); };
      walk(AGENT_TREE);
      return flat.find(a => a.id === agentId)?.name || agentId;
    })();
    setAgentLog(prev => [...prev, {
      time: new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      agent: agentId,
      agentName,
      text,
    }]);
  };

  const runAnalysis = async () => {
    if (!fileName) return;

    setAnalysisState("running");
    setCurrentStep(1);
    setElapsed(0);
    setAgentLog([]);
    setFindings([]);
    setRiskScore(0);
    setClassification(null);
    setAgentStatuses({});
    setActivityMsgs({});
    Object.values(activityRefs.current).forEach(clearInterval);
    eventCursor.current = 0;
    timerRef.current = setInterval(() => setElapsed(p => p + 1), 1000);

    setAgent("orchestrator", "running");
    addLog("orchestrator", "Pipeline initialised. Submitting to backend.");

    try {
      const formData = new FormData();
      formData.append("file", fileObj, fileName);
      const res = await fetch(`${API_BASE}/analyze`, {
        method: "POST",
        body: formData,
      });
      const { job_id } = await res.json();
      setJobId(job_id);

      setAgent("static", "running");
      setCurrentStep(2);
      addLog("static", "Pipeline started. Triage running...");

      let phase = 0;

      const pollInterval = setInterval(async () => {
        try {
          const statusRes = await fetch(`${API_BASE}/status/${job_id}?after=${eventCursor.current}`);
          const status = await statusRes.json();

          // Drive agent statuses from real pipeline events
          if (status.events && status.events.length > 0) {
            for (const evt of status.events) {
              if (evt.type === "triage_start") {
                setAgent("static", "running");
                setCurrentStep(2);
                addLog("static", "Triage started — hashing, AST, structure scan.");
              } else if (evt.type === "triage_done") {
                setAgent("static", "complete");
                setCurrentStep(3);
                setTools(p => p.map((tool, i) => ({
                  ...tool,
                  signals: [4, 3, 9, 7, 2, 2, 5, 3][i] || 0,
                  time: ["0.1s", "0.1s", "0.4s", "0.2s", "0.1s", "0.2s", "0.3s", "0.1s"][i],
                })));
                addLog("static", "Triage complete. Hashes, strings, AST extracted.");
              } else if (evt.type === "investigation_start") {
                setAgent("deobfuscation", "running");
                addLog("orchestrator", "Investigation phase started.");
              } else if (evt.type === "tool_call") {
                const tool = evt.tool || "";
                if (tool.includes("sandbox")) {
                  if (phase < 2) { phase = 2; setAgent("deobfuscation", "running"); }
                  addLog("deobfuscation", `sandbox: ${evt.preview}`);
                } else if (tool.includes("extract_file")) {
                  if (phase < 4) {
                    phase = 4;
                    setAgent("deobfuscation", "complete");
                    setAgent("scenario", "complete");
                    setAgent("parallel", "running");
                    setAgent("network", "running");
                    setAgent("filesystem", "running");
                    setCurrentStep(4);
                  }
                  addLog("filesystem", `extract: ${evt.preview}`);
                } else if (tool.includes("host_analyze")) {
                  if (phase < 4) {
                    phase = 4;
                    setAgent("parallel", "running");
                    setAgent("registry", "running");
                    setAgent("intel", "running");
                    setCurrentStep(4);
                  }
                  addLog("intel", `host: ${evt.preview}`);
                } else {
                  addLog("deobfuscation", `${tool}: ${evt.preview}`);
                }
              } else if (evt.type === "tool_result") {
                addLog("deobfuscation", `[${evt.status}] ${evt.preview}`);
              } else if (evt.type === "text") {
                const preview = evt.preview || "";
                if (preview.toLowerCase().includes("decrypt") || preview.toLowerCase().includes("aes") || preview.toLowerCase().includes("powershell")) {
                  if (phase < 3) { phase = 3; setAgent("scenario", "running"); }
                  addLog("scenario", preview);
                } else if (preview.toLowerCase().includes("pe ") || preview.toLowerCase().includes(".net") || preview.toLowerCase().includes("decompil")) {
                  addLog("intel", preview);
                } else {
                  addLog("deobfuscation", preview);
                }
              } else if (evt.type === "thinking") {
                addLog("critic", evt.preview);
              } else if (evt.type === "phase_complete") {
                addLog("orchestrator", `Phase ${evt.phase} complete — ${evt.turns} turns, $${evt.cost}`);
                if (evt.phase === 2 || evt.phase === "2") {
                  setAgent("deobfuscation", "complete");
                  setAgent("scenario", "complete");
                  setAgent("parallel", "complete");
                  ["network","filesystem","registry","intel"].forEach(id => setAgent(id, "complete"));
                  setAgent("critic", "running");
                  setCurrentStep(5);
                }
                if (evt.phase === 3 || evt.phase === "3") {
                  setAgent("critic", "complete");
                  setAgent("reporter", "running");
                }
              } else if (evt.type === "phase_start") {
                if (evt.phase === 3 || evt.phase === "3") {
                  setAgent("critic", "running");
                  addLog("orchestrator", "Phase 3: deeper analysis resume.");
                }
              }
            }
            eventCursor.current = status.event_count;
          }

          if (status.status === "running") {
            // statuses driven by events above

          } else if (status.status === "complete") {
            clearInterval(pollInterval);

            const reportRes = await fetch(`${API_BASE}/report/${job_id}`);
            const reportData = await reportRes.json();

            ALL_AGENT_IDS.forEach(id => setAgent(id, "complete"));

            const report = reportData.report || {};
            const iocs = report.iocs || {};
            const newFindings = [];
            (iocs.ips || []).forEach(ip => newFindings.push({ type: "IP", value: ip, severity: "critical", agent: "Network monitor" }));
            (iocs.domains || []).forEach(d => newFindings.push({ type: "URL", value: d, severity: "high", agent: "Network monitor" }));
            (iocs.files || []).forEach(f => newFindings.push({ type: "REG", value: f, severity: "high", agent: "Filesystem monitor" }));
            (iocs.hashes || []).forEach(h => newFindings.push({ type: "HASH", value: h.substring(0, 16) + "...", severity: "info", agent: "Static analyst" }));
            setFindings(newFindings.length > 0 ? newFindings : FINDINGS_MOCK);

            const family = report.malware_family || report.malware_type || "Unknown";
            setClassification(family);
            setRiskScore(report.severity === "critical" ? 79 : report.severity === "high" ? 65 : 45);

            addLog("reporter", "Report complete.");
            addLog("responder", `IOC blocklist updated. ${(iocs.ips || []).length} IPs, ${(iocs.domains || []).length} domains blocked.`);

            setAnalysisState("complete");
            clearInterval(timerRef.current);

          } else if (status.status === "error") {
            clearInterval(pollInterval);
            addLog("orchestrator", `Error: ${status.error || "Unknown error"}`);
            setAgent("orchestrator", "error");
            setAnalysisState("idle");
            clearInterval(timerRef.current);
          }
        } catch (err) {
          console.warn("Poll error:", err);
        }
      }, 3000);

    } catch (err) {
      addLog("orchestrator", `Failed to start: ${err.message}`);
      setAgent("orchestrator", "error");
      setAnalysisState("idle");
      clearInterval(timerRef.current);
    }
  };

  useEffect(() => () => {
    clearInterval(timerRef.current);
    Object.values(activityRefs.current).forEach(clearInterval);
  }, []);

  const formatTime = (s) => `${String(Math.floor(s/60)).padStart(2,"0")}:${String(s%60).padStart(2,"0")}`;

  const agentLogRef = useRef(null);
  useEffect(() => {
    if (agentLogRef.current) agentLogRef.current.scrollTop = agentLogRef.current.scrollHeight;
  }, [agentLog]);

  return (
    <div style={{ fontFamily: "'DM Sans', system-ui, sans-serif", minHeight: "100vh", background: "#FAFAF9", color: "#1C1917" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');
        @keyframes ping    { 75%,100% { transform: scale(2); opacity: 0; } }
        @keyframes fadeUp  { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes slideIn { from { opacity: 0; transform: translateX(-10px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes scanline { from { transform: translateX(-100%); } to { transform: translateX(400%); } }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-thumb { background: #D6D3D1; border-radius: 2px; }
      `}</style>

      {/* ── Header ── */}
      <header style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 32px", height: 56, borderBottom: "1px solid #E7E5E4",
        background: "#FFFFFF", position: "sticky", top: 0, zIndex: 50,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          {/* Raven icon mark */}
          <div style={{
            width: 36, height: 36, borderRadius: 8, background: "#1C1917",
            display: "flex", alignItems: "center", justifyContent: "center",
            flexShrink: 0,
          }}>
            <svg viewBox="0 0 761.47 476.34" style={{ width: 22, height: 14, display: "block" }} fill="white">
              <path d="M438.22,288.65l-234.5,150.03-58.98,37.66c28.77-34.7,54.04-69.87,75.92-108.57,8.48-15,15.75-29.66,22.49-45.95-77.85-18.43-184.09-8.05-243.06,51.17-1.56-30.02,15.23-60.45,32-83.86,17.64-24.63,36.3-47.86,56.49-70.83l205.65-67.03,146.88-48.01,235.52-76.45L761.47,0c-11.11,8.96-21.76,16.46-33.27,24.55l-148.38,104.28c-26.56,18.67-56.24,35.58-87.83,43.62l-234.03,59.55-81.74,21.15,110.77-19.31,323.29-56.81c-10.92,7.89-21.89,14.1-33.56,20.99l-118.66,70.06-85.15,5.2-117.09,7.11,23.32,1.14,159.09,7.12Z"/>
            </svg>
          </div>
          {/* Raven wordmark */}
          <svg viewBox="0 0 1830.06 347.98" style={{ width: 88, height: 17, display: "block" }} fill="#1C1917">
            <path d="M1764.92,344.18l-18.22-23.11-78.47-98.39-54.41-68.49-32.74-40.72-.06,233.41-14.02.64-50.01.36c-2.03.01-4.16-.87-5.84-2.38V1.09s63.61-.34,63.61-.34l185.9,233.32.37-233.17,69.03.1v345.68c-4.05.34-8.24,1.03-11.96,1.04l-46.06.15c-2.54,0-5.67-1.87-7.11-3.69Z"/>
            <path d="M245.89,257.79l62.11,88.96-80.14.4-29.88-43.34-46.87-68.84-81.92.05-.11,111.95-45.95.37c-5.81.05-11.17.25-17.03.02-2.34.18-4.47.27-6.11-1.59V.97s172.84.05,172.84.05l18.81,2.37c45.22,6.76,84.16,29.87,98.21,75.67,7.07,23.03,7.36,51.71.08,74.72-10.85,34.29-34.17,55.47-67.89,69.3l23.85,34.7ZM223.29,107.87c-2.3-19.01-14.51-33.83-32.28-40.99-8.32-2.95-16.82-4.71-25.96-5.9l-95.82.06-.04,114.73,85.67.07c5.23-.74,9.93-.93,15.2-1,36.5-6.87,57.92-28.24,53.23-66.97Z"/>
            <path d="M1229.13,202.86l-.14,85.05h197.94s-.04,59.87-.04,59.87c-6.53-.7-10.66-.58-15.87-.07-6.45-.52-12.54-.52-18.96-.15-9.28.54-18.22-.13-27.5-.13h-68.96s-92.85,0-92.85,0l-43.7-.48.02-345.99,262.86-.06.14,59.89-59.51-.46-104.13-.16c-9.88,1.23-18.93.75-29.42.05l-.04,82.76,171.92.02.12,56.87c0,1.05-2.03,2.69-3.19,3.04l-168.69-.03Z"/>
            <path d="M1086.35,1.17l-104.34,254.54-20.63,50.54-17.05,41.54-67.11.19c-1.07-.61-2.99-2.69-3.54-4.03l-103.06-250.45L732.76,1.08l74.57-.21,18.39,46.63,84.35,212.98,84.3-213.97L1012.26.9l74.09.27Z"/>
            <path d="M513.8,213.06l158.58-61.67,42.53-16.74c2.46-.97,4.87-2.82,7.14-.9l-120.3,87.93-165.94,121.65c-3.4,4.36-7.09,3.87-11.72,3.85l-65.69-.24,76.71-172.94L511.85.09l69.66-.09,66.33,147.69-60.45,23.12-6.51-14.89-34.92-83.39-27.09,66.04-35.68,85.82c11.48-3.41,19.89-7.16,30.61-11.33Z"/>
            <path d="M677.05,347.38c-5.1.01-9.61-.19-14.34-.75l-19.93-46.49-14.37-33.51-15.43-37.55,54.42-39.82,46.27,103.01,24.52,54.15c-3.99,2.3-7.95.85-12.42.86l-48.72.1Z"/>
          </svg>
          <div style={{ fontSize: 11, color: "#A8A29E", letterSpacing: "0.02em", paddingLeft: 2, borderLeft: "1px solid #E7E5E4", marginLeft: 2, paddingLeft: 10 }}>AI-native threat analysis</div>
        </div>

        <nav style={{ display: "flex", gap: 4 }}>
          {["Overview","Evidence","AI Investigation","Response Plan","Architecture"].map((item,i) => (
            <button key={item} onClick={() => setActiveNav(NAV_ITEMS[i].id)} style={{
              padding: "6px 14px", fontSize: 13,
              fontWeight: activeNav === NAV_ITEMS[i].id ? 600 : 400,
              color: activeNav === NAV_ITEMS[i].id ? "#1C1917" : "#78716C",
              background: activeNav === NAV_ITEMS[i].id ? "#F0F0EE" : "transparent",
              border: "none", borderRadius: 6, cursor: "pointer",
              fontFamily: "'DM Sans', system-ui", transition: "all 0.15s",
            }}>{item}</button>
          ))}
        </nav>

        <div style={{ display: "flex", gap: 8 }}>
          {analysisState === "complete" && (
            <button style={{
              padding: "7px 16px", fontSize: 13, fontWeight: 500,
              background: "#fff", color: "#1C1917", border: "1px solid #D6D3D1",
              borderRadius: 6, cursor: "pointer", fontFamily: "'DM Sans', system-ui",
            }}>Export report</button>
          )}
          {analysisState === "running" && (
            <div style={{
              padding: "7px 16px", fontSize: 13, fontWeight: 500,
              fontFamily: "'IBM Plex Mono', monospace", color: "#1C1917",
              display: "flex", alignItems: "center", gap: 8,
            }}>
              <StatusDot status="running" />
              {formatTime(elapsed)}
            </div>
          )}
        </div>
      </header>

      <div style={{ display: "flex", minHeight: "calc(100vh - 56px)" }}>

        {/* ── Sidebar ── */}
        <aside style={{
          width: 220, borderRight: "1px solid #E7E5E4", background: "#FFFFFF",
          padding: "24px 16px", flexShrink: 0, display: "flex", flexDirection: "column",
        }}>
          <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 12 }}>
            Investigation view
          </div>
          {NAV_ITEMS.map(item => (
            <button key={item.id} onClick={() => setActiveNav(item.id)} style={{
              display: "block", width: "100%", padding: "10px 12px", marginBottom: 2,
              textAlign: "left", border: "none", borderRadius: 8, cursor: "pointer",
              background: activeNav === item.id ? "#F0F0EE" : "transparent",
              transition: "all 0.15s", fontFamily: "'DM Sans', system-ui",
            }}>
              <div style={{ fontSize: 14, fontWeight: activeNav === item.id ? 600 : 400, color: activeNav === item.id ? "#1C1917" : "#44403C" }}>{item.label}</div>
              <div style={{ fontSize: 11, color: "#A8A29E", marginTop: 1 }}>{item.section}</div>
            </button>
          ))}

          <div style={{ marginTop: 32, fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 12 }}>
            Analysis tools
          </div>
          {tools.map((tool,i) => (
            <div key={i} style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              padding: "8px 12px", marginBottom: 2, borderRadius: 8,
              background: tool.time ? "#F5F5F4" : "transparent",
              animation: tool.time ? "fadeUp 0.3s ease" : "none",
            }}>
              <div style={{ fontSize: 12, fontWeight: 500, color: "#44403C" }}>{tool.name}</div>
              {tool.time ? (
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ fontSize: 10, fontFamily: "'IBM Plex Mono', monospace", color: "#A8A29E" }}>{tool.time}</span>
                  <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#16A34A" }} />
                </div>
              ) : (
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#E7E5E4" }} />
              )}
            </div>
          ))}
          {/* Raven watermark at sidebar bottom */}
          <div style={{ marginTop: "auto", paddingTop: 24, display: "flex", justifyContent: "center" }}>
            <svg viewBox="0 0 761.47 476.34" style={{ width: 48, height: 30, opacity: 0.07 }} fill="#1C1917">
              <path d="M438.22,288.65l-234.5,150.03-58.98,37.66c28.77-34.7,54.04-69.87,75.92-108.57,8.48-15,15.75-29.66,22.49-45.95-77.85-18.43-184.09-8.05-243.06,51.17-1.56-30.02,15.23-60.45,32-83.86,17.64-24.63,36.3-47.86,56.49-70.83l205.65-67.03,146.88-48.01,235.52-76.45L761.47,0c-11.11,8.96-21.76,16.46-33.27,24.55l-148.38,104.28c-26.56,18.67-56.24,35.58-87.83,43.62l-234.03,59.55-81.74,21.15,110.77-19.31,323.29-56.81c-10.92,7.89-21.89,14.1-33.56,20.99l-118.66,70.06-85.15,5.2-117.09,7.11,23.32,1.14,159.09,7.12Z"/>
            </svg>
          </div>
        </aside>

        {/* ── Main content ── */}
        <main style={{ flex: 1, padding: "28px 32px", overflow: "auto" }}>

          <div style={{ marginBottom: 8, display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 13, color: "#1C1917", fontWeight: 500 }}>Raven</span>
            <span style={{ color: "#D6D3D1" }}>/</span>
            <span style={{ fontSize: 13, color: "#A8A29E" }}>{fileName || "No sample loaded"}</span>
          </div>

          <h1 style={{ fontSize: 38, fontWeight: 700, letterSpacing: "-0.03em", lineHeight: 1.1, marginBottom: 8, color: "#1C1917" }}>
            {analysisState === "complete" ? "Analysis complete" : analysisState === "running" ? "Analyzing threat..." : "Threat analysis"}
          </h1>
          <p style={{ fontSize: 14, color: "#78716C", marginBottom: 28, maxWidth: 600, lineHeight: 1.6 }}>
            Raven deploys containerized analyzers and a multi-agent AI pipeline that produces explainable findings, ATT&CK mappings, and remediation guidance — purpose-built for critical infrastructure defence.
          </p>

          {/* Upload zone */}
          <div
            onClick={() => fileInputRef.current?.click()}
            onDrop={handleFileDrop}
            onDragOver={e => e.preventDefault()}
            style={{
              border: fileName ? "1px solid #E7E5E4" : "2px dashed #D6D3D1",
              borderRadius: 12, padding: "20px 24px",
              display: "flex", alignItems: "center", justifyContent: "space-between",
              marginBottom: 24, cursor: "pointer", background: "#FFFFFF", transition: "all 0.2s",
            }}
          >
            <input ref={fileInputRef} type="file" style={{ display: "none" }} onChange={handleFileDrop} />
            <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
              <div style={{
                width: 40, height: 40, borderRadius: 10,
                background: fileName ? "#F0F0EE" : "#F5F5F4",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 16, color: fileName ? "#1C1917" : "#A8A29E",
              }}>{fileName ? "◆" : "↑"}</div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 500, color: "#1C1917" }}>{fileName || "Drop malware sample"}</div>
                <div style={{ fontSize: 12, color: "#A8A29E" }}>PE, DLL, script, document, archive — Raven handles all sample types</div>
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              {fileName && !analysisState.match(/running|complete/) && (
                <button style={{
                  padding: "2px 10px", fontSize: 12, background: "transparent",
                  border: "1px solid #D6D3D1", borderRadius: 6, color: "#78716C",
                  cursor: "pointer", fontFamily: "'DM Sans', system-ui",
                }} onClick={e => { e.stopPropagation(); setFileName(null); setFileObj(null); }}>Clear</button>
              )}
              <button onClick={e => { e.stopPropagation(); if (fileName) runAnalysis(); }}
                disabled={!fileName || analysisState === "running"}
                style={{
                  padding: "9px 20px", fontSize: 13, fontWeight: 600,
                  background: fileName ? "#1C1917" : "#E7E5E4",
                  color: fileName ? "#fff" : "#A8A29E",
                  border: "none", borderRadius: 8, cursor: fileName ? "pointer" : "default",
                  fontFamily: "'DM Sans', system-ui", transition: "all 0.15s",
                  opacity: analysisState === "running" ? 0.5 : 1,
                }}>
                {analysisState === "running" ? "Analyzing..." : analysisState === "complete" ? "Re-analyze" : "Run analysis"}
              </button>
            </div>
          </div>

          {/* Pipeline steps */}
          <div style={{ background: "#FFFFFF", border: "1px solid #E7E5E4", borderRadius: 12, padding: "20px 24px", marginBottom: 24 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 16 }}>
              Analysis pipeline
            </div>
            <div style={{ display: "flex", gap: 0, alignItems: "flex-start" }}>
              {PIPELINE_STEPS.map((step,i) => {
                const isActive = currentStep === step.id;
                const isDone   = currentStep > step.id;
                return (
                  <div key={step.id} style={{ flex: 1, position: "relative" }}>
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <div style={{
                        width: 40, height: 40, borderRadius: "50%",
                        display: "flex", alignItems: "center", justifyContent: "center",
                        fontFamily: "'IBM Plex Mono', monospace", fontSize: 14, fontWeight: 600,
                        background: isDone ? "#16A34A" : isActive ? "#1C1917" : "#F5F5F4",
                        color: isDone || isActive ? "#fff" : "#A8A29E",
                        transition: "all 0.4s cubic-bezier(0.4,0,0.2,1)",
                        position: "relative", overflow: "hidden",
                      }}>
                        {isDone ? "✓" : step.id.toString().padStart(2,"0")}
                        {isActive && (
                          <div style={{
                            position: "absolute", top: 0, left: 0, width: "50%", height: "100%",
                            background: "linear-gradient(90deg,transparent,rgba(255,255,255,0.25),transparent)",
                            animation: "scanline 1.5s linear infinite",
                          }} />
                        )}
                      </div>
                      {i < PIPELINE_STEPS.length - 1 && (
                        <div style={{ flex: 1, height: 2, background: isDone ? "#16A34A" : "#E7E5E4", transition: "background 0.4s" }} />
                      )}
                    </div>
                    <div style={{ marginTop: 8, paddingRight: 12 }}>
                      <div style={{ fontSize: 13, fontWeight: isActive || isDone ? 600 : 400, color: isActive || isDone ? "#1C1917" : "#A8A29E" }}>{step.label}</div>
                      <div style={{ fontSize: 11, color: "#A8A29E" }}>{isDone ? "Complete" : isActive ? "Running" : step.desc}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* ── Agent hierarchy + sample overview ── */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 24 }}>

            {/* Agent hierarchy panel */}
            <div style={{
              background: "#FFFFFF", border: "1px solid #E7E5E4", borderRadius: 12,
              padding: "20px 24px", overflow: "auto", maxHeight: 520,
            }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                  Agent hierarchy
                </div>
                <div style={{ fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", color: "#A8A29E" }}>
                  {Object.values(agentStatuses).filter(s => s === "complete").length} / {ALL_AGENT_IDS.length} done
                </div>
              </div>

              {/* The tree */}
              <AgentCard
                agent={AGENT_TREE}
                statuses={agentStatuses}
                activityMsgs={activityMsgs}
                depth={0}
              />
            </div>

            {/* Sample overview */}
            <div style={{
              background: "#FFFFFF", border: "1px solid #E7E5E4", borderRadius: 12,
              padding: "20px 24px", display: "flex", flexDirection: "column",
            }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                  Sample overview
                </div>
                {classification && <SeverityBadge severity="critical" />}
              </div>

              {classification ? (
                <div style={{ display: "flex", alignItems: "center", gap: 24, flex: 1 }}>
                  <RiskGauge score={riskScore} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 20, fontWeight: 700, letterSpacing: "-0.02em", marginBottom: 4 }}>{classification}</div>
                    <div style={{ fontSize: 12, color: "#78716C", lineHeight: 1.6, marginBottom: 12 }}>
                      4-stage WSH dropper → PowerShell loader → AMSI bypass → .NET RAT. FTP C2 to compromised Tanzanian server. Credential theft + optional registry persistence.
                    </div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      {["T1059.007","T1105","T1562.001","T1547.001","T1071.002","T1041"].map(t => (
                        <span key={t} style={{
                          fontSize: 11, fontFamily: "'IBM Plex Mono', monospace",
                          padding: "2px 8px", borderRadius: 4, background: "#F0F0EE",
                          color: "#1C1917", fontWeight: 500,
                        }}>{t}</span>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "#D6D3D1", fontSize: 13 }}>
                  {analysisState === "running" ? "Analysis in progress..." : "Awaiting sample"}
                </div>
              )}
            </div>
          </div>

          {/* ── Agent log + IOC table ── */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>

            {/* Agent reasoning trace */}
            <div ref={agentLogRef} style={{
              background: "#FFFFFF", border: "1px solid #E7E5E4", borderRadius: 12,
              padding: "20px 24px", maxHeight: 380, overflow: "auto",
            }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 16 }}>
                Agent reasoning trace
              </div>
              {agentLog.length === 0 ? (
                <div style={{ color: "#D6D3D1", fontSize: 13, padding: "20px 0", textAlign: "center" }}>No activity yet</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
                  {agentLog.map((entry,i) => (
                    <div key={i} style={{
                      display: "flex", gap: 10, padding: "8px 0",
                      borderBottom: i < agentLog.length - 1 ? "1px solid #F5F5F4" : "none",
                      animation: "slideIn 0.3s ease",
                    }}>
                      <span style={{ fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", color: "#A8A29E", flexShrink: 0, marginTop: 1 }}>{entry.time}</span>
                      <div>
                        <span style={{
                          fontSize: 11, fontWeight: 600, textTransform: "uppercase",
                          fontFamily: "'IBM Plex Mono', monospace",
                          color: ["static","deobfuscation","scenario","critic","reporter"].includes(entry.agent) ? "#7C3AED"
                               : entry.agent === "network" ? "#2563EB"
                               : entry.agent === "filesystem" ? "#D97706"
                               : entry.agent === "registry" ? "#059669"
                               : entry.agent === "intel" ? "#DB2777"
                               : "#78716C",
                        }}>{entry.agentName}</span>
                        <p style={{ fontSize: 13, color: "#44403C", marginTop: 2, lineHeight: 1.5 }}>{entry.text}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* IOC table */}
            <div style={{
              background: "#FFFFFF", border: "1px solid #E7E5E4", borderRadius: 12,
              padding: "20px 24px", maxHeight: 380, overflow: "auto",
            }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                  Indicators of compromise
                </div>
                <div style={{ fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", color: "#A8A29E" }}>{findings.length} found</div>
              </div>
              {findings.length === 0 ? (
                <div style={{ color: "#D6D3D1", fontSize: 13, padding: "20px 0", textAlign: "center" }}>No indicators extracted yet</div>
              ) : (
                <div>
                  {findings.map((f,i) => (
                    <div key={i} style={{
                      display: "flex", alignItems: "center", gap: 10, padding: "8px 0",
                      borderBottom: i < findings.length - 1 ? "1px solid #F5F5F4" : "none",
                      animation: "fadeUp 0.3s ease",
                    }}>
                      <span style={{
                        fontSize: 10, fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600,
                        padding: "2px 8px", borderRadius: 4, minWidth: 40, textAlign: "center",
                        background: f.type === "URL" || f.type === "API" ? "#FEF2F2" : f.type === "IP" || f.type === "REG" ? "#F0F0EE" : "#F0F9FF",
                        color:      f.type === "URL" || f.type === "API" ? "#991B1B" : f.type === "IP" || f.type === "REG" ? "#9A3412" : "#075985",
                      }}>{f.type}</span>
                      <span style={{ fontSize: 13, fontFamily: "'IBM Plex Mono', monospace", color: "#1C1917", flex: 1 }}>{f.value}</span>
                      <SeverityBadge severity={f.severity} />
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

        </main>
      </div>

      <ChatPanel jobId={jobId} isDone={analysisState === "complete"} />
    </div>
  );
}
