import { useState, useEffect, useRef } from "react";

const AGENTS = [
  { id: "static", name: "Static analyst", model: "Claude", desc: "Hashes · PE · Entropy", status: "idle" },
  { id: "behavioral", name: "Behavioral profiler", model: "Gemini", desc: "Threat modeling", status: "idle" },
  { id: "critic", name: "Adversarial critic", model: "GPT", desc: "FP reduction · Validation", status: "idle" },
  { id: "consensus", name: "Consensus resolver", model: "Claude", desc: "Multi-model synthesis", status: "idle" },
  { id: "reporter", name: "Report writer", model: "Claude", desc: "MITRE · Remediation", status: "idle" },
  { id: "responder", name: "Response agents", model: "System", desc: "IOC export · Alerts · Tickets", status: "idle" },
];

const PIPELINE_STEPS = [
  { id: 1, label: "Ingest", desc: "Sample intake" },
  { id: 2, label: "Classify", desc: "File identification" },
  { id: 3, label: "Analyze", desc: "Parallel analyzers" },
  { id: 4, label: "Reason", desc: "Agent debate" },
  { id: 5, label: "Report", desc: "Final synthesis" },
];

const TOOLS = [
  { name: "Hashing + metadata", desc: "MD5, SHA-256, ssdeep", signals: 0, time: null },
  { name: "File identification", desc: "Magic bytes, MIME type", signals: 0, time: null },
  { name: "String extraction", desc: "ASCII + Unicode strings", signals: 0, time: null },
  { name: "Import recovery", desc: "API names from binary", signals: 0, time: null },
  { name: "Entropy profiler", desc: "Packer + obfuscation hints", signals: 0, time: null },
  { name: "YARA signature scan", desc: "Heuristic rule matching", signals: 0, time: null },
  { name: "IOC extractor", desc: "URLs, IPs, registry keys", signals: 0, time: null },
  { name: "Hex inspector", desc: "Header + payload bytes", signals: 0, time: null },
];

const NAV_ITEMS = [
  { id: "overview", label: "Overview", section: "Command center" },
  { id: "evidence", label: "Evidence", section: "Static artifacts" },
  { id: "investigation", label: "AI investigation", section: "Agent reasoning" },
  { id: "response", label: "Response plan", section: "Containment + export" },
  { id: "architecture", label: "Architecture", section: "Platform blueprint" },
];

const FINDINGS_MOCK = [
  { type: "URL", value: "hxxp://45.33.21[.]8/gate.php", severity: "critical", agent: "Static analyst" },
  { type: "IP", value: "45.33.21.8:443", severity: "high", agent: "Static analyst" },
  { type: "REG", value: "HKCU\\Software\\...\\Run", severity: "high", agent: "Static analyst" },
  { type: "HASH", value: "7e2f9a3b...d41c8e", severity: "info", agent: "Static analyst" },
  { type: "API", value: "WriteProcessMemory", severity: "critical", agent: "Static analyst" },
  { type: "API", value: "CreateRemoteThread", severity: "critical", agent: "Static analyst" },
];

function StatusDot({ status }) {
  const colors = {
    idle: "#D1D5DB",
    running: "#1C1917",
    complete: "#16A34A",
    error: "#DC2626",
  };
  return (
    <div style={{ position: "relative", width: 10, height: 10 }}>
      <div style={{
        width: 10, height: 10, borderRadius: "50%",
        backgroundColor: colors[status] || colors.idle,
      }} />
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
    high: { bg: "#F0F0EE", color: "#9A3412", border: "#FED7AA" },
    medium: { bg: "#FFFBEB", color: "#92400E", border: "#FDE68A" },
    info: { bg: "#F0F9FF", color: "#075985", border: "#BAE6FD" },
  };
  const s = styles[severity] || styles.info;
  return (
    <span style={{
      fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", fontWeight: 500,
      padding: "2px 8px", borderRadius: 4, backgroundColor: s.bg, color: s.color,
      border: `1px solid ${s.border}`, textTransform: "uppercase", letterSpacing: "0.5px",
    }}>
      {severity}
    </span>
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
          style={{ transition: "stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1)" }} />
      </svg>
      <div style={{
        position: "absolute", top: "50%", left: "50%", transform: "translate(-50%, -50%)",
        textAlign: "center",
      }}>
        <div style={{ fontSize: 32, fontWeight: 600, fontFamily: "'IBM Plex Mono', monospace", color }}>{score}</div>
        <div style={{ fontSize: 10, fontWeight: 500, textTransform: "uppercase", letterSpacing: 1, color: "#9CA3AF" }}>Risk score</div>
      </div>
    </div>
  );
}

export default function MalwareScopeDashboard() {
  const [activeNav, setActiveNav] = useState("overview");
  const [fileName, setFileName] = useState(null);
  const [analysisState, setAnalysisState] = useState("idle");
  const [currentStep, setCurrentStep] = useState(0);
  const [agents, setAgents] = useState(AGENTS);
  const [tools, setTools] = useState(TOOLS);
  const [findings, setFindings] = useState([]);
  const [riskScore, setRiskScore] = useState(0);
  const [classification, setClassification] = useState(null);
  const [agentLog, setAgentLog] = useState([]);
  const [elapsed, setElapsed] = useState(0);
  const fileInputRef = useRef(null);
  const timerRef = useRef(null);

  const handleFileDrop = (e) => {
    e.preventDefault();
    const file = e.dataTransfer?.files[0] || e.target?.files[0];
    if (file) setFileName(file.name);
  };

  const runAnalysis = () => {
    if (!fileName) return;
    setAnalysisState("running");
    setCurrentStep(1);
    setElapsed(0);
    setAgentLog([]);
    setFindings([]);
    setRiskScore(0);
    setClassification(null);

    timerRef.current = setInterval(() => setElapsed(p => p + 1), 1000);

    const agentSequence = [
      { step: 1, delay: 400, agentId: "static", log: "Ingesting sample, computing hashes..." },
      { step: 2, delay: 1800, agentId: "static", log: "PE32 executable detected. SHA-256 computed.", toolIdx: [0, 1], toolSignals: [4, 3], toolTimes: ["0.1s", "0.1s"] },
      { step: 3, delay: 3200, agentId: "static", log: "Extracting strings — found 3 C2 URLs, PowerShell cradle.", toolIdx: [2, 3, 4, 5], toolSignals: [9, 7, 2, 2], toolTimes: ["0.4s", "0.2s", "0.1s", "0.2s"] },
      { step: 3, delay: 5000, agentId: "static", log: "IOC extraction complete. 14 indicators recovered.", toolIdx: [6, 7], toolSignals: [5, 3], toolTimes: ["0.3s", "0.1s"], completeAgent: "static", findingsSlice: [0, 1, 2, 3] },
      { step: 4, delay: 6500, agentId: "behavioral", log: "Building threat scenario from static evidence...", },
      { step: 4, delay: 8000, agentId: "behavioral", log: "Classification: RAT/backdoor. Process injection + C2 beaconing.", completeAgent: "behavioral", findingsSlice: [4, 5] },
      { step: 4, delay: 9500, agentId: "critic", log: "Reviewing findings — no keylogging imports detected." },
      { step: 4, delay: 11000, agentId: "critic", log: "Challenge: Missing clipboard/keylog APIs. Downgrade to backdoor/downloader?", completeAgent: "critic" },
      { step: 4, delay: 12500, agentId: "consensus", log: "Resolving debate. Backdoor confirmed at 87% confidence.", completeAgent: "consensus" },
      { step: 5, delay: 14000, agentId: "reporter", log: "Generating threat report with MITRE ATT&CK mapping." },
      { step: 5, delay: 15500, agentId: "reporter", log: "Report complete. Remediation plan generated.", completeAgent: "reporter" },
      { step: 5, delay: 16500, agentId: "responder", log: "Exporting IOCs to blocklist. Alert dispatched. Ticket created.", completeAgent: "responder" },
    ];

    agentSequence.forEach(({ step, delay, agentId, log, toolIdx, toolSignals, toolTimes, completeAgent, findingsSlice }) => {
      setTimeout(() => {
        setCurrentStep(step);
        setAgents(prev => prev.map(a => a.id === agentId ? { ...a, status: "running" } : a));
        setAgentLog(prev => [...prev, { time: new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" }), agent: agentId, text: log }]);

        if (toolIdx) {
          setTools(prev => prev.map((t, i) =>
            toolIdx.includes(i) ? { ...t, signals: toolSignals[toolIdx.indexOf(i)], time: toolTimes[toolIdx.indexOf(i)] } : t
          ));
        }
        if (completeAgent) {
          setAgents(prev => prev.map(a => a.id === completeAgent ? { ...a, status: "complete" } : a));
        }
        if (findingsSlice) {
          setFindings(prev => [...prev, ...findingsSlice.map(i => FINDINGS_MOCK[i])]);
        }
      }, delay);
    });

    setTimeout(() => {
      setAnalysisState("complete");
      setRiskScore(79);
      setClassification("Backdoor / Downloader");
      clearInterval(timerRef.current);
    }, 17000);
  };

  useEffect(() => () => clearInterval(timerRef.current), []);

  const formatTime = (s) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  return (
    <div style={{ fontFamily: "'DM Sans', system-ui, sans-serif", minHeight: "100vh", background: "#FAFAF9", color: "#1C1917" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');
        @keyframes ping { 75%, 100% { transform: scale(2); opacity: 0; } }
        @keyframes fadeUp { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes slideIn { from { opacity: 0; transform: translateX(-12px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes scanline { from { transform: translateX(-100%); } to { transform: translateX(200%); } }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-thumb { background: #D6D3D1; border-radius: 2px; }
      `}</style>

      <header style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 32px", height: 56, borderBottom: "1px solid #E7E5E4",
        background: "#FFFFFF", position: "sticky", top: 0, zIndex: 50,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8, background: "#1C1917",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600, fontSize: 14, color: "#fff",
          }}>MS</div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600, letterSpacing: "-0.02em" }}>MalwareScope</div>
            <div style={{ fontSize: 11, color: "#A8A29E", letterSpacing: "0.02em" }}>AI-native threat analysis</div>
          </div>
        </div>

        <nav style={{ display: "flex", gap: 4 }}>
          {["Overview", "Evidence", "AI Investigation", "Response Plan", "Architecture"].map((item, i) => (
            <button key={item} onClick={() => setActiveNav(NAV_ITEMS[i].id)} style={{
              padding: "6px 14px", fontSize: 13, fontWeight: activeNav === NAV_ITEMS[i].id ? 600 : 400,
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
            }}>Export PDF</button>
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

        <aside style={{
          width: 220, borderRight: "1px solid #E7E5E4", background: "#FFFFFF",
          padding: "24px 16px", flexShrink: 0,
        }}>
          <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 12 }}>
            Investigation view
          </div>
          {NAV_ITEMS.map((item) => (
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
          {tools.map((tool, i) => (
            <div key={i} style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              padding: "8px 12px", marginBottom: 2, borderRadius: 8,
              background: tool.time ? "#F5F5F4" : "transparent",
              animation: tool.time ? "fadeUp 0.3s ease" : "none",
            }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 500, color: "#44403C" }}>{tool.name}</div>
              </div>
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
        </aside>

        <main style={{ flex: 1, padding: "28px 32px", overflow: "auto" }}>

          <div style={{ marginBottom: 8, display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 13, color: "#1C1917", fontWeight: 500 }}>Threat analysis</span>
            <span style={{ color: "#D6D3D1" }}>/</span>
            <span style={{ fontSize: 13, color: "#A8A29E" }}>{fileName || "No sample loaded"}</span>
          </div>

          <h1 style={{
            fontSize: 38, fontWeight: 700, letterSpacing: "-0.03em",
            lineHeight: 1.1, marginBottom: 8, color: "#1C1917",
          }}>
            {analysisState === "complete" ? "Analysis complete" : analysisState === "running" ? "Analyzing threat..." : "Static malware triage"}
          </h1>
          <p style={{ fontSize: 14, color: "#78716C", marginBottom: 28, maxWidth: 600, lineHeight: 1.6 }}>
            Containerized analyzers feed evidence into a multi-model AI pipeline that produces explainable findings, ATT&CK mappings, and remediation guidance.
          </p>

          <div
            onClick={() => fileInputRef.current?.click()}
            onDrop={handleFileDrop}
            onDragOver={(e) => e.preventDefault()}
            style={{
              border: fileName ? "1px solid #E7E5E4" : "2px dashed #D6D3D1",
              borderRadius: 12, padding: "20px 24px",
              display: "flex", alignItems: "center", justifyContent: "space-between",
              marginBottom: 24, cursor: "pointer", background: "#FFFFFF",
              transition: "all 0.2s",
            }}
          >
            <input ref={fileInputRef} type="file" style={{ display: "none" }} onChange={handleFileDrop} />
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
                  {fileName ? fileName : "Drop malware sample"}
                </div>
                <div style={{ fontSize: 12, color: "#A8A29E" }}>
                  Supports PE, DLL, script, archive, document, or memory artifact
                </div>
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              {fileName && !analysisState.match(/running|complete/) && (
                <button style={{
                  padding: "2px 10px", fontSize: 12, background: "transparent",
                  border: "1px solid #D6D3D1", borderRadius: 6, color: "#78716C",
                  cursor: "pointer", fontFamily: "'DM Sans', system-ui",
                }} onClick={(e) => { e.stopPropagation(); setFileName(null); }}>Clear</button>
              )}
              <button onClick={(e) => { e.stopPropagation(); if (fileName) runAnalysis(); }}
                disabled={!fileName || analysisState === "running"}
                style={{
                  padding: "9px 20px", fontSize: 13, fontWeight: 600,
                  background: fileName ? "#1C1917" : "#E7E5E4",
                  color: fileName ? "#fff" : "#A8A29E",
                  border: "none", borderRadius: 8, cursor: fileName ? "pointer" : "default",
                  fontFamily: "'DM Sans', system-ui", transition: "all 0.15s",
                  opacity: analysisState === "running" ? 0.5 : 1,
                }}>
                {analysisState === "running" ? "Analyzing..." : analysisState === "complete" ? "Re-analyze" : "Run triage"}
              </button>
            </div>
          </div>

          <div style={{
            background: "#FFFFFF", border: "1px solid #E7E5E4", borderRadius: 12,
            padding: "20px 24px", marginBottom: 24,
          }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 16 }}>
              Analysis pipeline
            </div>
            <div style={{ display: "flex", gap: 0, alignItems: "flex-start" }}>
              {PIPELINE_STEPS.map((step, i) => {
                const isActive = currentStep === step.id;
                const isDone = currentStep > step.id;
                const isPending = currentStep < step.id;
                return (
                  <div key={step.id} style={{ flex: 1, position: "relative" }}>
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <div style={{
                        width: 40, height: 40, borderRadius: "50%",
                        display: "flex", alignItems: "center", justifyContent: "center",
                        fontFamily: "'IBM Plex Mono', monospace", fontSize: 14, fontWeight: 600,
                        background: isDone ? "#16A34A" : isActive ? "#1C1917" : "#F5F5F4",
                        color: isDone || isActive ? "#fff" : "#A8A29E",
                        transition: "all 0.4s cubic-bezier(0.4, 0, 0.2, 1)",
                        position: "relative", overflow: "hidden",
                      }}>
                        {isDone ? "✓" : step.id.toString().padStart(2, "0")}
                        {isActive && (
                          <div style={{
                            position: "absolute", top: 0, left: 0, width: "50%", height: "100%",
                            background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.25), transparent)",
                            animation: "scanline 1.5s linear infinite",
                          }} />
                        )}
                      </div>
                      {i < PIPELINE_STEPS.length - 1 && (
                        <div style={{
                          flex: 1, height: 2, marginLeft: 0, marginRight: 0,
                          background: isDone ? "#16A34A" : "#E7E5E4",
                          transition: "background 0.4s",
                        }} />
                      )}
                    </div>
                    <div style={{ marginTop: 8, paddingRight: 12 }}>
                      <div style={{
                        fontSize: 13, fontWeight: isActive || isDone ? 600 : 400,
                        color: isActive ? "#1C1917" : isDone ? "#1C1917" : "#A8A29E",
                      }}>{step.label}</div>
                      <div style={{ fontSize: 11, color: "#A8A29E" }}>
                        {isDone ? "Complete" : isActive ? "Running" : step.desc}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 24 }}>

            <div style={{
              background: "#FFFFFF", border: "1px solid #E7E5E4", borderRadius: 12,
              padding: "20px 24px",
            }}>
              <div style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                marginBottom: 16,
              }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                  Agent status
                </div>
                <div style={{ fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", color: "#A8A29E" }}>
                  {agents.filter(a => a.status === "complete").length}/{agents.length} complete
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                {agents.map((agent) => (
                  <div key={agent.id} style={{
                    padding: "12px 14px", borderRadius: 10,
                    border: agent.status === "running" ? "1px solid #A8A29E" : "1px solid #F5F5F4",
                    background: agent.status === "running" ? "#F7F7F6" : agent.status === "complete" ? "#FAFAF9" : "#fff",
                    transition: "all 0.3s", animation: agent.status === "running" ? "fadeUp 0.3s ease" : "none",
                  }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: "#1C1917" }}>{agent.name}</div>
                      <StatusDot status={agent.status} />
                    </div>
                    <div style={{ fontSize: 11, color: "#A8A29E" }}>{agent.desc}</div>
                    <div style={{
                      marginTop: 6, fontSize: 10, fontFamily: "'IBM Plex Mono', monospace",
                      fontWeight: 500, color: agent.model === "Claude" ? "#7C3AED" : agent.model === "Gemini" ? "#2563EB" : agent.model === "GPT" ? "#059669" : "#78716C",
                      textTransform: "uppercase", letterSpacing: "0.05em",
                    }}>{agent.model}</div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{
              background: "#FFFFFF", border: "1px solid #E7E5E4", borderRadius: 12,
              padding: "20px 24px", display: "flex", flexDirection: "column",
            }}>
              <div style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                marginBottom: 16,
              }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                  Sample overview
                </div>
                {classification && <SeverityBadge severity="critical" />}
              </div>

              {classification ? (
                <div style={{ display: "flex", alignItems: "center", gap: 24, flex: 1 }}>
                  <RiskGauge score={riskScore} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 22, fontWeight: 700, letterSpacing: "-0.02em", marginBottom: 4 }}>{classification}</div>
                    <div style={{ fontSize: 12, color: "#78716C", lineHeight: 1.6, marginBottom: 12 }}>
                      Process injection capability via WriteProcessMemory + CreateRemoteThread. C2 beaconing to 45.33.21.8. Registry persistence established.
                    </div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      {["T1055", "T1059.001", "T1547.001", "T1071.001"].map(t => (
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
                <div style={{
                  flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
                  color: "#D6D3D1", fontSize: 13,
                }}>
                  {analysisState === "running" ? "Analysis in progress..." : "Awaiting sample"}
                </div>
              )}
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>

            <div style={{
              background: "#FFFFFF", border: "1px solid #E7E5E4", borderRadius: 12,
              padding: "20px 24px", maxHeight: 380, overflow: "auto",
            }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 16 }}>
                Agent reasoning trace
              </div>
              {agentLog.length === 0 ? (
                <div style={{ color: "#D6D3D1", fontSize: 13, padding: "20px 0", textAlign: "center" }}>
                  No activity yet
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
                  {agentLog.map((entry, i) => (
                    <div key={i} style={{
                      display: "flex", gap: 10, padding: "8px 0",
                      borderBottom: i < agentLog.length - 1 ? "1px solid #F5F5F4" : "none",
                      animation: "slideIn 0.3s ease",
                    }}>
                      <span style={{
                        fontSize: 11, fontFamily: "'IBM Plex Mono', monospace",
                        color: "#A8A29E", flexShrink: 0, marginTop: 1,
                      }}>{entry.time}</span>
                      <div>
                        <span style={{
                          fontSize: 11, fontWeight: 600, textTransform: "uppercase",
                          color: entry.agent === "static" ? "#7C3AED" : entry.agent === "behavioral" ? "#2563EB" : entry.agent === "critic" ? "#059669" : entry.agent === "consensus" ? "#7C3AED" : entry.agent === "reporter" ? "#7C3AED" : "#78716C",
                          fontFamily: "'IBM Plex Mono', monospace",
                        }}>{agents.find(a => a.id === entry.agent)?.name}</span>
                        <p style={{ fontSize: 13, color: "#44403C", marginTop: 2, lineHeight: 1.5 }}>{entry.text}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div style={{
              background: "#FFFFFF", border: "1px solid #E7E5E4", borderRadius: 12,
              padding: "20px 24px", maxHeight: 380, overflow: "auto",
            }}>
              <div style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                marginBottom: 16,
              }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                  Indicators of compromise
                </div>
                <div style={{ fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", color: "#A8A29E" }}>
                  {findings.length} found
                </div>
              </div>
              {findings.length === 0 ? (
                <div style={{ color: "#D6D3D1", fontSize: 13, padding: "20px 0", textAlign: "center" }}>
                  No indicators extracted yet
                </div>
              ) : (
                <div>
                  {findings.map((f, i) => (
                    <div key={i} style={{
                      display: "flex", alignItems: "center", gap: 10, padding: "8px 0",
                      borderBottom: i < findings.length - 1 ? "1px solid #F5F5F4" : "none",
                      animation: "fadeUp 0.3s ease",
                    }}>
                      <span style={{
                        fontSize: 10, fontFamily: "'IBM Plex Mono', monospace",
                        fontWeight: 600, padding: "2px 8px", borderRadius: 4,
                        background: f.type === "URL" || f.type === "API" ? "#FEF2F2" : f.type === "IP" || f.type === "REG" ? "#F0F0EE" : "#F0F9FF",
                        color: f.type === "URL" || f.type === "API" ? "#991B1B" : f.type === "IP" || f.type === "REG" ? "#9A3412" : "#075985",
                        minWidth: 40, textAlign: "center",
                      }}>{f.type}</span>
                      <span style={{
                        fontSize: 13, fontFamily: "'IBM Plex Mono', monospace",
                        color: "#1C1917", flex: 1,
                      }}>{f.value}</span>
                      <SeverityBadge severity={f.severity} />
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

        </main>
      </div>
    </div>
  );
}
