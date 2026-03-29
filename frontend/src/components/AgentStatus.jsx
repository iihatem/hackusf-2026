/**
 * AgentStatus — 8 agent cards showing running/complete states and key findings.
 */

const AGENT_META = {
  static:     { label: "Static Analysis",   icon: "🔍", color: "blue" },
  scenario:   { label: "Scenario Builder",  icon: "🎬", color: "purple" },
  network:    { label: "Network Monitor",   icon: "🌐", color: "cyan" },
  filesystem: { label: "Filesystem",        icon: "📁", color: "yellow" },
  registry:   { label: "Registry/System",  icon: "🗝️",  color: "orange" },
  intel:      { label: "Threat Intel",      icon: "🕵️",  color: "red" },
  critic:     { label: "Critic",            icon: "⚖️",  color: "pink" },
  report:     { label: "Report Writer",     icon: "📋", color: "emerald" },
};

const STATUS_STYLES = {
  idle:     "border-gray-800 bg-gray-950",
  running:  "border-blue-600 bg-blue-950 ring-1 ring-blue-700",
  complete: "border-emerald-700 bg-emerald-950",
  error:    "border-red-700 bg-red-950",
};

function Spinner() {
  return (
    <svg className="animate-spin h-4 w-4 text-blue-400" fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
    </svg>
  );
}

function AgentCard({ agentKey, data }) {
  const meta = AGENT_META[agentKey];
  const status = data?.status || "idle";
  const findings = data?.findings;

  const snippet = findings
    ? Object.entries(findings)
        .slice(0, 2)
        .map(([k, v]) => {
          if (typeof v === "boolean") return `${k}: ${v ? "yes" : "no"}`;
          if (typeof v === "string" && v.length < 60) return `${k}: ${v}`;
          if (typeof v === "number") return `${k}: ${v}`;
          if (Array.isArray(v)) return `${k}: [${v.length} items]`;
          return null;
        })
        .filter(Boolean)
        .join(" · ")
    : null;

  return (
    <div className={`rounded-xl border p-4 transition-all duration-500 ${STATUS_STYLES[status]}`}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-lg">{meta.icon}</span>
          <span className="text-sm font-semibold text-gray-200">{meta.label}</span>
        </div>
        <div>
          {status === "running" && <Spinner />}
          {status === "complete" && <span className="text-emerald-400 text-sm">✓</span>}
          {status === "error" && <span className="text-red-400 text-sm">✗</span>}
          {status === "idle" && <span className="text-gray-700 text-sm">○</span>}
        </div>
      </div>

      {/* Progress bar */}
      <div className="w-full bg-gray-800 rounded-full h-1 mb-2">
        <div
          className="h-1 rounded-full transition-all duration-700"
          style={{
            width: `${data?.percent || 0}%`,
            backgroundColor: status === "complete" ? "#10b981" : status === "running" ? "#3b82f6" : status === "error" ? "#ef4444" : "#374151",
          }}
        />
      </div>

      {/* Findings snippet */}
      {snippet && (
        <p className="text-[11px] text-gray-500 font-mono truncate">{snippet}</p>
      )}
      {!snippet && status === "idle" && (
        <p className="text-[11px] text-gray-700 font-mono">Waiting…</p>
      )}
    </div>
  );
}

export default function AgentStatus({ progress }) {
  if (!progress) return null;

  const keys = ["static", "scenario", "network", "filesystem", "registry", "intel", "critic", "report"];

  return (
    <div className="grid grid-cols-2 gap-3">
      {keys.map((key) => (
        <AgentCard key={key} agentKey={key} data={progress[key]} />
      ))}
    </div>
  );
}
