/**
 * ReportPanel — Final threat report with severity ring, MITRE ATT&CK, and remediation.
 * Only renders after ReportWriterAgent completes.
 */

const SEVERITY_COLORS = {
  critical: { ring: "#dc2626", bg: "#450a0a", text: "#fca5a5", label: "CRITICAL" },
  high:     { ring: "#ea580c", bg: "#431407", text: "#fdba74", label: "HIGH" },
  medium:   { ring: "#ca8a04", bg: "#422006", text: "#fde047", label: "MEDIUM" },
  low:      { ring: "#16a34a", bg: "#052e16", text: "#86efac", label: "LOW" },
};

const CONFIDENCE_COLORS = {
  high:   "text-emerald-400",
  medium: "text-yellow-400",
  low:    "text-red-400",
};

const TACTIC_COLORS = [
  "bg-red-950 text-red-300",
  "bg-orange-950 text-orange-300",
  "bg-yellow-950 text-yellow-300",
  "bg-blue-950 text-blue-300",
  "bg-purple-950 text-purple-300",
  "bg-cyan-950 text-cyan-300",
  "bg-pink-950 text-pink-300",
];

function SeverityRing({ severity, score }) {
  const cfg = SEVERITY_COLORS[severity] || SEVERITY_COLORS.medium;
  const pct = Math.min(100, Math.max(0, (score / 10) * 100));
  const r = 40;
  const circ = 2 * Math.PI * r;
  const dash = (pct / 100) * circ;

  return (
    <div className="flex flex-col items-center justify-center p-4 rounded-xl" style={{ backgroundColor: cfg.bg }}>
      <svg width="110" height="110" viewBox="0 0 110 110" className="mb-2">
        {/* Track */}
        <circle cx="55" cy="55" r={r} fill="none" stroke="#1f2937" strokeWidth="10" />
        {/* Progress */}
        <circle
          cx="55" cy="55" r={r}
          fill="none"
          stroke={cfg.ring}
          strokeWidth="10"
          strokeDasharray={`${dash} ${circ - dash}`}
          strokeLinecap="round"
          transform="rotate(-90 55 55)"
          style={{ transition: "stroke-dasharray 1s ease-in-out" }}
        />
        <text x="55" y="50" textAnchor="middle" fill={cfg.text} fontSize="14" fontWeight="bold" fontFamily="monospace">
          {score?.toFixed(1)}
        </text>
        <text x="55" y="65" textAnchor="middle" fill={cfg.text} fontSize="9" fontFamily="monospace">
          / 10
        </text>
      </svg>
      <span className="text-xs font-mono font-bold tracking-widest" style={{ color: cfg.ring }}>
        {cfg.label}
      </span>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div className="mb-5">
      <h4 className="text-[11px] font-mono uppercase tracking-widest text-gray-500 mb-2 border-b border-gray-800 pb-1">
        {title}
      </h4>
      {children}
    </div>
  );
}

function MitreTag({ technique, idx }) {
  const color = TACTIC_COLORS[idx % TACTIC_COLORS.length];
  return (
    <div className={`inline-flex flex-col px-2 py-1.5 rounded text-[11px] font-mono mr-2 mb-2 ${color}`}>
      <span className="font-bold">{technique.id}</span>
      <span className="text-[10px] opacity-80">{technique.tactic}</span>
      <span className="text-[10px] opacity-60 truncate max-w-[120px]">{technique.technique}</span>
    </div>
  );
}

function RemediationList({ items, colorClass }) {
  if (!items?.length) return <p className="text-gray-600 text-xs font-mono">None specified</p>;
  return (
    <ul className="space-y-1">
      {items.map((item, i) => (
        <li key={i} className={`text-xs font-mono flex gap-2 ${colorClass}`}>
          <span className="shrink-0">›</span>
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}

export default function ReportPanel({ report }) {
  if (!report) {
    return (
      <div className="bg-gray-950 border border-gray-800 rounded-xl p-5 h-64 flex items-center justify-center">
        <p className="text-gray-600 text-sm font-mono">Report will appear when analysis completes…</p>
      </div>
    );
  }

  const sev = (report.severity || "medium").toLowerCase();
  const conf = (report.confidence || "low").toLowerCase();

  return (
    <div className="bg-gray-950 border border-gray-800 rounded-xl p-5 overflow-y-auto max-h-[80vh]">
      <h3 className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-4">
        Threat Report
      </h3>

      {/* Header row: ring + metadata */}
      <div className="flex gap-4 mb-5 flex-wrap">
        <SeverityRing severity={sev} score={report.severity_score || 0} />
        <div className="flex-1 min-w-[200px]">
          <div className="mb-1">
            <span className="text-gray-500 text-xs font-mono">Family: </span>
            <span className="text-gray-100 text-sm font-mono font-bold">{report.malware_family || "Unknown"}</span>
          </div>
          <div className="mb-1">
            <span className="text-gray-500 text-xs font-mono">Type: </span>
            <span className="text-gray-300 text-xs font-mono">{report.malware_type || "Unknown"}</span>
          </div>
          <div className="mb-3">
            <span className="text-gray-500 text-xs font-mono">Confidence: </span>
            <span className={`text-xs font-mono font-bold uppercase ${CONFIDENCE_COLORS[conf] || "text-gray-400"}`}>
              {conf}
            </span>
          </div>
          <p className="text-gray-300 text-xs font-mono leading-relaxed">{report.executive_summary}</p>
        </div>
      </div>

      {/* MITRE ATT&CK */}
      {report.mitre_attack?.length > 0 && (
        <Section title="MITRE ATT&CK">
          <div className="flex flex-wrap">
            {report.mitre_attack.map((t, i) => (
              <MitreTag key={i} technique={t} idx={i} />
            ))}
          </div>
        </Section>
      )}

      {/* At Risk */}
      {report.at_risk && (
        <Section title="Assets at Risk">
          {report.at_risk.ics_relevant && (
            <div className="bg-red-950 border border-red-800 rounded p-2 mb-2">
              <p className="text-red-300 text-xs font-mono font-bold">⚠ ICS/SCADA RISK</p>
              <p className="text-red-400 text-xs font-mono">{report.at_risk.ics_risk_description}</p>
            </div>
          )}
          <div className="flex flex-wrap gap-1">
            {(report.at_risk.systems || []).map((s, i) => (
              <span key={i} className="bg-gray-900 border border-gray-700 text-gray-300 text-[11px] font-mono px-2 py-0.5 rounded">
                {s}
              </span>
            ))}
          </div>
        </Section>
      )}

      {/* Remediation */}
      {report.remediation && (
        <Section title="Remediation">
          <div className="mb-3">
            <p className="text-[11px] font-mono text-red-400 uppercase mb-1">Immediate</p>
            <RemediationList items={report.remediation.immediate} colorClass="text-red-300" />
          </div>
          <div className="mb-3">
            <p className="text-[11px] font-mono text-yellow-400 uppercase mb-1">Short Term</p>
            <RemediationList items={report.remediation.short_term} colorClass="text-yellow-300" />
          </div>
          <div>
            <p className="text-[11px] font-mono text-blue-400 uppercase mb-1">Long Term</p>
            <RemediationList items={report.remediation.long_term} colorClass="text-blue-300" />
          </div>
        </Section>
      )}
    </div>
  );
}
