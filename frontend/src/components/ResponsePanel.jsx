/**
 * ResponsePanel — Autonomous response pipeline results (light theme).
 * Shows blocklist enforcement, SOC alert dispatch, incident ticket, and verification.
 */

function SectionLabel({ children }) {
  return (
    <div style={{ fontSize: 10, fontWeight: 600, color: "#A8A29E", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 12 }}>
      {children}
    </div>
  );
}

function StatusPill({ status }) {
  const cfg = {
    idle:     { bg: "#F5F5F4", color: "#A8A29E" },
    running:  { bg: "#FEF9C3", color: "#92400E" },
    complete: { bg: "#F0FDF4", color: "#166534" },
    skipped:  { bg: "#F5F5F4", color: "#A8A29E" },
    error:    { bg: "#FEF2F2", color: "#991B1B" },
  }[status] || { bg: "#F5F5F4", color: "#A8A29E" };
  return (
    <span style={{
      fontSize: 10, fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600,
      padding: "2px 8px", borderRadius: 4, textTransform: "uppercase", letterSpacing: "0.05em",
      background: cfg.bg, color: cfg.color,
    }}>
      {status}
    </span>
  );
}

function Card({ children, style }) {
  return (
    <div style={{ background: "#FFFFFF", border: "1px solid #E7E5E4", borderRadius: 12, padding: "18px 22px", ...style }}>
      {children}
    </div>
  );
}

function EmptyState({ message }) {
  return <p style={{ fontSize: 13, color: "#D6D3D1", fontStyle: "italic" }}>{message}</p>;
}

function Tag({ children, color = "#F0F0EE", textColor = "#44403C" }) {
  return (
    <span style={{
      fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", padding: "2px 8px",
      borderRadius: 4, background: color, color: textColor, fontWeight: 500,
      display: "inline-block", margin: "2px 4px 2px 0",
    }}>{children}</span>
  );
}

function BlocklistCard({ data }) {
  if (!data) return <EmptyState message="Waiting for BlocklistAgent…" />;
  const ok = data.status === "success";
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: ok ? "#16A34A" : "#F59E0B" }}>{ok ? "✓ Pushed to firewall" : "⚠ Partial"}</span>
        <span style={{ fontSize: 12, color: "#A8A29E", fontFamily: "'IBM Plex Mono', monospace" }}>{data.actions_taken} actions</span>
      </div>
      {data.blocked_ips?.length > 0 && (
        <div>
          <div style={{ fontSize: 11, color: "#A8A29E", marginBottom: 4 }}>Blocked IPs ({data.blocked_ips.length})</div>
          <div>{data.blocked_ips.slice(0, 6).map((ip, i) => <Tag key={i} color="#FEF2F2" textColor="#991B1B">{ip}</Tag>)}
            {data.blocked_ips.length > 6 && <span style={{ fontSize: 11, color: "#A8A29E" }}>+{data.blocked_ips.length - 6} more</span>}
          </div>
        </div>
      )}
      {data.blocked_domains?.length > 0 && (
        <div>
          <div style={{ fontSize: 11, color: "#A8A29E", marginBottom: 4 }}>DNS sinkholed ({data.blocked_domains.length})</div>
          <div>{data.blocked_domains.slice(0, 4).map((d, i) => <Tag key={i} color="#FFF7ED" textColor="#9A3412">{d}</Tag>)}
            {data.blocked_domains.length > 4 && <span style={{ fontSize: 11, color: "#A8A29E" }}>+{data.blocked_domains.length - 4} more</span>}
          </div>
        </div>
      )}
      {data.firewall_rule_ids?.length > 0 && (
        <div style={{ fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", color: "#A8A29E" }}>
          Rules: {data.firewall_rule_ids.slice(0, 2).join(", ")}{data.firewall_rule_ids.length > 2 ? ` +${data.firewall_rule_ids.length - 2}` : ""}
        </div>
      )}
    </div>
  );
}

function AlertCard({ data }) {
  if (!data) return <EmptyState message="Waiting for AlertAgent…" />;
  const sevColor = { critical: "#DC2626", high: "#EA580C", medium: "#F59E0B", low: "#16A34A" };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: sevColor[data.severity?.toLowerCase()] || "#1C1917" }}>
          {(data.severity || "").toUpperCase()}
        </span>
        <span style={{ fontSize: 12, color: data.status === "sent" ? "#16A34A" : "#DC2626", fontFamily: "'IBM Plex Mono', monospace" }}>
          {data.status === "sent" ? "✓ Dispatched" : "✗ Failed"}
        </span>
        {data.alert_id && <span style={{ fontSize: 11, color: "#A8A29E", fontFamily: "'IBM Plex Mono', monospace" }}>{data.alert_id}</span>}
      </div>
      {data.subject && <div style={{ fontSize: 13, fontWeight: 600, color: "#1C1917", lineHeight: 1.4 }}>{data.subject}</div>}
      {data.recipients?.length > 0 && <div style={{ fontSize: 12, color: "#78716C" }}>To: {data.recipients.join(", ")}</div>}
      {data.requires_human_action && (
        <div style={{ background: "#FFFBEB", border: "1px solid #FDE68A", borderRadius: 8, padding: "10px 12px" }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: "#92400E", marginBottom: 4 }}>HUMAN ACTION REQUIRED</div>
          {(data.human_actions || []).slice(0, 2).map((a, i) => (
            <div key={i} style={{ fontSize: 12, color: "#78716C" }}>› {a}</div>
          ))}
        </div>
      )}
      {data.sla_minutes && <div style={{ fontSize: 11, color: "#A8A29E", fontFamily: "'IBM Plex Mono', monospace" }}>SLA: {data.sla_minutes} min</div>}
    </div>
  );
}

function TicketCard({ data }) {
  if (!data) return <EmptyState message="Waiting for TicketAgent…" />;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: "#1C1917", fontFamily: "'IBM Plex Mono', monospace" }}>{data.ticket_id}</span>
        <span style={{ fontSize: 11, padding: "2px 8px", borderRadius: 4, background: "#EFF6FF", color: "#1D4ED8", fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600, textTransform: "uppercase" }}>
          {data.status}
        </span>
      </div>
      {data.title && <div style={{ fontSize: 13, fontWeight: 600, color: "#1C1917", lineHeight: 1.4 }}>{data.title}</div>}
      <div style={{ display: "flex", gap: 16 }}>
        {data.sla_hours && <span style={{ fontSize: 12, color: "#78716C" }}>SLA: {data.sla_hours}h</span>}
        {data.assigned_to && <span style={{ fontSize: 12, color: "#78716C" }}>Assigned: {data.assigned_to}</span>}
      </div>
      {data.remediation_checklist?.length > 0 && (
        <div>
          <div style={{ fontSize: 11, color: "#A8A29E", marginBottom: 4 }}>Checklist ({data.remediation_checklist.length} items)</div>
          {data.remediation_checklist.slice(0, 3).map((item, i) => (
            <div key={i} style={{ fontSize: 12, color: "#44403C", padding: "2px 0" }}>☐ {item}</div>
          ))}
          {data.remediation_checklist.length > 3 && (
            <div style={{ fontSize: 11, color: "#A8A29E" }}>…and {data.remediation_checklist.length - 3} more</div>
          )}
        </div>
      )}
    </div>
  );
}

function VerificationCard({ data }) {
  if (!data) return <EmptyState message="Waiting for VerificationAgent…" />;
  const allPassed = data.overall_status === "verified";
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: allPassed ? "#16A34A" : "#F59E0B" }}>
          {allPassed ? "✓ All checks passed" : `⚠ ${data.overall_status}`}
        </span>
        {data.iteration_label && <span style={{ fontSize: 11, color: "#A8A29E", fontFamily: "'IBM Plex Mono', monospace" }}>{data.iteration_label}</span>}
      </div>
      {data.checks_passed?.length > 0 && (
        <div style={{ fontSize: 12, color: "#16A34A" }}>{data.checks_passed.length} checks passed</div>
      )}
      {data.checks_failed?.length > 0 && (
        <div>
          <div style={{ fontSize: 12, color: "#DC2626", marginBottom: 4 }}>{data.checks_failed.length} checks failed</div>
          {data.checks_failed.map((c, i) => <div key={i} style={{ fontSize: 12, color: "#78716C" }}>✗ {c}</div>)}
        </div>
      )}
      {data.escalation_required && (
        <div style={{ background: "#FEF2F2", border: "1px solid #FECACA", borderRadius: 8, padding: "10px 12px" }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: "#991B1B" }}>ESCALATED TO HUMAN ANALYST</div>
          {data.notes && <div style={{ fontSize: 12, color: "#78716C", marginTop: 4 }}>{data.notes}</div>}
        </div>
      )}
    </div>
  );
}

export default function ResponsePanel({ response }) {
  if (!response || response.status === "idle") {
    return (
      <Card style={{ textAlign: "center", padding: "48px 24px" }}>
        <div style={{ fontSize: 32, marginBottom: 12 }}>🛡️</div>
        <div style={{ fontSize: 14, fontWeight: 500, color: "#78716C" }}>Response pipeline idle</div>
        <div style={{ fontSize: 13, color: "#A8A29E", marginTop: 6 }}>
          Triggers automatically for confirmed high / critical threats
        </div>
      </Card>
    );
  }

  if (response.status === "skipped") {
    return (
      <Card style={{ textAlign: "center", padding: "48px 24px" }}>
        <div style={{ fontSize: 32, marginBottom: 12 }}>✓</div>
        <div style={{ fontSize: 14, fontWeight: 500, color: "#78716C" }}>No response triggered</div>
        <div style={{ fontSize: 13, color: "#A8A29E", marginTop: 6 }}>
          Threat severity below high / critical threshold
        </div>
      </Card>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Status banner */}
      <Card style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <div style={{ fontSize: 14, fontWeight: 600, color: "#1C1917", marginBottom: 2 }}>Autonomous Response Pipeline</div>
          <div style={{ fontSize: 12, color: "#78716C" }}>
            {response.status === "running"  && "Executing response actions…"}
            {response.status === "complete" && "All actions executed and verified"}
            {response.status === "error"    && (response.error || "Response pipeline error")}
          </div>
        </div>
        <StatusPill status={response.status} />
      </Card>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <Card>
          <SectionLabel>Firewall blocklist</SectionLabel>
          <BlocklistCard data={response.blocklist} />
        </Card>
        <Card>
          <SectionLabel>SOC alert</SectionLabel>
          <AlertCard data={response.alert} />
        </Card>
        <Card>
          <SectionLabel>Incident ticket</SectionLabel>
          <TicketCard data={response.ticket} />
        </Card>
        <Card>
          <SectionLabel>Verification loop</SectionLabel>
          <VerificationCard data={response.verification} />
        </Card>
      </div>
    </div>
  );
}
