/**
 * IOCTable — Extracted indicators of compromise table.
 */

const TYPE_STYLES = {
  ip:     "bg-red-950 text-red-300 border border-red-800",
  domain: "bg-orange-950 text-orange-300 border border-orange-800",
  hash:   "bg-yellow-950 text-yellow-300 border border-yellow-800",
  url:    "bg-purple-950 text-purple-300 border border-purple-800",
  file:   "bg-blue-950 text-blue-300 border border-blue-800",
};

function IOCBadge({ type }) {
  return (
    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase font-bold ${TYPE_STYLES[type] || TYPE_STYLES.file}`}>
      {type}
    </span>
  );
}

export default function IOCTable({ iocs }) {
  if (!iocs) {
    return (
      <div className="bg-gray-950 border border-gray-800 rounded-xl p-5 h-48 flex items-center justify-center">
        <p className="text-gray-600 text-sm font-mono">No IOCs yet…</p>
      </div>
    );
  }

  const rows = [
    ...(iocs.ips || []).map(v => ({ type: "ip", value: v })),
    ...(iocs.domains || []).map(v => ({ type: "domain", value: v })),
    ...(iocs.hashes || []).map(v => ({ type: "hash", value: v })),
    ...(iocs.urls || []).map(v => ({ type: "url", value: v })),
    ...(iocs.files || []).map(v => ({ type: "file", value: v })),
  ];

  if (rows.length === 0) {
    return (
      <div className="bg-gray-950 border border-gray-800 rounded-xl p-5 h-48 flex items-center justify-center">
        <p className="text-gray-600 text-sm font-mono">No IOCs extracted</p>
      </div>
    );
  }

  return (
    <div className="bg-gray-950 border border-gray-800 rounded-xl p-5">
      <h3 className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-3">
        Indicators of Compromise ({rows.length})
      </h3>
      <div className="overflow-y-auto max-h-64">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="text-gray-600 border-b border-gray-800">
              <th className="text-left pb-2 pr-3 w-20">Type</th>
              <th className="text-left pb-2">Indicator</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={i} className="border-b border-gray-900 hover:bg-gray-900/50">
                <td className="py-1.5 pr-3">
                  <IOCBadge type={row.type} />
                </td>
                <td className="py-1.5 text-gray-300 break-all">{row.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
