/**
 * PipelineFlow — ADK pipeline visualization.
 * Shows the sequential/parallel agent flow with node states.
 */

const STATUS_COLORS = {
  idle: "#374151",
  running: "#1d4ed8",
  complete: "#065f46",
  error: "#7f1d1d",
};

const STATUS_BG = {
  idle: "#111827",
  running: "#1e3a8a",
  complete: "#064e3b",
  error: "#450a0a",
};

const STATUS_RING = {
  idle: "border-gray-700",
  running: "border-blue-500 animate-pulse",
  complete: "border-emerald-500",
  error: "border-red-600",
};

function Node({ label, status, isParallel }) {
  return (
    <div
      className={`flex flex-col items-center justify-center px-3 py-2 rounded-lg border-2 text-xs font-mono font-semibold min-w-[110px] text-center transition-all duration-500 ${STATUS_RING[status]}`}
      style={{ backgroundColor: STATUS_BG[status], color: status === "idle" ? "#6b7280" : "#e5e7eb" }}
    >
      <span>{label}</span>
      {status === "running" && (
        <span className="mt-1 text-[10px] text-blue-400 font-normal">● running</span>
      )}
      {status === "complete" && (
        <span className="mt-1 text-[10px] text-emerald-400 font-normal">✓ done</span>
      )}
      {status === "error" && (
        <span className="mt-1 text-[10px] text-red-400 font-normal">✗ error</span>
      )}
    </div>
  );
}

function Arrow() {
  return (
    <div className="flex items-center mx-1 text-gray-600 font-bold text-sm">→</div>
  );
}

export default function PipelineFlow({ progress }) {
  if (!progress) return null;

  const s = (key) => progress[key]?.status || "idle";

  return (
    <div className="bg-gray-950 border border-gray-800 rounded-xl p-5">
      <h3 className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-4">
        ADK Analysis Pipeline
      </h3>

      {/* Main flow */}
      <div className="flex items-start flex-wrap gap-y-4">
        {/* Sequential: Static */}
        <Node label="Static Analysis" status={s("static")} />
        <Arrow />

        {/* Sequential: Scenario */}
        <Node label="Scenario Builder" status={s("scenario")} />
        <Arrow />

        {/* ParallelAgent block */}
        <div className="flex flex-col items-center">
          <span className="text-[10px] font-mono text-gray-600 mb-1 uppercase tracking-wider">
            ParallelAgent
          </span>
          <div className="border border-dashed border-gray-700 rounded-lg p-2 flex gap-2">
            <Node label="Network Monitor" status={s("network")} isParallel />
            <Node label="Filesystem" status={s("filesystem")} isParallel />
            <Node label="Registry" status={s("registry")} isParallel />
            <Node label="Threat Intel" status={s("intel")} isParallel />
          </div>
        </div>

        <Arrow />

        {/* Sequential: Critic */}
        <Node label="Critic" status={s("critic")} />
        <Arrow />

        {/* Sequential: Report */}
        <Node label="Report Writer" status={s("report")} />
      </div>
    </div>
  );
}
