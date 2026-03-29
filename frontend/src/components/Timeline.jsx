/**
 * Timeline — live-scrolling event feed.
 * Events stream in as agents report them. Auto-scrolls to bottom.
 */

import { useEffect, useRef } from "react";

const LEVEL_STYLES = {
  info:    "text-gray-400 border-gray-700",
  running: "text-blue-400 border-blue-800",
  success: "text-emerald-400 border-emerald-900",
  error:   "text-red-400 border-red-900",
  warning: "text-yellow-400 border-yellow-900",
};

const LEVEL_ICONS = {
  info:    "◦",
  running: "⟳",
  success: "✓",
  error:   "✗",
  warning: "⚠",
};

function formatTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export default function Timeline({ events }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events?.length]);

  if (!events || events.length === 0) {
    return (
      <div className="bg-gray-950 border border-gray-800 rounded-xl p-5 h-64 flex items-center justify-center">
        <p className="text-gray-600 text-sm font-mono">Upload a file to start analysis…</p>
      </div>
    );
  }

  return (
    <div className="bg-gray-950 border border-gray-800 rounded-xl p-5">
      <h3 className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-3">
        Event Timeline
      </h3>
      <div className="overflow-y-auto max-h-72 space-y-1 pr-1">
        {events.map((ev, i) => {
          const style = LEVEL_STYLES[ev.level] || LEVEL_STYLES.info;
          const icon = LEVEL_ICONS[ev.level] || "◦";
          return (
            <div
              key={i}
              className={`flex items-start gap-2 text-[12px] font-mono border-l-2 pl-3 py-0.5 ${style}`}
            >
              <span className="shrink-0 text-gray-600 w-20">{formatTime(ev.timestamp)}</span>
              <span className="shrink-0">{icon}</span>
              <span className="text-gray-500 shrink-0 w-28 truncate">{ev.source}</span>
              <span>{ev.message}</span>
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
