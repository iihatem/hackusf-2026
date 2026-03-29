/**
 * ChatPanel.jsx — Floating analyst chat powered by Snowflake RAG + Claude.
 *
 * Props:
 *   jobId  (string)  — the analysis job identifier
 *   isDone (boolean) — true when the analysis pipeline has completed
 *
 * Dependencies (install in your React project):
 *   npm install react-markdown remark-gfm
 *
 * Wire into your app:
 *   import ChatPanel from "./components/ChatPanel";
 *   <ChatPanel jobId={jobId} isDone={isDone} />
 *
 * Also add sendChat (from sendChat.js) to your API client module and
 * import it here as shown below.
 */

import { useState, useEffect, useRef } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { sendChat } from "./sendChat";

const CHUNK_COLORS = {
  mitre_technique:       { bg: "#EDE9FE", color: "#5B21B6" },
  capability:            { bg: "#FEF3C7", color: "#92400E" },
  c2_infrastructure:     { bg: "#FEE2E2", color: "#991B1B" },
  infection_chain_stage: { bg: "#E0F2FE", color: "#075985" },
  blue_team_summary:     { bg: "#F0FDF4", color: "#166534" },
  hunt_query:            { bg: "#ECFDF5", color: "#065F46" },
  file_drop:             { bg: "#FDF2F8", color: "#86198F" },
};

const SUGGESTIONS = [
  "What are the main C2 indicators?",
  "Which MITRE techniques were detected?",
  "Summarize the persistence mechanisms",
  "What immediate remediation steps are recommended?",
];

export default function ChatPanel({ jobId, isDone }) {
  const [open, setOpen]         = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput]       = useState("");
  const [loading, setLoading]   = useState(false);
  const messagesEndRef           = useRef(null);
  const inputRef                 = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 80);
  }, [open]);

  const canChat = !!jobId && isDone;

  const send = async () => {
    const q = input.trim();
    if (!q || loading || !canChat) return;
    setInput("");
    setMessages(prev => [...prev, { role: "user", text: q }]);
    setLoading(true);
    try {
      const data = await sendChat(jobId, q);
      setMessages(prev => [...prev, {
        role: "assistant",
        text: data.answer,
        sources: data.sources || [],
      }]);
    } catch (err) {
      setMessages(prev => [...prev, { role: "assistant", text: `Error: ${err.message}`, error: true }]);
    } finally {
      setLoading(false);
    }
  };

  const onKey = (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); }
  };

  return (
    <>
      {/* Floating toggle button */}
      <button
        onClick={() => setOpen(o => !o)}
        title="Analyst chat"
        style={{
          position: "fixed", bottom: 28, right: 28, zIndex: 200,
          width: 52, height: 52, borderRadius: "50%",
          background: canChat ? "#1C1917" : "#A8A29E",
          border: "none", cursor: "pointer",
          display: "flex", alignItems: "center", justifyContent: "center",
          boxShadow: "0 4px 24px rgba(0,0,0,0.18)",
          transition: "all 0.2s",
        }}
      >
        {open ? (
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
            <path d="M3 3l12 12M15 3L3 15" stroke="#fff" strokeWidth="2" strokeLinecap="round"/>
          </svg>
        ) : (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
            <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"
              stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        )}
        {canChat && messages.length === 0 && !open && (
          <span style={{
            position: "absolute", top: -2, right: -2, width: 12, height: 12,
            borderRadius: "50%", background: "#16A34A", border: "2px solid #fff",
          }} />
        )}
      </button>

      {/* Chat panel */}
      {open && (
        <div style={{
          position: "fixed", bottom: 92, right: 28, zIndex: 199,
          width: 380, height: 540,
          background: "#FFFFFF", borderRadius: 16,
          border: "1px solid #E7E5E4",
          boxShadow: "0 8px 40px rgba(0,0,0,0.14)",
          display: "flex", flexDirection: "column",
          fontFamily: "'DM Sans', system-ui, sans-serif",
          animation: "chatSlideUp 0.2s cubic-bezier(0.4,0,0.2,1)",
        }}>
          <style>{`
            @keyframes chatSlideUp {
              from { opacity: 0; transform: translateY(16px); }
              to   { opacity: 1; transform: translateY(0); }
            }
            @keyframes chatBounce {
              0%,80%,100% { transform: scale(0.6); }
              40%          { transform: scale(1); }
            }
            .ms-bubble > *:last-child { margin-bottom: 0 !important; }
            .ms-bubble ul, .ms-bubble ol { margin-top: 4px; }
          `}</style>

          {/* Header */}
          <div style={{
            padding: "14px 16px", borderBottom: "1px solid #F5F5F4",
            display: "flex", alignItems: "center", justifyContent: "space-between",
            flexShrink: 0,
          }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 600, color: "#1C1917" }}>Analyst chat</div>
              <div style={{ fontSize: 11, color: "#A8A29E", marginTop: 1, display: "flex", alignItems: "center", gap: 5 }}>
                <div style={{
                  width: 6, height: 6, borderRadius: "50%",
                  background: canChat ? "#16A34A" : "#D1D5DB",
                }} />
                {canChat ? "Findings indexed — RAG ready" : isDone === false && jobId ? "Analysis running…" : "Run analysis to enable chat"}
              </div>
            </div>
            <span style={{
              fontSize: 10, fontFamily: "'IBM Plex Mono', monospace", fontWeight: 500,
              padding: "2px 8px", borderRadius: 4,
              background: "#F5F3FF", color: "#5B21B6",
              textTransform: "uppercase", letterSpacing: "0.05em",
            }}>Snowflake RAG</span>
          </div>

          {/* Messages */}
          <div style={{ flex: 1, overflow: "auto", padding: "12px 14px" }}>
            {messages.length === 0 ? (
              <div style={{ padding: "24px 0", textAlign: "center" }}>
                <svg width="36" height="36" viewBox="0 0 24 24" fill="none" style={{ margin: "0 auto 10px", display: "block" }}>
                  <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"
                    stroke="#D6D3D1" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
                <div style={{ fontSize: 13, fontWeight: 600, color: canChat ? "#1C1917" : "#A8A29E", marginBottom: 16 }}>
                  {canChat ? "Ask about the analysis" : "No analysis loaded"}
                </div>
                {canChat && SUGGESTIONS.map(q => (
                  <button key={q} onClick={() => { setInput(q); inputRef.current?.focus(); }} style={{
                    display: "block", width: "100%", marginBottom: 6,
                    padding: "8px 12px", fontSize: 12, textAlign: "left",
                    background: "#FAFAF9", border: "1px solid #E7E5E4", borderRadius: 8,
                    color: "#44403C", cursor: "pointer",
                    fontFamily: "'DM Sans', system-ui",
                  }}>{q}</button>
                ))}
              </div>
            ) : (
              <>
                {messages.map((msg, i) => (
                  <div key={i} style={{
                    marginBottom: 14, display: "flex",
                    flexDirection: msg.role === "user" ? "row-reverse" : "row",
                    gap: 8, alignItems: "flex-start",
                  }}>
                    <div style={{
                      width: 26, height: 26, borderRadius: "50%", flexShrink: 0,
                      background: msg.role === "user" ? "#1C1917" : "#F5F5F4",
                      display: "flex", alignItems: "center", justifyContent: "center",
                      fontSize: 10, fontWeight: 700,
                      color: msg.role === "user" ? "#fff" : "#78716C",
                      fontFamily: "'IBM Plex Mono', monospace",
                    }}>
                      {msg.role === "user" ? "A" : "AI"}
                    </div>
                    <div style={{ maxWidth: "82%", minWidth: 0 }}>
                      <div
                        className={msg.role === "assistant" && !msg.error ? "ms-bubble" : undefined}
                        style={{
                          padding: "10px 13px", borderRadius: 12,
                          borderTopRightRadius: msg.role === "user" ? 4 : 12,
                          borderTopLeftRadius:  msg.role === "user" ? 12 : 4,
                          background: msg.role === "user" ? "#1C1917" : msg.error ? "#FEF2F2" : "#F5F5F4",
                          color: msg.role === "user" ? "#fff" : msg.error ? "#991B1B" : "#1C1917",
                          fontSize: 13, lineHeight: 1.6, wordBreak: "break-word",
                        }}
                      >
                        {msg.role === "user" || msg.error ? (
                          msg.text
                        ) : (
                          <ReactMarkdown
                            remarkPlugins={[remarkGfm]}
                            components={{
                              p:      ({ children }) => <p style={{ margin: "0 0 8px", lineHeight: 1.65 }}>{children}</p>,
                              strong: ({ children }) => <strong style={{ fontWeight: 600, color: "#1C1917" }}>{children}</strong>,
                              em:     ({ children }) => <em style={{ fontStyle: "italic" }}>{children}</em>,
                              ul:     ({ children }) => <ul style={{ margin: "4px 0 8px", paddingLeft: 18, listStyleType: "disc" }}>{children}</ul>,
                              ol:     ({ children }) => <ol style={{ margin: "4px 0 8px", paddingLeft: 18 }}>{children}</ol>,
                              li:     ({ children }) => <li style={{ marginBottom: 3, lineHeight: 1.55 }}>{children}</li>,
                              code:   ({ inline, children }) => inline
                                ? <code style={{
                                    fontFamily: "'IBM Plex Mono', monospace", fontSize: 11,
                                    background: "#E7E5E4", color: "#1C1917",
                                    padding: "1px 5px", borderRadius: 4,
                                  }}>{children}</code>
                                : <pre style={{
                                    fontFamily: "'IBM Plex Mono', monospace", fontSize: 11,
                                    background: "#1C1917", color: "#E7E5E4",
                                    padding: "10px 12px", borderRadius: 8, overflowX: "auto",
                                    margin: "6px 0", lineHeight: 1.6, whiteSpace: "pre",
                                  }}><code>{children}</code></pre>,
                              blockquote: ({ children }) => (
                                <blockquote style={{
                                  borderLeft: "3px solid #D6D3D1", margin: "6px 0",
                                  paddingLeft: 10, color: "#78716C",
                                }}>{children}</blockquote>
                              ),
                              h1: ({ children }) => <h1 style={{ fontSize: 15, fontWeight: 700, margin: "8px 0 4px", color: "#1C1917" }}>{children}</h1>,
                              h2: ({ children }) => <h2 style={{ fontSize: 14, fontWeight: 600, margin: "6px 0 3px", color: "#1C1917" }}>{children}</h2>,
                              h3: ({ children }) => <h3 style={{ fontSize: 13, fontWeight: 600, margin: "4px 0 2px", color: "#44403C" }}>{children}</h3>,
                              hr: () => <hr style={{ border: "none", borderTop: "1px solid #E7E5E4", margin: "8px 0" }} />,
                              a:  ({ href, children }) => (
                                <a href={href} target="_blank" rel="noopener noreferrer"
                                  style={{ color: "#7C3AED", textDecoration: "underline", textUnderlineOffset: 2 }}>
                                  {children}
                                </a>
                              ),
                              table: ({ children }) => (
                                <div style={{ overflowX: "auto", margin: "6px 0" }}>
                                  <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 12 }}>{children}</table>
                                </div>
                              ),
                              th: ({ children }) => (
                                <th style={{ padding: "4px 8px", borderBottom: "2px solid #E7E5E4", textAlign: "left", fontWeight: 600, whiteSpace: "nowrap" }}>{children}</th>
                              ),
                              td: ({ children }) => (
                                <td style={{ padding: "4px 8px", borderBottom: "1px solid #F5F5F4" }}>{children}</td>
                              ),
                            }}
                          >
                            {msg.text}
                          </ReactMarkdown>
                        )}
                      </div>
                      {msg.sources && msg.sources.length > 0 && (
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6 }}>
                          {msg.sources.map((src, si) => {
                            const c = CHUNK_COLORS[src.chunk_type] || { bg: "#F5F5F4", color: "#78716C" };
                            return (
                              <span key={si} title={src.content} style={{
                                fontSize: 10, fontFamily: "'IBM Plex Mono', monospace", fontWeight: 500,
                                padding: "2px 7px", borderRadius: 4,
                                background: c.bg, color: c.color,
                                cursor: "default", maxWidth: 140,
                                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                              }}>
                                {src.chunk_type.replace(/_/g, " ")}
                              </span>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </div>
                ))}

                {loading && (
                  <div style={{ display: "flex", gap: 8, alignItems: "flex-start", marginBottom: 14 }}>
                    <div style={{
                      width: 26, height: 26, borderRadius: "50%", flexShrink: 0,
                      background: "#F5F5F4", display: "flex", alignItems: "center", justifyContent: "center",
                      fontSize: 10, fontWeight: 700, color: "#78716C",
                      fontFamily: "'IBM Plex Mono', monospace",
                    }}>AI</div>
                    <div style={{ padding: "12px 14px", background: "#F5F5F4", borderRadius: 12, borderTopLeftRadius: 4 }}>
                      <div style={{ display: "flex", gap: 4 }}>
                        {[0, 1, 2].map(d => (
                          <div key={d} style={{
                            width: 6, height: 6, borderRadius: "50%", background: "#A8A29E",
                            animation: `chatBounce 1.2s ease-in-out ${d * 0.2}s infinite`,
                          }} />
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input bar */}
          <div style={{ padding: "12px 14px", borderTop: "1px solid #F5F5F4", flexShrink: 0 }}>
            <div style={{
              display: "flex", gap: 8, alignItems: "flex-end",
              background: "#F5F5F4", borderRadius: 12, padding: "8px 12px",
            }}>
              <textarea
                ref={inputRef}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={onKey}
                placeholder={canChat ? "Ask about IOCs, MITRE, remediation…" : "Run analysis to enable chat"}
                disabled={!canChat || loading}
                rows={1}
                style={{
                  flex: 1, border: "none", background: "transparent",
                  fontSize: 13, color: "#1C1917", resize: "none", outline: "none",
                  fontFamily: "'DM Sans', system-ui", lineHeight: 1.5,
                  maxHeight: 80, overflow: "auto",
                }}
              />
              <button
                onClick={send}
                disabled={!input.trim() || !canChat || loading}
                style={{
                  width: 30, height: 30, borderRadius: 8, border: "none", flexShrink: 0,
                  background: input.trim() && canChat ? "#1C1917" : "#E7E5E4",
                  cursor: input.trim() && canChat ? "pointer" : "default",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  transition: "all 0.15s",
                }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                  <path d="M22 2L11 13M22 2L15 22L11 13M22 2L2 9L11 13"
                    stroke={input.trim() && canChat ? "#fff" : "#A8A29E"}
                    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </button>
            </div>
            <div style={{ fontSize: 10, color: "#D6D3D1", marginTop: 5, textAlign: "center" }}>
              Snowflake vector search · Claude
            </div>
          </div>
        </div>
      )}
    </>
  );
}
