malwarescope/
├── CLAUDE.md ← Claude Code's primary context file
├── .env.example ← env vars template (never .env itself)
├── requirements.txt
├── README.md
│
├── orchestrator.py ← top-level coordinator
│
├── monitoring/ ← Layer 1: continuous monitoring agents
│ ├── **init**.py
│ ├── network_feed_agent.py
│ ├── endpoint_feed_agent.py
│ ├── threat_intel_feed_agent.py
│ └── triage_agent.py
│
├── analysis/ ← Layer 2: deep analysis pipeline
│ ├── **init**.py
│ ├── pipeline.py ← orchestrates the analysis agents
│ ├── static_analyzer.py ← non-AI artifact extraction
│ ├── agents/
│ │ ├── **init**.py
│ │ ├── static_agent.py
│ │ ├── scenario_builder.py
│ │ ├── network_monitor_agent.py
│ │ ├── filesystem_agent.py
│ │ ├── registry_agent.py
│ │ ├── threat_intel_agent.py
│ │ ├── critic_agent.py
│ │ └── report_agent.py
│
├── response/ ← Layer 3: autonomous response agents
│ ├── **init**.py
│ ├── blocklist_agent.py
│ ├── alert_agent.py
│ ├── ticket_agent.py
│ └── verification_loop_agent.py
│
├── sandbox/ ← Docker sandbox management
│ ├── **init**.py
│ └── sandbox_manager.py
│
├── api/ ← FastAPI backend
│ ├── **init**.py
│ ├── main.py
│ ├── routes/
│ │ ├── analyze.py
│ │ ├── status.py
│ │ └── export.py
│ └── models.py ← Pydantic request/response models
│
├── frontend/ ← React UI
│ ├── package.json
│ ├── src/
│ │ ├── App.jsx
│ │ ├── components/
│ │ │ ├── PipelineFlow.jsx
│ │ │ ├── AgentStatus.jsx
│ │ │ ├── Timeline.jsx
│ │ │ ├── IOCTable.jsx
│ │ │ └── ReportPanel.jsx
│ │ ├── hooks/
│ │ │ └── useAnalysis.js ← polling logic
│ │ └── api/
│ │ └── client.js ← API calls
│
├── simulation/ ← simulated data streams for demo
│ ├── **init**.py
│ ├── network_stream.py
│ ├── endpoint_stream.py
│ └── sample_events.json
│
├── tests/
│ ├── test_agents.py
│ ├── test_pipeline.py
│ └── test_response.py
│
└── yara_rules/
└── \*.yar ← community YARA rule files
