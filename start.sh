#!/usr/bin/env bash
# MalwareScope — Start all services for demo
# Usage: ./start.sh
#
# Starts:
#   1. FastAPI backend (port 9000) — file upload, analysis pipeline, job status
#   2. Analysis service A2A (port 8001) — monitoring → analysis escalation
#   3. Response service A2A (port 8002) — analysis → autonomous response
#   4. React frontend (port 3000) — dev server
#
# Prerequisites:
#   pip install -r requirements.txt
#   cd frontend && npm install
#   cp .env.example .env  (then add your ANTHROPIC_API_KEY)

set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${CYAN}[info]${NC} $*"; }
success() { echo -e "${GREEN}[ok]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC} $*"; }
die()     { echo -e "${RED}[err]${NC}  $*" >&2; exit 1; }

# ── Pre-flight checks ──────────────────────────────────────────────────────────
[ -f "$ROOT_DIR/.env" ] || die ".env not found. Run: cp .env.example .env && edit ANTHROPIC_API_KEY"
source "$ROOT_DIR/.env"
[ -n "$ANTHROPIC_API_KEY" ] || die "ANTHROPIC_API_KEY is not set in .env"

command -v uvicorn >/dev/null 2>&1 || die "uvicorn not found. Run: pip install -r requirements.txt"
command -v npm     >/dev/null 2>&1 || die "npm not found. Install Node.js."

[ -d "$ROOT_DIR/frontend/node_modules" ] || {
  info "Installing frontend dependencies…"
  cd "$ROOT_DIR/frontend" && npm install --silent
}

# ── Kill any previous instances on our ports ───────────────────────────────────
for port in 9000 8001 8002; do
  pid=$(lsof -ti ":$port" 2>/dev/null || true)
  [ -n "$pid" ] && { warn "Killing existing process on port $port (pid $pid)"; kill "$pid" 2>/dev/null || true; }
done

# ── Start services ─────────────────────────────────────────────────────────────
cd "$ROOT_DIR"

info "Starting FastAPI backend on port 9000…"
uvicorn api.main:app --host 0.0.0.0 --port 9000 --log-level info > /tmp/malwarescope_api.log 2>&1 &
API_PID=$!

info "Starting Analysis A2A service on port 8001…"
uvicorn analysis_service.agent:a2a_app --host 0.0.0.0 --port 8001 --log-level warning > /tmp/malwarescope_analysis.log 2>&1 &
ANALYSIS_PID=$!

info "Starting Response A2A service on port 8002…"
uvicorn response_service.agent:a2a_app --host 0.0.0.0 --port 8002 --log-level warning > /tmp/malwarescope_response.log 2>&1 &
RESPONSE_PID=$!

# Give backend services a moment to bind
sleep 2

info "Starting React frontend on port 3000…"
cd "$ROOT_DIR/frontend"
npm start > /tmp/malwarescope_frontend.log 2>&1 &
FRONTEND_PID=$!

# ── Wait for backend health ────────────────────────────────────────────────────
info "Waiting for API to become healthy…"
for i in $(seq 1 15); do
  if curl -sf http://localhost:9000/health >/dev/null 2>&1; then
    success "API is healthy"
    break
  fi
  sleep 1
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  MalwareScope is running!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BLUE}Frontend${NC}       → http://localhost:3000"
echo -e "  ${BLUE}API${NC}            → http://localhost:9000"
echo -e "  ${BLUE}API docs${NC}       → http://localhost:9000/docs"
echo -e "  ${BLUE}Analysis A2A${NC}   → http://localhost:8001"
echo -e "  ${BLUE}Response A2A${NC}   → http://localhost:8002"
echo ""
echo -e "  Logs: /tmp/malwarescope_*.log"
echo -e "  PIDs: api=$API_PID analysis=$ANALYSIS_PID response=$RESPONSE_PID frontend=$FRONTEND_PID"
echo ""
echo -e "  Press ${YELLOW}Ctrl+C${NC} to stop all services"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# ── Trap Ctrl+C to clean up all child processes ────────────────────────────────
cleanup() {
  echo ""
  info "Shutting down all services…"
  kill "$API_PID" "$ANALYSIS_PID" "$RESPONSE_PID" "$FRONTEND_PID" 2>/dev/null || true
  success "All services stopped."
}
trap cleanup INT TERM

wait
