#!/bin/bash
# Start MalwareScope — backend (port 8001) + frontend (port 3000)

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# Colors
G='\033[32m' R='\033[31m' Y='\033[33m' B='\033[1m' RS='\033[0m'

echo -e "${B}MalwareScope${RS} — starting services"

# Check .env
if [ ! -s "snowflake_chat_integration/.env" ] || ! grep -q "ANTHROPIC_API_KEY=sk-" "snowflake_chat_integration/.env" 2>/dev/null; then
  echo -e "${Y}WARNING:${RS} Set ANTHROPIC_API_KEY in snowflake_chat_integration/.env for RAG chat"
fi

# Start backend
echo -e "${G}Starting backend${RS} on port 8001..."
.venv/bin/python -m uvicorn api_server:app --port 8001 --reload &
BACKEND_PID=$!

# Start frontend
echo -e "${G}Starting frontend${RS} on port 3000..."
cd frontend
npx next dev --port 3000 &
FRONTEND_PID=$!
cd ..

echo ""
echo -e "${B}Ready:${RS}"
echo -e "  Frontend: ${G}http://localhost:3000${RS}"
echo -e "  Backend:  ${G}http://localhost:8001${RS}"
echo -e "  Health:   ${G}http://localhost:8001/health${RS}"
echo ""
echo "Press Ctrl+C to stop both."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait
