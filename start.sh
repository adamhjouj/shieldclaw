#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

OPENCLAW_PORT=18789
SHIELDCLAW_PORT=8443

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down...${NC}"
    kill $OPENCLAW_PID $SHIELDCLAW_PID $DISCORDBOT_PID 2>/dev/null
    wait $OPENCLAW_PID $SHIELDCLAW_PID $DISCORDBOT_PID 2>/dev/null
    echo -e "${GREEN}All processes stopped.${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM

# Kill anything already on our ports
lsof -ti:$OPENCLAW_PORT -ti:$SHIELDCLAW_PORT 2>/dev/null | xargs kill -9 2>/dev/null || true
pkill -9 -f "discord_bot.py" 2>/dev/null || true
sleep 1

# ── 1. OpenClaw gateway ──
echo -e "${CYAN}[1/3]${NC} Starting OpenClaw gateway on port $OPENCLAW_PORT..."
cd "$DIR/openclaw"
npx pnpm openclaw gateway run --port $OPENCLAW_PORT > /tmp/openclaw-gateway.log 2>&1 &
OPENCLAW_PID=$!
cd "$DIR"

for i in $(seq 1 20); do
    if curl -sf http://127.0.0.1:$OPENCLAW_PORT/health > /dev/null 2>&1; then
        echo -e "${GREEN}  ✔ OpenClaw is live${NC}"
        break
    fi
    if [ "$i" -eq 20 ]; then
        echo -e "${RED}  ✘ OpenClaw failed to start (check /tmp/openclaw-gateway.log)${NC}"
        kill $OPENCLAW_PID 2>/dev/null
        exit 1
    fi
    sleep 1
done

# ── 2. ShieldClaw (FastAPI) ──
echo -e "${CYAN}[2/3]${NC} Starting ShieldClaw on port $SHIELDCLAW_PORT (DEV_BYPASS=true)..."
DEV_BYPASS=true python3 "$DIR/main.py" > /tmp/shieldclaw.log 2>&1 &
SHIELDCLAW_PID=$!

for i in $(seq 1 15); do
    if curl -sf http://127.0.0.1:$SHIELDCLAW_PORT/health > /dev/null 2>&1 || \
       lsof -ti:$SHIELDCLAW_PORT > /dev/null 2>&1; then
        echo -e "${GREEN}  ✔ ShieldClaw is live${NC}"
        break
    fi
    if [ "$i" -eq 15 ]; then
        echo -e "${RED}  ✘ ShieldClaw failed to start (check /tmp/shieldclaw.log)${NC}"
        kill $OPENCLAW_PID $SHIELDCLAW_PID 2>/dev/null
        exit 1
    fi
    sleep 1
done

# ── 3. Discord bot ──
echo -e "${CYAN}[3/3]${NC} Starting Discord bot..."
python3 "$DIR/jacob/shieldbot/discord_bot.py" > /tmp/shieldbot-discord.log 2>&1 &
DISCORDBOT_PID=$!
sleep 2

if kill -0 $DISCORDBOT_PID 2>/dev/null; then
    echo -e "${GREEN}  ✔ Discord bot is running${NC}"
else
    echo -e "${RED}  ✘ Discord bot crashed (check /tmp/shieldbot-discord.log)${NC}"
    kill $OPENCLAW_PID $SHIELDCLAW_PID 2>/dev/null
    exit 1
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  All systems go.${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  OpenClaw   → http://127.0.0.1:$OPENCLAW_PORT"
echo -e "  ShieldClaw → http://127.0.0.1:$SHIELDCLAW_PORT"
echo -e "  Discord    → PID $DISCORDBOT_PID"
echo ""
echo -e "  Logs:"
echo -e "    tail -f /tmp/openclaw-gateway.log"
echo -e "    tail -f /tmp/shieldclaw.log"
echo -e "    tail -f /tmp/shieldbot-discord.log"
echo ""
echo -e "${YELLOW}  Press Ctrl+C to stop everything.${NC}"
echo ""

wait
