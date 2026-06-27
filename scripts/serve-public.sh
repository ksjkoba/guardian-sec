#!/usr/bin/env bash
# Put Guardian online with a FREE public HTTPS URL via Cloudflare Tunnel.
#
# Cost: $0. No VPS, no router/firewall changes, no Cloudflare account needed for
# the quick-tunnel mode. The dashboard stays password-protected (serve-shared.sh
# enforces a login), and Cloudflare terminates TLS, so the public URL is HTTPS.
#
# Caveat: a "quick tunnel" URL (*.trycloudflare.com) is RANDOM and changes on
# every restart. For a STABLE URL you need a free Cloudflare account + a domain
# (a "named tunnel") — see the note printed at the end.
#
# The dashboard is only reachable while this script (your PC) is running.
#
# Usage:
#   ./scripts/serve-public.sh                 # dashboard on :8801 + public tunnel
#   GUARDIAN_PORT=9000 ./scripts/serve-public.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${GUARDIAN_PORT:-8801}"
CF="./bin/cloudflared"
CF_LOG="/tmp/cloudflared.log"

# ── 1. Ensure cloudflared is available (download the static binary if not) ──
if [[ ! -x "$CF" ]]; then
  echo "Downloading cloudflared (one-time)..."
  mkdir -p bin
  curl -fsSL -o "$CF" \
    https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
  chmod +x "$CF"
fi

# ── 2. Start the password-protected dashboard if it isn't already up ──
if ! curl -s -o /dev/null "http://127.0.0.1:${PORT}/" 2>/dev/null; then
  echo "Starting Guardian dashboard on :${PORT} ..."
  setsid bash -c "GUARDIAN_PORT=${PORT} ./scripts/serve-shared.sh > /tmp/guardian-dashboard.log 2>&1" < /dev/null &
  disown
  for _ in $(seq 1 30); do
    curl -s -o /dev/null "http://127.0.0.1:${PORT}/" 2>/dev/null && break
    sleep 1
  done
fi

# ── 3. Start the Cloudflare tunnel (http2 protocol works where UDP is blocked) ──
echo "Starting Cloudflare tunnel ..."
pkill -f "cloudflared tunnel" 2>/dev/null || true
sleep 1
setsid bash -c "$CF tunnel --url http://127.0.0.1:${PORT} --protocol http2 --no-autoupdate > $CF_LOG 2>&1" < /dev/null &
disown

# ── 4. Wait for the public URL + a registered connection ──
URL=""
for _ in $(seq 1 30); do
  URL="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$CF_LOG" 2>/dev/null | head -1 || true)"
  [[ -n "$URL" ]] && grep -q "Registered tunnel connection" "$CF_LOG" 2>/dev/null && break
  sleep 1
done

echo ""
echo "============================================================"
if [[ -n "$URL" ]]; then
  echo "  Guardian is LIVE on the internet (free):"
  echo ""
  echo "      $URL"
  echo ""
  echo "  Share this URL + the dashboard password (see .env) with"
  echo "  anyone who should have access."
else
  echo "  Tunnel started but no URL yet — check: tail -f $CF_LOG"
fi
echo "------------------------------------------------------------"
echo "  Note: this *.trycloudflare.com URL changes each restart."
echo "  For a permanent custom URL (still free):"
echo "    1. Create a free Cloudflare account + add a domain."
echo "    2. $CF tunnel login"
echo "    3. $CF tunnel create guardian"
echo "    4. Route a hostname:  $CF tunnel route dns guardian guardian.YOURDOMAIN"
echo "    5. Run: $CF tunnel run --url http://127.0.0.1:${PORT} guardian"
echo "============================================================"
echo ""
echo "  Stop everything:  pkill -f cloudflared; pkill -f 'guardian.cli serve'"
