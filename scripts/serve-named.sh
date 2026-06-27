#!/usr/bin/env bash
# Run Guardian behind a STABLE Cloudflare Named Tunnel on your own domain.
#
# Prerequisite: run ./scripts/setup-named-tunnel.sh once (interactive login).
# After that, this script starts the password-protected dashboard and serves it
# at https://$GUARDIAN_PUBLIC_HOST/ — the same URL every time.
#
# The dashboard is only reachable while this script (your PC) is running.
set -euo pipefail
cd "$(dirname "$0")/.."

CF="./bin/cloudflared"
TUNNEL_NAME="${GUARDIAN_TUNNEL_NAME:-guardian}"
PORT="${GUARDIAN_PORT:-8801}"

if [[ -f .env ]]; then
  set -a; # shellcheck disable=SC1091
  source .env; set +a
fi

HOST="${GUARDIAN_PUBLIC_HOST:-}"
if [[ -z "$HOST" || "$HOST" == *example.com ]]; then
  echo "ERROR: set GUARDIAN_PUBLIC_HOST in .env (e.g. guardian.yourdomain.com)"
  exit 1
fi

if [[ ! -x "$CF" ]] || ! "$CF" tunnel list 2>/dev/null | grep -q "[[:space:]]${TUNNEL_NAME}[[:space:]]"; then
  echo "Named tunnel '$TUNNEL_NAME' not set up yet."
  echo "Run the one-time setup first:  ./scripts/setup-named-tunnel.sh"
  exit 1
fi

# Start the password-protected dashboard if not already up.
if ! curl -s -o /dev/null "http://127.0.0.1:${PORT}/" 2>/dev/null; then
  echo "Starting Guardian dashboard on :${PORT} ..."
  setsid bash -c "GUARDIAN_PORT=${PORT} ./scripts/serve-shared.sh > /tmp/guardian-dashboard.log 2>&1" < /dev/null &
  disown
  for _ in $(seq 1 30); do
    curl -s -o /dev/null "http://127.0.0.1:${PORT}/" 2>/dev/null && break
    sleep 1
  done
fi

echo ""
echo "============================================================"
echo "  Guardian is LIVE at:  https://$HOST/"
echo "  Share this URL + the dashboard password (see .env)."
echo "============================================================"
echo ""
echo "  Stop: Ctrl+C here, then  pkill -f 'guardian.cli serve'"
echo ""

# Run the tunnel in the foreground (http2 protocol works where UDP is blocked).
exec "$CF" tunnel --protocol http2 --no-autoupdate run --url "http://127.0.0.1:${PORT}" "$TUNNEL_NAME"
