#!/usr/bin/env bash
# Start Guardian as a SHARED dashboard reachable from other machines.
#
# Binds to 0.0.0.0 so devices on your network can reach it at
# http://<this-machine-ip>:<port>/  — and REQUIRES a login password (this
# dashboard is no longer loopback-only, so access control is mandatory).
#
# The password is read from GUARDIAN_DASHBOARD_PASSWORD / _HASH. If neither is
# set, a strong one is generated once and saved to .env so the URL + login stay
# stable across restarts. Print it once, then share it with your users.
#
# Usage:
#   ./scripts/serve-shared.sh                 # port 8765
#   GUARDIAN_PORT=9000 ./scripts/serve-shared.sh
#   GUARDIAN_DASHBOARD_PASSWORD='my pass' ./scripts/serve-shared.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate

ENV_FILE=".env"

# Load any existing .env so a previously-saved password is honored.
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ENV_FILE"
  set +a
fi

export GUARDIAN_BIND_HOST="${GUARDIAN_BIND_HOST:-0.0.0.0}"
PORT="${GUARDIAN_PORT:-8765}"
export GUARDIAN_BREACH_PROVIDER="${GUARDIAN_BREACH_PROVIDER:-auto}"
export GUARDIAN_INSECURE_SSL="${GUARDIAN_INSECURE_SSL:-1}"

# ── Ensure a dashboard password exists (mandatory for a shared dashboard) ──
if [[ -z "${GUARDIAN_DASHBOARD_PASSWORD:-}" && -z "${GUARDIAN_DASHBOARD_PASSWORD_HASH:-}" ]]; then
  GEN_PASS="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(12))')"
  export GUARDIAN_DASHBOARD_PASSWORD="$GEN_PASS"
  {
    echo ""
    echo "# Added by serve-shared.sh — dashboard login password"
    echo "GUARDIAN_DASHBOARD_PASSWORD=$GEN_PASS"
  } >> "$ENV_FILE"
  echo "============================================================"
  echo "  Generated a dashboard password and saved it to .env:"
  echo ""
  echo "      $GEN_PASS"
  echo ""
  echo "  Share this with the people who should have access."
  echo "  Change it anytime by editing GUARDIAN_DASHBOARD_PASSWORD in .env."
  echo "============================================================"
fi

# ── Show the URLs users should open ──
LAN_IP="$(.venv/bin/python -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(('8.8.8.8', 80)); print(s.getsockname()[0]); s.close()" 2>/dev/null || echo '<this-machine-ip>')"
echo ""
echo "Guardian SHARED dashboard"
echo "  Bind:    ${GUARDIAN_BIND_HOST}:${PORT}"
echo "  Local:   http://127.0.0.1:${PORT}/"
echo "  Network: http://${LAN_IP}:${PORT}/   <- share this with users on your network"
echo "  Login:   password required (see above / .env)"
echo ""
echo "  Note: on WSL2, expose to your Windows LAN with (run in PowerShell as admin):"
echo "    netsh interface portproxy add v4tov4 listenport=${PORT} listenaddress=0.0.0.0 connectport=${PORT} connectaddress=${LAN_IP}"
echo "    netsh advfirewall firewall add rule name=Guardian dir=in action=allow protocol=TCP localport=${PORT}"
echo ""

exec .venv/bin/python -m guardian.cli serve --host "${GUARDIAN_BIND_HOST}" --port "${PORT}" "$@"
