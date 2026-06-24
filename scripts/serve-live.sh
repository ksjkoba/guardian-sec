#!/usr/bin/env bash
# Start Guardian with live Personal Check (auto provider: HIBP if keyed, else XposedOrNot)
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate

export GUARDIAN_INSECURE_SSL="${GUARDIAN_INSECURE_SSL:-1}"
export GUARDIAN_BREACH_PROVIDER="${GUARDIAN_BREACH_PROVIDER:-auto}"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

echo "Guardian — breach provider: ${GUARDIAN_BREACH_PROVIDER}"
if [[ -n "${HIBP_API_KEY:-}" ]]; then
  echo "  HIBP_API_KEY: set (auto will prefer HIBP)"
else
  echo "  HIBP_API_KEY: not set (auto will use free multi-source: XposedOrNot + HackMyIP)"
fi
echo "  Dashboard: http://127.0.0.1:8765"
echo ""

exec python3 -m guardian.cli serve "$@"
