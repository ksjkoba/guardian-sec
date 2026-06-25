#!/usr/bin/env bash
# Start Guardian with HTTPS (self-signed local cert) — use when binding beyond localhost
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate

export GUARDIAN_INSECURE_SSL="${GUARDIAN_INSECURE_SSL:-1}"
export GUARDIAN_BREACH_PROVIDER="${GUARDIAN_BREACH_PROVIDER:-auto}"
export GUARDIAN_TLS_AUTO="${GUARDIAN_TLS_AUTO:-1}"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl is required for GUARDIAN_TLS_AUTO (install: sudo apt install openssl)"
  exit 1
fi

PYTHON=".venv/bin/python3"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON=python3
fi

echo "Guardian — HTTPS enabled (GUARDIAN_TLS_AUTO=${GUARDIAN_TLS_AUTO})"
echo "  Breach provider: ${GUARDIAN_BREACH_PROVIDER}"
echo "  Dashboard: https://127.0.0.1:8765/  (accept browser warning for self-signed cert)"
echo ""

exec "$PYTHON" -m guardian.cli serve "$@"
