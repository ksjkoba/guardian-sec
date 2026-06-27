#!/usr/bin/env bash
# VPS deployment — public dashboard at https://guardian.example.com
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate

export GUARDIAN_DEPLOY_MODE="${GUARDIAN_DEPLOY_MODE:-vps}"
export GUARDIAN_PUBLIC_HOST="${GUARDIAN_PUBLIC_HOST:-guardian.example.com}"
export GUARDIAN_PUBLIC_PORT="${GUARDIAN_PUBLIC_PORT:-443}"
export GUARDIAN_BIND_HOST="${GUARDIAN_BIND_HOST:-0.0.0.0}"
export GUARDIAN_BREACH_PROVIDER="${GUARDIAN_BREACH_PROVIDER:-auto}"
export GUARDIAN_INSECURE_SSL="${GUARDIAN_INSECURE_SSL:-0}"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

PYTHON=".venv/bin/python3"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON=python3
fi

HOST="${GUARDIAN_BIND_HOST:-0.0.0.0}"
PORT="${GUARDIAN_PORT:-8765}"

echo "Guardian VPS — ${GUARDIAN_PUBLIC_HOST:-guardian.example.com}"
echo "  Bind: ${HOST}:${PORT}"
if [[ -n "${GUARDIAN_TLS_CERT:-}" ]]; then
  echo "  Public: https://${GUARDIAN_PUBLIC_HOST}/ (TLS cert configured)"
else
  echo "  WARN: Set GUARDIAN_TLS_CERT/GUARDIAN_TLS_KEY in .env (see .env.vps.example)"
  echo "  Or run certbot, then restart."
fi
echo ""

exec "$PYTHON" -m guardian.cli serve --host "$HOST" --port "$PORT" "$@"
