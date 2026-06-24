#!/usr/bin/env bash
# One-click: start Guardian if needed, open http://127.0.0.1:8765 in your browser
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

PYTHON=".venv/bin/python3"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON=python3
fi

exec "$PYTHON" -m guardian.cli open "$@"
