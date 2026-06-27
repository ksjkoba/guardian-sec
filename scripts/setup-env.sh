#!/usr/bin/env bash
# Copy .env.example → .env for live breach checks + optional TLS/security keys
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  echo "Already exists: .env (not overwritten)"
  echo "Compare with .env.example for new options."
  exit 0
fi

cp .env.example .env
echo "Created .env from .env.example"
echo ""
echo "Next steps:"
echo "  1. Edit .env — add HIBP_API_KEY if you have one (optional)"
echo "  2. For LAN/remote access, set GUARDIAN_TLS_AUTO=1"
echo "  3. Start local:  ./scripts/open-guardian.sh"
echo "     Start VPS:    cp .env.vps.example .env && ./scripts/serve-vps.sh"
echo "     Deploy guide: docs/deployment.md"
