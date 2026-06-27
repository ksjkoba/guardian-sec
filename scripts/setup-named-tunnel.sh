#!/usr/bin/env bash
# One-time setup for a STABLE, free Cloudflare Named Tunnel on your own domain.
#
# This is interactive: `cloudflared tunnel login` opens your browser so YOU can
# authorize the tunnel against your Cloudflare account. It must run in your real
# terminal (not a headless/sandboxed one).
#
# After this completes once, start the dashboard anytime with:
#     ./scripts/serve-named.sh
#
# Requirements:
#   - A free Cloudflare account with YOUR DOMAIN already added to it.
#   - The hostname you want, set as GUARDIAN_PUBLIC_HOST in .env
#     (e.g. GUARDIAN_PUBLIC_HOST=guardian.yourdomain.com)
set -euo pipefail
cd "$(dirname "$0")/.."

CF="./bin/cloudflared"
TUNNEL_NAME="${GUARDIAN_TUNNEL_NAME:-guardian}"

# Load .env for GUARDIAN_PUBLIC_HOST
if [[ -f .env ]]; then
  set -a; # shellcheck disable=SC1091
  source .env; set +a
fi

HOST="${GUARDIAN_PUBLIC_HOST:-}"
if [[ -z "$HOST" || "$HOST" == *example.com ]]; then
  echo "ERROR: set your real hostname in .env first, e.g.:"
  echo "    GUARDIAN_PUBLIC_HOST=guardian.yourdomain.com"
  exit 1
fi

# Ensure cloudflared exists
if [[ ! -x "$CF" ]]; then
  echo "Downloading cloudflared (one-time)..."
  mkdir -p bin
  curl -fsSL -o "$CF" \
    https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
  chmod +x "$CF"
fi

echo "=== Step 1/3: Authorize cloudflared with your Cloudflare account ==="
echo "A browser window will open. Pick the domain that owns: $HOST"
"$CF" tunnel login

echo ""
echo "=== Step 2/3: Create the named tunnel '$TUNNEL_NAME' (idempotent) ==="
if "$CF" tunnel list 2>/dev/null | grep -q "[[:space:]]${TUNNEL_NAME}[[:space:]]"; then
  echo "Tunnel '$TUNNEL_NAME' already exists — reusing it."
else
  "$CF" tunnel create "$TUNNEL_NAME"
fi

echo ""
echo "=== Step 3/3: Route $HOST to the tunnel (creates a CNAME DNS record) ==="
"$CF" tunnel route dns "$TUNNEL_NAME" "$HOST"

echo ""
echo "============================================================"
echo "  Named tunnel ready."
echo "    Tunnel:   $TUNNEL_NAME"
echo "    Hostname: https://$HOST/"
echo ""
echo "  Start the dashboard + tunnel anytime with:"
echo "      ./scripts/serve-named.sh"
echo "============================================================"
