# Guardian deployment guide

Guardian is **local-first**. The default and recommended setup is a personal
dashboard bound to `127.0.0.1`. This guide also covers exposing it on a server,
which requires an authenticating HTTPS front end (see *Security* below).

Replace `guardian.example.com` with your own hostname throughout.

---

## Local PC (default, recommended)

No public DNS or TLS required.

```bash
pip install "guardian-sec[web]"
guardian serve            # http://127.0.0.1:8765
```

Optional `.env`:

```env
GUARDIAN_DEPLOY_MODE=local
```

---

## Free public URL (no VPS) — Cloudflare Tunnel

The fastest **$0** way to put Guardian online for others, straight from your PC
(works behind NAT/WSL2, no router or firewall changes, HTTPS included):

```bash
./scripts/serve-public.sh
```

This downloads `cloudflared` (once), starts the **password-protected** dashboard,
opens a Cloudflare tunnel, and prints a public `https://…trycloudflare.com` URL.
Share that URL plus the dashboard password (in `.env`).

Notes:
- The dashboard is only reachable while the script (your PC) is running.
- The quick-tunnel URL is random and changes on restart.
- Always keep the dashboard password set; the tunnel is open to the internet.

### Stable custom URL (free, your own domain)

For a permanent URL like `https://guardian.yourdomain.com` that never changes,
use a Cloudflare **named tunnel** (free; needs a free Cloudflare account with
your domain added).

```bash
# 1. Set your hostname in .env
echo 'GUARDIAN_PUBLIC_HOST=guardian.yourdomain.com' >> .env

# 2. One-time interactive setup (opens a browser to authorize the tunnel)
./scripts/setup-named-tunnel.sh

# 3. Run it anytime afterwards — same URL every time
./scripts/serve-named.sh
```

The one-time setup logs in, creates a tunnel named `guardian`, and adds a CNAME
DNS record routing your hostname to it. `serve-named.sh` then starts the
password-protected dashboard and serves it at your hostname. Both the dashboard
password and Cloudflare TLS apply.

---

## Server / VPS (public)

> **Important:** Set a dashboard password for any network-exposed deployment.
> Guardian's built-in session handshake provides end-to-end *payload
> encryption*, not access control. Setting `GUARDIAN_DASHBOARD_PASSWORD` (or
> `GUARDIAN_DASHBOARD_PASSWORD_HASH`) enables a real login gate in front of the
> dashboard. For internet-facing deployments, also put it behind a reverse
> proxy that terminates TLS (and optionally adds its own auth layer).

### Dashboard password

```bash
# Simplest:
export GUARDIAN_DASHBOARD_PASSWORD='a-long-passphrase'

# Preferred — keep the plaintext out of the environment:
python -c "import hashlib,getpass; print(hashlib.sha256(getpass.getpass().encode()).hexdigest())"
export GUARDIAN_DASHBOARD_PASSWORD_HASH='<the-hash-above>'
```

When a password is set, browsers must log in before the dashboard issues a
session or serves any API route (the WebSocket is gated too). Sessions last
`GUARDIAN_ACCESS_TTL` seconds (default 24h).

**Brute-force protection.** After `GUARDIAN_LOGIN_MAX_FAILURES` failed attempts
(default 5) a client is locked out for `GUARDIAN_LOGIN_LOCKOUT_SECS` (default
300s). Loopback is exempt unless you set `GUARDIAN_LOGIN_THROTTLE_LOCAL=1`.

**Audit log.** Every login success, failure, lockout, and logout is appended to
`<data_dir>/audit.log` as JSONL (mode `0600`). Review it to spot probing:

```bash
tail -f ~/.guardian/audit.log
```

### Option A — Nginx reverse proxy (recommended)

Run Guardian bound to localhost and let nginx serve HTTPS on 443.

`/etc/nginx/sites-available/guardian`:

```nginx
server {
    listen 80;
    server_name guardian.example.com;
    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # Add an auth layer here (auth_basic, mTLS, or an SSO subrequest).
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/guardian /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d guardian.example.com
```

`.env`:

```env
GUARDIAN_BIND_HOST=127.0.0.1
GUARDIAN_PUBLIC_HOST=guardian.example.com
GUARDIAN_PUBLIC_PORT=443
GUARDIAN_DEPLOY_MODE=vps
```

### Option B — Guardian serves TLS directly

```bash
sudo certbot certonly --standalone -d guardian.example.com
```

`.env`:

```env
GUARDIAN_TLS_CERT=/etc/letsencrypt/live/guardian.example.com/fullchain.pem
GUARDIAN_TLS_KEY=/etc/letsencrypt/live/guardian.example.com/privkey.pem
GUARDIAN_BIND_HOST=0.0.0.0
```

For local testing you can also set `GUARDIAN_TLS_AUTO=1` to generate a
self-signed certificate under the data directory (`~/.guardian/tls/`).

---

## Firewall

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
# Only if exposing Guardian directly (no nginx): sudo ufw allow 8765/tcp
sudo ufw enable
```

---

## Auto-start (systemd)

Copy `scripts/guardian.service` to `/etc/systemd/system/guardian.service`,
adjust the paths/user/hostname, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now guardian
sudo systemctl status guardian
```

Rate limiting (VPS mode): set `GUARDIAN_RATE_LIMIT=120` (requests/min per IP).

---

## Production security checklist

| Control | Recommended value |
|---------|-------------------|
| `GUARDIAN_DASHBOARD_PASSWORD[_HASH]` | **Set a dashboard login password** (real access control) |
| `GUARDIAN_BIND_HOST=127.0.0.1` | Don't expose Guardian directly; front it with nginx |
| Reverse-proxy auth | optional extra layer (basic auth / mTLS / SSO) in front of the dashboard |
| `GUARDIAN_DISABLE_TEST_ALERT=1` | Block `/api/test-alert` (no fake alert injection) |
| `cryptography` installed | Enables E2E payload encryption + at-rest encryption |
| TLS | Terminate HTTPS at the proxy (Option A) or in Guardian (Option B) |

---

## Persistence

Alerts and campaigns are stored under the data directory
(`~/.guardian/dashboard.db` by default) and restored on restart. Dashboard
settings are saved to `~/.guardian/settings.json`. Set `GUARDIAN_DATA_DIR` to
choose a different writable location.
```