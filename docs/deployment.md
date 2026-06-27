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

## Server / VPS (public)

> **Important:** Guardian's built-in session handshake provides end-to-end
> payload encryption, **not** access control. Anyone who can reach a public
> dashboard can use it. Put it behind a reverse proxy that terminates TLS and
> enforces authentication (basic auth, mTLS, or SSO).

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
| `GUARDIAN_BIND_HOST=127.0.0.1` | Don't expose Guardian directly; front it with nginx |
| Reverse-proxy auth | basic auth / mTLS / SSO in front of the dashboard |
| `GUARDIAN_DISABLE_TEST_ALERT=1` | Block `/api/test-alert` (no fake alert injection) |
| `cryptography` installed | Enables API session auth + at-rest encryption |
| TLS | Terminate HTTPS at the proxy (Option A) or in Guardian (Option B) |

---

## Persistence

Alerts and campaigns are stored under the data directory
(`~/.guardian/dashboard.db` by default) and restored on restart. Dashboard
settings are saved to `~/.guardian/settings.json`. Set `GUARDIAN_DATA_DIR` to
choose a different writable location.
```