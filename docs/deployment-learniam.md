# Guardian deployment — learniam.online

## Domain layout (recommended)

| Host | Purpose |
|------|---------|
| `learniam.online` | Marketing landing (`website/learniam/index.html`) |
| `guardian.learniam.online` | Guardian dashboard (VPS) |

The dashboard lives on a **subdomain** so the apex serves the public landing page.

---

## Marketing landing page (`learniam.online`)

Static site source: `website/learniam/index.html`

**Preview locally:**

```bash
cd ~/Guardian/Sec/website/learniam
python3 -m http.server 8080
# open http://127.0.0.1:8080
```

**Deploy on VPS (same server as Guardian):**

1. Copy project to `/opt/guardian/Sec` (includes `website/learniam/`)
2. Enable nginx apex config:

```bash
sudo cp /opt/guardian/Sec/website/learniam/nginx-apex.conf /etc/nginx/sites-available/learniam-apex
sudo ln -s /etc/nginx/sites-available/learniam-apex /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d learniam.online -d www.learniam.online
```

3. Point DNS **A** records `@` and `www` to the same VPS IP as `guardian`.

**Hostinger static hosting (no VPS):** upload `website/learniam/index.html` as your site root in hPanel → **Websites**, and point `guardian` subdomain A record to your Guardian server separately.

---

## Hostinger DNS (do this in hPanel)

1. **Domains** → **learniam.online** → **DNS / Nameservers** → **DNS records**
2. Add:

| Type | Name | Content | TTL |
|------|------|---------|-----|
| **A** | `guardian` | `<YOUR_VPS_PUBLIC_IP>` | 3600 |

3. Optional apex (marketing on Hostinger hosting):

| Type | Name | Content |
|------|------|---------|
| **A** | `@` | Hostinger hosting IP (from Websites panel) |

DNS can take up to 24h; usually minutes. Check: `dig +short guardian.learniam.online`

---

## End-user deployment choices

### Local PC (default)

Personal machine — no public DNS required.

```bash
./scripts/setup-env.sh      # once
./scripts/open-guardian.sh  # http://127.0.0.1:8765
```

`.env`:

```env
GUARDIAN_DEPLOY_MODE=local
```

### VPS (public)

Remote server reachable at **https://guardian.learniam.online**

```bash
cp .env.vps.example .env
# Edit .env — set TLS paths after certbot
./scripts/serve-vps.sh
```

---

## VPS TLS with Let's Encrypt

On Ubuntu/Debian VPS (after DNS A record points to the server):

```bash
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx
```

**Option A — Nginx reverse proxy (recommended)**

`/etc/nginx/sites-available/guardian`:

```nginx
server {
    listen 80;
    server_name guardian.learniam.online;
    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/guardian /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d guardian.learniam.online
```

Run Guardian bound to localhost only:

```env
GUARDIAN_BIND_HOST=127.0.0.1
GUARDIAN_PUBLIC_HOST=guardian.learniam.online
GUARDIAN_PUBLIC_PORT=443
GUARDIAN_DEPLOY_MODE=vps
```

**Option B — Guardian serves TLS directly**

```bash
sudo certbot certonly --standalone -d guardian.learniam.online
```

In `.env`:

```env
GUARDIAN_TLS_CERT=/etc/letsencrypt/live/guardian.learniam.online/fullchain.pem
GUARDIAN_TLS_KEY=/etc/letsencrypt/live/guardian.learniam.online/privkey.pem
GUARDIAN_BIND_HOST=0.0.0.0
```

---

## Firewall

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
# Only if not using nginx: sudo ufw allow 8765/tcp
sudo ufw enable
```

---

## Auto-start (systemd)

Copy `scripts/guardian.service` to `/etc/systemd/system/guardian.service`, adjust paths/user, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now guardian
sudo systemctl status guardian
```

Pair with nginx + certbot (Option A above). Guardian binds to `127.0.0.1:8765`; nginx serves HTTPS on 443.

Rate limiting: set `GUARDIAN_RATE_LIMIT=120` in `.env` (requests/min per IP, VPS mode only).

---

## Production security

| Control | VPS default |
|---------|-------------|
| `GUARDIAN_DISABLE_TEST_ALERT=1` | Blocks `/api/test-alert` (no fake alert injection) |
| `GUARDIAN_BIND_HOST=127.0.0.1` | Guardian not exposed directly; nginx on 443 only |
| API session auth | Required for sensitive routes when `cryptography` installed |
| Verify badges | Persisted to `dashboard.db` after live re-check |

Override test-alert only for debugging: `GUARDIAN_ALLOW_TEST_ALERT=1` (not recommended on public internet).

---

## Persistence

Alerts and campaigns are stored in `~/.guardian/dashboard.db` and restored when Guardian restarts.

User settings from the dashboard **Settings** tab are saved to `~/.guardian/settings.json`.

---

## Email mailboxes (Hostinger)

Create in hPanel → **Emails** (forward all to your inbox if you prefer one inbox):

| Address | Purpose |
|---------|---------|
| `grievance@learniam.online` | DPDP Grievance Officer (Kshitish Jha) |
| `privacy@learniam.online` | Privacy / DPDP queries |
| `security@learniam.online` | Vulnerability reports |
| `contact@learniam.online` | General contact |
