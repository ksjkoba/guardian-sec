# Guardian — Chat Handoff

Use this file with `@docs/guardian-handoff.md` in a new Cursor chat to continue work without losing context.

**Project:** Guardian — SLM-powered cybersecurity dashboard  
**Location (WSL):** `~/Guardian/Sec`  
**Windows path:** `\\wsl$\Ubuntu\home\jhak\Guardian\Sec`  
**Dashboard:** http://127.0.0.1:8765  
**Serve:** `python3 -m guardian.cli serve`

---

## Environment

- Windows + WSL Ubuntu; often run commands from Git Bash or WSL
- Corporate SSL proxy: `export GUARDIAN_INSECURE_SSL=1` before serve/fetch
- Virtualenv: `cd ~/Guardian/Sec && source .venv/bin/activate`
- If port busy: `pkill -f 'guardian.cli serve'`
- After code changes: restart serve + hard-refresh dashboard (`Ctrl+Shift+R`)

---

## What Was Built

### Live feed (fixed)
- **Root cause:** `asyncio.Queue` created on wrong event loop when uvicorn ran in a background thread; WebSocket clients never received alerts
- **Fix:** Queue created in FastAPI `lifespan` via `asyncio.get_running_loop()`
- CLI starts web server **before** defense modules; `wait_for_server_ready()` exits if port 8765 is in use
- Heartbeats sync uptime via `msg.stats` in `index.html`

### Test alerts
- `POST /api/test-alert` and `python3 -m guardian.cli test-alert`
- Uses shared `state` singleton in `cli.py` (not a separate `DashboardState()`)

### Global threat ticker
- Module: `guardian/intel/global_ticker.py` (`global_feed`)
- Polls ~every 120s: **ThreatFox**, **URLhaus**, **MalwareBazaar**, **CISA KEV**, **OpenPhish**, **Feodo Tracker**, **PhishTank**, **Spamhaus DROP**, **URLhaus-Hosts**, **SSLBL**, **blocklist.de**, **Tor Exit Nodes** (12 sources)
- APIs: `POST /api/global-feed/push`, `GET /api/global-feed/sources`, `GET /api/global-feed/status` (includes `sources_ok` / `sources_failed`)
- **Balanced fetch:** `DEFAULT_PER_SOURCE_QUOTA = 6`, round-robin interleave (was ThreatFox-only before)
- **`classify_severity()`** — threat type, confidence, malware family, source → LOW/MEDIUM/HIGH/CRITICAL mix
- **Cross-source IOC dedup** — same URL/IP from multiple providers surfaces once (`normalize_ioc()`)
- **OpenPhish cache** — 15 min stale fallback on proxy `Connection reset`
- **PhishTank** — HTTPS CSV + 15 min cache (fixed proxy/rate-limit issues)

### Source verification
- `guardian/intel/verifier.py` — `POST /api/verify-alert` live re-check against provider feeds
- Badges: ✓ Confirmed on source | ⚠ Aged off feed | 🧪 Test alert
- Global alerts: `verified: true` at ingest, `verified_method: ingested_from_live_feed`

### Parser fixes
- **ThreatFox CSV:** fixed column mapping (was using IOC ID as malware name); confidence from `confidence_level`
- **URLhaus CSV:** fixed threat type column (was showing dates instead of `malware_download`)

### Personal breach check (two-tab UI)
- **Tab 1 — Personal Check:** email/phone/username breach lookup + timeline + watchlist
- **Tab 2 — Live Threat Feed:** existing SOC dashboard (unchanged)
- Module: `guardian/intel/breach_lookup.py`
- APIs: `GET /api/breach/scenarios`, `POST /api/breach/check`, `GET/POST/DELETE /api/breach/watchlist/*`

**Providers (`GUARDIAN_BREACH_PROVIDER`):**

| Value | Behavior |
|-------|----------|
| `mock` (default) | Fictional demo emails for QA — sample chips in UI |
| `auto` | **HIBP** if `HIBP_API_KEY` set, else **multi** (free dual-source) |
| `multi` | **XposedOrNot + HackMyIP** — free, no keys; exposed if any source hits |
| `xposedornot` | Single free source |
| `hibp` | Have I Been Pwned (paid key required) |

- Daily quota counter in banner (`used/limit/remaining`, resets UTC midnight)
- Live mode: **email only** — phone/username tabs greyed out (APIs don't support them)
- Mock personas: `marcus.hale47@gmail.com` (clean), `dana.porter1988@outlook.com` (3 breaches), etc.

**Quick start live:**
```bash
./scripts/serve-live.sh
# or: export GUARDIAN_BREACH_PROVIDER=auto && python3 -m guardian.cli serve
```

**Production (HIBP):**
```bash
export HIBP_API_KEY=your-key
export GUARDIAN_BREACH_PROVIDER=auto
./scripts/serve-live.sh
```

Copy `.env.example` → `.env` for persistent config.

---
- Inter font, welcome banner, plain-English summaries
- Source links: homepage + "View original report"
- 🌍 Worldwide filter, source catalog sidebar
- Color-coded source badges (ThreatFox purple, URLhaus orange, etc.)
- **Global feed poll health** panel — last poll age, batch size, per-source ok/fail from `/api/global-feed/status`
- **Cross-verify sources** button on global alerts — calls `POST /api/cross-verify`

---

## Key Files

| Path | Purpose |
|------|---------|
| `guardian/web/server.py` | Lifespan queue, API routes, metadata passthrough |
| `guardian/cli.py` | Serve order, `wait_for_server_ready`, global ticker start |
| `guardian/intel/breach_lookup.py` | Personal check — mock / XposedOrNot / HIBP |
| `scripts/serve-live.sh` | Start with `GUARDIAN_BREACH_PROVIDER=auto` |
| `scripts/qa_mock_scenarios.py` | Full mock QA runner (33 checks) |
| `tests/test_breach_lookup.py`, `tests/test_breach_providers.py` | Breach tests |
| `guardian/web/static/index.html` | Two-tab UX, verify badges, breach check UI |
| `guardian/intel/global_ticker.py` | Feed polling, severity, balanced fetch |
| `guardian/intel/verifier.py` | Live source verification |
| `guardian/intel/feeds.py` | ThreatFox CSV malware column fix |
| `tests/test_global_ticker.py`, `tests/test_verifier.py` | Tests |

---

## How to Run

```bash
pkill -f 'guardian.cli serve'   # if needed
cd ~/Guardian/Sec && source .venv/bin/activate
export GUARDIAN_INSECURE_SSL=1
python3 -m guardian.cli serve
```

**Validate global feeds:** Filter **🌍 Worldwide** — click **View original report** or verify on ThreatFox/URLhaus directly.  
**Test data only:** `python3 -m guardian.cli test-alert`  
**Re-verify alert:** `POST /api/verify-alert` with `{"alert_id":"..."}`

---

## Known Gaps / Next Steps

1. **HIBP for prod** — set `HIBP_API_KEY` + `GUARDIAN_BREACH_PROVIDER=auto` when ready to ship
2. **Phone/username live lookup** — no free API; tabs disabled in live mode until a provider is added
3. **Restart required** after some settings changes — use Settings tab or `.env`
4. **OpenPhish / Tor exits** may fail behind corporate proxy — cache mitigates; VPN helps
5. **Optional:** `ABUSEIPDB_API_KEY`, `NVD_API_KEY`, `ABUSE_CH_AUTH_KEY` for cross-verify enrichers
6. **Local alerts** (logs/network) use Phi-3 SLM — wording can hallucinate; global feeds do not
7. **scapy** not installed — network monitor disabled; install + sudo for local network alerts
8. **Deployment:** see `docs/deployment.md` for local and VPS setup

### Recently added

- **Persistence** — `~/.guardian/dashboard.db` restores alerts/campaigns across restarts
- **Settings tab** — breach provider, deploy mode, TLS; saves to `~/.guardian/settings.json`
- **Campaign narratives** — rule-based summary when SLM unavailable
- **Export** — Settings → Export dashboard JSON
- **VPS** — `scripts/guardian.service`, rate limiting via `GUARDIAN_RATE_LIMIT`

---

## Errors Seen & Fixes

| Error | Resolution |
|-------|------------|
| `Connection refused` on 8765 | Run `serve` in separate terminal; `pkill` if port busy |
| `[dashboard] WARN: event loop closed; dropped alert` | Old server / failed bind — restart cleanly |
| `[dashboard] WARN: _emit before queue wired` | Test ran in separate process, not connected to serve |
| SSL cert failures | `GUARDIAN_INSECURE_SSL=1` |
| abuse.ch APIs 401 | Use CSV exports (no API key) |
| Only ThreatFox in feed | Balanced round-robin fetch (fixed) |
| All CRITICAL/HIGH | `classify_severity()` (fixed) |
| `reference_url: "75"` | ThreatFox CSV column misalignment (fixed) |

---

## Continuation Prompt (copy into new chat)

```
Continue Guardian dashboard work. Read @docs/guardian-handoff.md for full context.

Stack: WSL ~/Guardian/Sec, serve on :8765, GUARDIAN_INSECURE_SSL=1 often required.

Prior work: live WebSocket feed fix, global threat ticker (12 sources), Personal Check tab
(mock + XposedOrNot + HIBP auto provider, quota counter), source verification, cross-verify UI.

Personal Check: GUARDIAN_BREACH_PROVIDER=auto (free XON now; HIBP when key set).
See .env.example and scripts/serve-live.sh.

If you need verbatim prior discussion, also attach the exported chat markdown from Cursor.
```
N now; HIBP when key set).
See .env.example and scripts/serve-live.sh.

If you need verbatim prior discussion, also attach the exported chat markdown from Cursor.
```
