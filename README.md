# Guardian / Sec

[![CI](https://github.com/ksjkoba/guardian-sec/actions/workflows/ci.yml/badge.svg)](https://github.com/ksjkoba/guardian-sec/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**SLM-powered local cybersecurity defense system** — a self-hosted security dashboard that pairs a local small language model (Phi-3-mini) with live threat-intelligence feeds. It watches your logs, files, processes, and network for threats, correlates them into attack campaigns, and provides a personal data-breach check — all on `127.0.0.1` by default.

> Designed for individuals and small teams who want meaningful security monitoring without sending their data to a third-party SaaS.

---

## Features

- **Live web dashboard** — real-time alert feed, attack-campaign correlation, and stats at `http://127.0.0.1:8765`.
- **SLM-powered analysis** — local Phi-3-mini scans code, configs, and logs for vulnerabilities (no model file required to run the dashboard).
- **Defense modules** — log analyzer, file-integrity monitor, process monitor, and network monitor, all feeding a shared threat correlator.
- **Threat intelligence** — aggregates open-source feeds (ThreatFox, URLhaus, CISA KEV, Feodo, and more) with 5-stage cross-source verification.
- **Personal breach check** — k-anonymity password checks and email/username breach lookups, encrypted in the browser.
- **Defense-in-depth** — X25519/AES-256-GCM encrypted API payloads, session auth, optional TLS, and an encrypted at-rest vault.
- **Persistence** — alerts and campaigns survive restarts (`~/.guardian/dashboard.db`); falls back to a temp dir gracefully when that path isn't writable.

## Quick start

```bash
cd ~/Guardian/Sec
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[web]"          # core + web dashboard
python -m guardian.cli serve --open
```

Dashboard: <http://127.0.0.1:8765>

One-click launcher (starts the server in the background if needed, then opens your browser):

```bash
./scripts/open-guardian.sh
# or:
python -m guardian.cli open
```

## Installation options

Guardian's heavy dependencies are optional extras so the core stays lightweight:

| Extra | Installs | Enables |
|-------|----------|---------|
| _(none)_ | `click`, `rich`, `psutil` | CLI, log/file/process scanning |
| `.[web]` | + `fastapi`, `uvicorn`, `cryptography` | Web dashboard, encrypted API, breach checks |
| `.[slm]` | + `llama-cpp-python` | Local Phi-3 vulnerability analysis |
| `.[network]` | + `scapy` | Live packet sniffing (needs root / `cap_net_raw`) |
| `.[full]` | everything above | All features |

For the local SLM, also download the model:

```bash
python -m guardian.cli download-model        # Phi-3-mini GGUF (~2.4 GB)
```

> `llama-cpp-python` compiles from source. For GPU builds see the comments in `requirements.txt`.

## Usage

```bash
# Run the dashboard + all defense modules
python -m guardian.cli serve

# Run every module as a headless daemon (no web UI)
python -m guardian.cli defend --respond        # dry-run active response

# One-shot scans
python -m guardian.cli scan-code ./src
python -m guardian.cli scan-config .env
python -m guardian.cli scan-logs /var/log/auth.log
python -m guardian.cli scan-processes
python -m guardian.cli scan-file suspicious.bin

# Threat intelligence
python -m guardian.cli check-ioc 1.2.3.4
python -m guardian.cli update-feeds
python -m guardian.cli cross-verify --ioc "http://example.com/bad"
```

Run `python -m guardian.cli --help` for the full command list.

## Configuration

Settings are saved to `~/.guardian/settings.json` (editable from the dashboard's **Settings** tab) and can be overridden by environment variables. Copy `.env.example` to `.env` to set defaults. Useful variables:

| Variable | Purpose |
|----------|---------|
| `GUARDIAN_DATA_DIR` | Where Guardian stores its DB, vault, and keys (default `~/.guardian`) |
| `GUARDIAN_TLS_AUTO` | Enable self-signed HTTPS |
| `GUARDIAN_BREACH_PROVIDER` | Breach-lookup backend (`auto`, `mock`, …) |
| `GUARDIAN_INSECURE_SSL` | Allow insecure SSL for corporate proxies |
| `GUARDIAN_ALLOW_BLOCK_PRIVATE` | Permit active response to firewall-block private/RFC1918 IPs (off by default — prevents self-DoS) |

## Development

```bash
pip install -e ".[web]" pytest pyflakes httpx2   # httpx2 backs starlette's TestClient
pytest -q                 # run the test suite
pyflakes guardian/        # lint
```

CI runs the test suite on Python 3.10–3.12 for every push and pull request to `master`.

## Project layout

```
guardian/
  cli.py            # Click entry point (serve, defend, scan-*, check-ioc, …)
  engine/           # alert model, correlator, responder, ATT&CK mapping, SLM
  modules/          # log / file / process / network monitors + code scanner
  intel/            # TI feeds, breach lookup, cross-verification, ClamAV
  security/         # crypto, session auth, TLS, encrypted vault, keys
  web/              # FastAPI server, persistence, settings, rate limiting
tests/              # pytest suite
scripts/            # launchers, systemd unit, env/setup helpers
docs/               # handoff + deployment notes
```

## Docs

- [`docs/guardian-handoff.md`](docs/guardian-handoff.md) — project context and architecture
- [`docs/deployment-learniam.md`](docs/deployment-learniam.md) — domain, landing page, and VPS deployment

## Security & deployment posture

Guardian is designed **local-first** — a personal SOC dashboard bound to `127.0.0.1`.

- **Run it on loopback** (`--host 127.0.0.1`, the default) for single-machine use.
- **API auth** (E2E session handshake) is on by default but requires the `cryptography` package (installed via the `web`/`full` extras). If it is missing, the server warns loudly at startup that the API is unauthenticated.
- **Exposing the dashboard to a network or the internet is not recommended without a hardened front end.** Put it behind a reverse proxy that terminates TLS and enforces authentication (basic auth, mTLS, or SSO). The built-in session handshake provides end-to-end payload encryption, **not** access control — anyone who can reach a public dashboard can complete the handshake.
- **Active response is dry-run by default.** Live blocking/killing/quarantine is opt-in (`--respond-live`) and guarded against self-destructive targets (loopback/private IPs, init/own PID, symlinks and protected system paths).

See [`docs/deployment-learniam.md`](docs/deployment-learniam.md) for VPS notes.

## License

MIT — see [`LICENSE`](LICENSE).
