# Guardian / Sec

Local cybersecurity dashboard — complete implementation lives in this folder.

## Location

| Environment | Path |
|-------------|------|
| WSL / Linux | `/home/jhak/Guardian/Sec` |
| Short form | `~/Guardian/Sec` |
| Windows (File Explorer) | `\\wsl$\Ubuntu\home\jhak\Guardian\Sec` |

## Quick start

```bash
cd ~/Guardian/Sec
source .venv/bin/activate
./scripts/open-guardian.sh
```

Dashboard: http://127.0.0.1:8765

## Docs

- `docs/guardian-handoff.md` — project context and architecture
- `docs/deployment-learniam.md` — domain, landing page, and VPS deployment
- `website/learniam/index.html` — public marketing page for `learniam.online`

## Features

- **Settings tab** — configure provider, deploy mode, TLS (saved to `~/.guardian/settings.json`)
- **Persistence** — alerts and campaigns survive restarts (`~/.guardian/dashboard.db`)
- **Export** — download dashboard JSON from Settings

## Entry point

```bash
python -m guardian.cli serve
```
