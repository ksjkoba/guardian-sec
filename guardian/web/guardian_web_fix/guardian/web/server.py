"""
Guardian web server — FastAPI + WebSocket live dashboard.

Exposes:
  GET  /                       → dashboard HTML
  GET  /api/alerts             → recent alerts (JSON)
  GET  /api/campaigns          → active campaigns (JSON)
  GET  /api/stats              → summary counts
  GET  /api/feeds              → TI feed status
  POST /api/ioc/check          → IOC lookup
  WS   /ws                     → real-time event stream
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path
from typing import Any

from guardian.engine.alert import Alert, Severity
from guardian.engine.correlator import Campaign, CampaignStatus

try:
    from contextlib import asynccontextmanager
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    import uvicorn
    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False


# ─── In-process state (shared with the rest of Guardian) ─────────────────────

class DashboardState:
    """Thread-safe store of alerts and campaigns for the web layer."""

    MAX_ALERTS = 500

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._alerts: list[dict] = []
        self._campaigns: list[dict] = []
        self._stats: dict[str, Any] = {
            "total_alerts": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total_campaigns": 0,
            "ioc_hits": 0,
            "uptime_start": time.time(),
        }
        self._broadcast_queue: "asyncio.Queue | None" = None
        self._loop: "asyncio.AbstractEventLoop | None" = None

    def set_queue(self, q: "asyncio.Queue", loop: "asyncio.AbstractEventLoop") -> None:
        self._broadcast_queue = q
        self._loop = loop

    def ingest_alert(self, alert: Alert) -> None:
        d = alert.to_dict()
        d["ioc_tag"] = alert.metadata.get("ioc_tag", "")
        d["ioc_matches"] = alert.metadata.get("ioc_matches", [])
        d["severity_upgraded"] = alert.metadata.get("severity_upgraded", False)

        with self._lock:
            self._alerts.append(d)
            if len(self._alerts) > self.MAX_ALERTS:
                self._alerts = self._alerts[-self.MAX_ALERTS:]
            self._stats["total_alerts"] += 1
            sev_key = alert.severity.value.lower()
            self._stats[sev_key] = self._stats.get(sev_key, 0) + 1
            if alert.metadata.get("ioc_matches"):
                self._stats["ioc_hits"] += 1

        self._emit({"type": "alert", "data": d})

    def ingest_campaign(self, campaign: Campaign) -> None:
        d = campaign.to_dict()
        with self._lock:
            existing = next((i for i, c in enumerate(self._campaigns) if c["id"] == d["id"]), None)
            if existing is not None:
                self._campaigns[existing] = d
            else:
                self._campaigns.append(d)
                self._stats["total_campaigns"] += 1

        self._emit({"type": "campaign", "data": d})

    def get_alerts(self, limit: int = 100, severity: "str | None" = None) -> list[dict]:
        with self._lock:
            alerts = list(reversed(self._alerts))
        if severity:
            alerts = [a for a in alerts if a["severity"] == severity.upper()]
        return alerts[:limit]

    def get_campaigns(self) -> list[dict]:
        with self._lock:
            return sorted(self._campaigns, key=lambda c: c["last_seen"], reverse=True)

    def get_stats(self) -> dict:
        with self._lock:
            s = dict(self._stats)
        s["uptime_secs"] = int(time.time() - s["uptime_start"])
        return s

    def _emit(self, event: dict) -> None:
        # If the web layer has not wired a queue/loop yet, log and drop loudly
        # (was a silent `return` before — which hid the live-feed bug).
        if self._broadcast_queue is None or self._loop is None:
            print(f"[dashboard] WARN: _emit before queue wired; dropped {event.get('type')}")
            return
        if self._loop.is_closed():
            print(f"[dashboard] WARN: event loop closed; dropped {event.get('type')}")
            return
        try:
            self._loop.call_soon_threadsafe(self._broadcast_queue.put_nowait, event)
        except RuntimeError as e:
            # loop not running / wrong loop — surface it instead of hiding
            print(f"[dashboard] WARN: could not enqueue {event.get('type')}: {e}")


# Global singleton
state = DashboardState()


# ─── WebSocket connection manager ─────────────────────────────────────────────

class ConnectionManager:
    def __init__(self) -> None:
        self._clients: "list[WebSocket]" = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: "WebSocket") -> None:
        await ws.accept()
        async with self._lock:
            self._clients.append(ws)

    async def disconnect(self, ws: "WebSocket") -> None:
        async with self._lock:
            try:
                self._clients.remove(ws)
            except ValueError:
                pass

    async def broadcast(self, message: dict) -> None:
        text = json.dumps(message)
        dead: "list[WebSocket]" = []
        async with self._lock:
            clients = list(self._clients)
        for ws in clients:
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)


# ─── FastAPI app factory ──────────────────────────────────────────────────────

def create_app(dashboard_state: "DashboardState | None" = None) -> "FastAPI":
    if not _HAS_FASTAPI:
        raise ImportError(
            "FastAPI and uvicorn are required for the web dashboard.\n"
            "Run: pip install fastapi uvicorn"
        )

    ds = dashboard_state or state
    manager = ConnectionManager()
    # NOTE: the asyncio.Queue is intentionally NOT created here. Creating it at
    # factory-call time (main thread, no running loop) binds it to the wrong
    # loop when uvicorn runs in a background thread — the broadcaster then
    # awaits a queue nothing ever feeds. Create it inside lifespan instead.

    @asynccontextmanager
    async def lifespan(application: "FastAPI"):
        # Create the queue and capture the loop INSIDE the running server loop,
        # so cross-thread `call_soon_threadsafe` targets the correct loop.
        loop = asyncio.get_running_loop()
        broadcast_queue: "asyncio.Queue" = asyncio.Queue()
        ds.set_queue(broadcast_queue, loop)

        async def _loop() -> None:
            while True:
                try:
                    event = await asyncio.wait_for(broadcast_queue.get(), timeout=1.0)
                    await manager.broadcast(event)
                except asyncio.TimeoutError:
                    # Heartbeat + live stats so UPTIME advances and the client
                    # knows the link is alive even when no alerts are flowing.
                    await manager.broadcast({
                        "type": "heartbeat",
                        "ts": time.time(),
                        "stats": ds.get_stats(),
                    })
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    # Was `pass` — that hid broadcaster failures forever.
                    print(f"[dashboard] broadcaster error: {e!r}")

        task = asyncio.create_task(_loop())
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    app = FastAPI(title="Guardian Dashboard", docs_url=None, redoc_url=None, lifespan=lifespan)

    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> "HTMLResponse":
        html_path = Path(__file__).parent / "static" / "index.html"
        if html_path.exists():
            return HTMLResponse(html_path.read_text())
        return HTMLResponse("<h1>Guardian</h1><p>Dashboard not found.</p>")

    @app.get("/api/alerts")
    async def get_alerts(limit: int = 100, severity: "str | None" = None) -> "JSONResponse":
        return JSONResponse(ds.get_alerts(limit=limit, severity=severity))

    @app.get("/api/campaigns")
    async def get_campaigns() -> "JSONResponse":
        return JSONResponse(ds.get_campaigns())

    @app.get("/api/stats")
    async def get_stats() -> "JSONResponse":
        return JSONResponse(ds.get_stats())

    @app.get("/api/feeds")
    async def get_feeds() -> "JSONResponse":
        try:
            from guardian.intel.feeds import feed_status
            return JSONResponse(feed_status())
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.post("/api/ioc/check")
    async def check_ioc(body: dict) -> "JSONResponse":
        value = body.get("value", "").strip()
        if not value:
            return JSONResponse({"error": "value required"}, status_code=400)
        try:
            from guardian.intel.feeds import get_index
            from guardian.intel.heuristics import check_value
            index = get_index()
            matches = index.lookup(value)
            suspicious = check_value(value)
            return JSONResponse({
                "value": value,
                "malicious": len(matches) > 0,
                "suspicious": suspicious is not None,
                "verdict": "MALICIOUS" if matches else ("SUSPICIOUS" if suspicious else "CLEAN"),
                "matches": [
                    {
                        "feed": m.feed,
                        "ioc_type": m.ioc_type,
                        "malware_family": m.malware_family,
                        "confidence": m.confidence,
                    }
                    for m in matches
                ],
                "suspicious_platform": {
                    "category": suspicious.category,
                    "reason": suspicious.reason,
                    "confidence": suspicious.confidence,
                    "example_abuse": suspicious.example_abuse,
                } if suspicious else None,
                "total_iocs_checked": index.total_iocs,
            })
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.websocket("/ws")
    async def websocket_endpoint(ws: "WebSocket") -> None:
        await manager.connect(ws)
        await ws.send_text(json.dumps({
            "type": "snapshot",
            "alerts": ds.get_alerts(limit=50),
            "campaigns": ds.get_campaigns(),
            "stats": ds.get_stats(),
        }))
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            await manager.disconnect(ws)

    return app


def run_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    dashboard_state: "DashboardState | None" = None,
) -> None:
    """Run the Guardian web server (blocking). Call from a thread."""
    if not _HAS_FASTAPI:
        raise ImportError("pip install fastapi uvicorn")

    app = create_app(dashboard_state)
    uvicorn.run(app, host=host, port=port, log_level="error")


def run_server_background(
    host: str = "127.0.0.1",
    port: int = 8765,
    dashboard_state: "DashboardState | None" = None,
) -> "threading.Thread":
    """Start the web server in a daemon thread. Returns the thread."""
    t = threading.Thread(
        target=run_server,
        kwargs={"host": host, "port": port, "dashboard_state": dashboard_state},
        daemon=True,
    )
    t.start()
    return t
