"""
Guardian web server - FastAPI + WebSocket live dashboard.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from guardian.engine.alert import Alert, Severity
from guardian.engine.correlator import Campaign, CampaignStatus

try:
    from contextlib import asynccontextmanager
    from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, File, UploadFile
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    import uvicorn
    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False


class DashboardState:
    """Thread-safe store of alerts and campaigns for the web layer."""

    MAX_ALERTS = 500

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._alerts: list[dict] = []
        self._campaigns: list[dict] = []
        self._stats: dict[str, Any] = {
            "total_alerts": 0, "critical": 0, "high": 0, "medium": 0,
            "low": 0, "info": 0, "total_campaigns": 0, "ioc_hits": 0,
            "uptime_start": time.time(),
        }
        self._broadcast_queue: "asyncio.Queue | None" = None
        self._loop: "asyncio.AbstractEventLoop | None" = None
        self._load_persisted()

    def _load_persisted(self) -> None:
        try:
            from guardian.web.persistence import init_db, load_alerts, load_campaigns
            init_db()
            self._alerts = load_alerts(self.MAX_ALERTS)
            self._campaigns = load_campaigns()
            self._recompute_stats()
            if self._alerts or self._campaigns:
                print(
                    f"[dashboard] restored {len(self._alerts)} alert(s), "
                    f"{len(self._campaigns)} campaign(s) from disk"
                )
        except Exception as e:
            print(f"[dashboard] persistence load skipped: {e}")

    def _recompute_stats(self) -> None:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        ioc_hits = 0
        for a in self._alerts:
            sev = str(a.get("severity", "INFO")).lower()
            if sev in counts:
                counts[sev] += 1
            if a.get("ioc_matches"):
                ioc_hits += 1
        self._stats.update({
            "total_alerts": len(self._alerts),
            "total_campaigns": len(self._campaigns),
            "ioc_hits": ioc_hits,
            **counts,
            "uptime_start": time.time(),
        })

    def set_queue(self, q: "asyncio.Queue", loop: "asyncio.AbstractEventLoop") -> None:
        self._broadcast_queue = q
        self._loop = loop

    def ingest_alert(self, alert: Alert) -> None:
        d = alert.to_dict()
        d["ioc_tag"] = alert.metadata.get("ioc_tag", "")
        d["ioc_matches"] = alert.metadata.get("ioc_matches", [])
        d["severity_upgraded"] = alert.metadata.get("severity_upgraded", False)
        # Pass through fields for dashboard UI (sources, plain-English, links)
        d["metadata"] = alert.metadata
        d["global_source"] = alert.metadata.get("global_source", "")
        d["source_label"] = alert.metadata.get("source_label", "")
        d["source_homepage"] = alert.metadata.get("source_homepage", "")
        d["reference_url"] = alert.metadata.get("reference_url", "")
        d["plain_summary"] = alert.metadata.get("plain_summary", "")
        d["severity_plain"] = alert.metadata.get("severity_plain", "")
        d["recommendation_plain"] = alert.metadata.get("recommendation_plain", "")
        d["is_global_feed"] = alert.metadata.get("is_global_feed", False)
        d["verified"] = alert.metadata.get("verified", False)
        d["verified_at"] = alert.metadata.get("verified_at")
        d["verified_method"] = alert.metadata.get("verified_method", "")
        d["verified_detail"] = alert.metadata.get("verified_detail", "")
        d["verified_found"] = alert.metadata.get("verified_found", False)
        with self._lock:
            self._alerts.append(d)
            if len(self._alerts) > self.MAX_ALERTS:
                self._alerts = self._alerts[-self.MAX_ALERTS:]
            self._stats["total_alerts"] += 1
            sev_key = alert.severity.value.lower()
            self._stats[sev_key] = self._stats.get(sev_key, 0) + 1
            if alert.metadata.get("ioc_matches"):
                self._stats["ioc_hits"] += 1
        try:
            from guardian.web.persistence import save_alert
            save_alert(d)
        except Exception:
            pass
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
        try:
            from guardian.web.persistence import save_campaign
            save_campaign(d)
        except Exception:
            pass
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
        # Was a silent `return` before, which hid the live-feed bug. Now logs.
        if self._broadcast_queue is None or self._loop is None:
            print(f"[dashboard] WARN: _emit before queue wired; dropped {event.get('type')}")
            return
        if self._loop.is_closed():
            print(f"[dashboard] WARN: event loop closed; dropped {event.get('type')}")
            return
        try:
            self._loop.call_soon_threadsafe(self._broadcast_queue.put_nowait, event)
        except RuntimeError as e:
            print(f"[dashboard] WARN: could not enqueue {event.get('type')}: {e}")


state = DashboardState()


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


def create_app(dashboard_state: "DashboardState | None" = None) -> "FastAPI":
    if not _HAS_FASTAPI:
        raise ImportError(
            "FastAPI and uvicorn are required for the web dashboard.\\n"
            "Run: pip install fastapi uvicorn"
        )

    ds = dashboard_state or state
    manager = ConnectionManager()

    try:
        from guardian.security.session import SessionManager
        sessions = SessionManager()
    except ImportError:
        sessions = None  # type: ignore[assignment]
    # NOTE: the asyncio.Queue is intentionally NOT created here. Creating it at
    # factory-call time (main thread, no running loop) binds it to the wrong
    # loop when uvicorn runs in a background thread - the broadcaster then
    # awaits a queue nothing ever feeds. Create it inside lifespan instead.

    @asynccontextmanager
    async def lifespan(application: "FastAPI"):
        loop = asyncio.get_running_loop()
        broadcast_queue: "asyncio.Queue" = asyncio.Queue()
        ds.set_queue(broadcast_queue, loop)

        async def _loop() -> None:
            while True:
                try:
                    event = await asyncio.wait_for(broadcast_queue.get(), timeout=1.0)
                    await manager.broadcast(event)
                except asyncio.TimeoutError:
                    await manager.broadcast({
                        "type": "heartbeat",
                        "ts": time.time(),
                        "stats": ds.get_stats(),
                    })
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    print(f"[dashboard] broadcaster error: {e!r}")

        task = asyncio.create_task(_loop())
        try:
            from guardian.intel.breach_lookup import start_watchlist_scheduler
            start_watchlist_scheduler()
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            ds.set_queue(None, None)

    app = FastAPI(title="Guardian Dashboard", docs_url=None, redoc_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def guardian_security_layer(request: "Request", call_next):  # type: ignore[no-untyped-def]
        from guardian.security.auth import api_auth_enabled, public_api_paths, verify_request_token
        from guardian.web.ratelimit import allow_request

        path = request.url.path
        client = request.client.host if request.client else "unknown"
        if not allow_request(client):
            return JSONResponse({"error": "rate limit exceeded"}, status_code=429)
        if api_auth_enabled() and path.startswith("/api/") and path not in public_api_paths(client):
            token = request.headers.get("X-Guardian-Session", "")
            if sessions is None or not verify_request_token(sessions, token):
                return JSONResponse(
                    {"error": "authentication required — reload dashboard to establish secure session"},
                    status_code=401,
                )
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if os.environ.get("GUARDIAN_TLS_CERT") or os.environ.get("GUARDIAN_TLS_AUTO"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> "HTMLResponse":
        html_path = Path(__file__).parent / "static" / "index.html"
        if html_path.exists():
            return HTMLResponse(
                html_path.read_text(),
                headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                },
            )
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

    @app.get("/api/settings")
    async def get_settings() -> "JSONResponse":
        from guardian.web.settings import effective_settings
        return JSONResponse(effective_settings())

    @app.post("/api/settings")
    async def post_settings(body: dict) -> "JSONResponse":
        from guardian.web.settings import RESTART_HINT_KEYS, save_user_settings
        saved = save_user_settings(body or {})
        return JSONResponse({
            "ok": True,
            "settings": saved,
            "restart_recommended": any(k in (body or {}) for k in RESTART_HINT_KEYS),
        })

    @app.get("/api/export")
    async def export_dashboard() -> "JSONResponse":
        from guardian.web.persistence import export_snapshot
        return JSONResponse(export_snapshot(
            ds.get_alerts(limit=ds.MAX_ALERTS),
            ds.get_campaigns(),
            ds.get_stats(),
        ))

    @app.get("/api/security/status")
    async def security_status() -> "JSONResponse":
        try:
            from guardian.security.crypto import has_crypto
            from guardian.security.keys import key_file_path

            if sessions is None:
                return JSONResponse({"e2e_available": False, "at_rest": False})
            out = sessions.status()
            out["at_rest"] = has_crypto()
            out["master_key_path"] = str(key_file_path()) if has_crypto() else None
            out["tls_enabled"] = bool(os.environ.get("GUARDIAN_TLS_CERT") or os.environ.get("GUARDIAN_TLS_AUTO"))
            from guardian.security.auth import api_auth_enabled, require_e2e_default
            from guardian.web.deploy import deployment_info
            out["api_auth"] = api_auth_enabled()
            out["require_e2e"] = require_e2e_default()
            out["deployment"] = deployment_info()
            return JSONResponse(out)
        except Exception as e:
            return JSONResponse({"e2e_available": False, "error": str(e)})

    @app.post("/api/security/handshake")
    async def security_handshake(body: dict) -> "JSONResponse":
        if sessions is None:
            return JSONResponse(
                {"error": "E2E encryption unavailable — install cryptography", "e2e_available": False},
                status_code=503,
            )
        client_key = str(body.get("client_public_key", "")).strip()
        if not client_key:
            return JSONResponse({"error": "client_public_key required"}, status_code=400)
        try:
            return JSONResponse(sessions.handshake(client_key))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        except ImportError as e:
            return JSONResponse({"error": str(e), "e2e_available": False}, status_code=503)

    def _unwrap(body: dict, path: str, request: "Request") -> dict | "JSONResponse":
        if sessions is None:
            return body
        from guardian.security.payload import unwrap_sensitive_body

        token = request.headers.get("X-Guardian-Session", "")
        try:
            return unwrap_sensitive_body(body, path=path, token=token, sessions=sessions)
        except PermissionError as e:
            return JSONResponse({"error": str(e)}, status_code=401)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)

    @app.post("/api/test-alert")
    async def inject_test_alert(request: "Request", body: dict | None = None) -> "JSONResponse":
        """Inject a test alert into the live dashboard (localhost dev helper)."""
        from guardian.engine.alert import Alert, Severity
        from guardian.security.auth import test_alert_allowed

        client = request.client.host if request.client else ""
        if not test_alert_allowed(client):
            return JSONResponse(
                {"error": "test-alert disabled in production (VPS). Use GUARDIAN_ALLOW_TEST_ALERT=1 to override."},
                status_code=403,
            )

        payload = body or {}
        sev_name = str(payload.get("severity", "HIGH")).upper()
        try:
            severity = Severity[sev_name]
        except KeyError:
            return JSONResponse({"error": f"invalid severity: {sev_name}"}, status_code=400)

        alert = Alert(
            module=str(payload.get("module", "test")),
            title=str(payload.get("title", "Live feed test")),
            description=str(payload.get("description", "Injected via /api/test-alert")),
            severity=severity,
            metadata=payload.get("metadata") or {"verified": False, "verified_detail": "This is a test alert, not from a live feed."},
        )
        ds.ingest_alert(alert)
        try:
            from guardian.engine.correlator import get_correlator
            get_correlator().ingest(alert)
        except Exception:
            pass
        return JSONResponse({"ok": True, "id": alert.id, "title": alert.title})

    @app.post("/api/global-feed/push")
    async def global_feed_push(body: dict) -> "JSONResponse":
        """Accept threat reports from external systems (SIEM, honeypots, APIs)."""
        from guardian.intel.global_ticker import get_ticker, push_payload_to_alert

        ticker = get_ticker()
        if ticker is not None:
            alert = ticker.ingest_external(body)
        else:
            alert = push_payload_to_alert(body)
            ds.ingest_alert(alert)
        return JSONResponse({"ok": True, "id": alert.id, "title": alert.title})

    @app.get("/api/global-feed/status")
    async def global_feed_status() -> "JSONResponse":
        from guardian.intel.global_ticker import get_ticker

        ticker = get_ticker()
        if ticker is None:
            return JSONResponse({"running": False, "message": "Global ticker not started"})
        s = ticker.status
        return JSONResponse({
            "running": s.running,
            "last_poll": s.last_poll,
            "last_error": s.last_error,
            "total_ingested": s.total_ingested,
            "last_batch": s.last_batch,
            "sources_ok": s.sources_ok,
            "sources_failed": s.sources_failed,
        })

    @app.get("/api/global-feed/sources")
    async def global_feed_sources() -> "JSONResponse":
        from guardian.intel.global_ticker import SOURCE_REGISTRY
        return JSONResponse([
            {"id": k, **v} for k, v in SOURCE_REGISTRY.items()
        ])

    @app.get("/api/breach/scenarios")
    async def breach_scenarios() -> "JSONResponse":
        from guardian.intel.breach_lookup import list_scenarios, provider_info
        return JSONResponse({
            **provider_info(),
            "scenarios": list_scenarios(),
        })

    @app.post("/api/breach/check")
    async def breach_check(request: Request, body: dict) -> "JSONResponse":
        from guardian.intel.breach_lookup import check_breach

        unwrapped = _unwrap(body, "/api/breach/check", request)
        if isinstance(unwrapped, JSONResponse):
            return unwrapped
        body = unwrapped
        id_type = str(body.get("type", body.get("identifier_type", "email"))).lower()
        value = str(body.get("value", body.get("identifier", ""))).strip()
        if id_type not in ("email", "phone", "username"):
            return JSONResponse({"error": "type must be email, phone, or username"}, status_code=400)
        result = check_breach(id_type, value)  # type: ignore[arg-type]
        from guardian.intel.breach_lookup import quota_status
        return JSONResponse({**result.to_dict(), "quota": quota_status()})

    @app.get("/api/breach/watchlist")
    async def breach_watchlist_get() -> "JSONResponse":
        from guardian.intel.breach_lookup import watchlist_list
        return JSONResponse(watchlist_list())

    @app.post("/api/breach/watchlist")
    async def breach_watchlist_add(request: Request, body: dict) -> "JSONResponse":
        from guardian.intel.breach_lookup import watchlist_add

        unwrapped = _unwrap(body, "/api/breach/watchlist", request)
        if isinstance(unwrapped, JSONResponse):
            return unwrapped
        body = unwrapped
        id_type = str(body.get("type", "email")).lower()
        value = str(body.get("value", "")).strip()
        label = str(body.get("label", ""))
        if id_type not in ("email", "phone", "username"):
            return JSONResponse({"error": "invalid type"}, status_code=400)
        out = watchlist_add(id_type, value, label)  # type: ignore[arg-type]
        if "error" in out:
            return JSONResponse(out, status_code=400)
        return JSONResponse(out)

    @app.delete("/api/breach/watchlist/{entry_id}")
    async def breach_watchlist_remove(entry_id: str) -> "JSONResponse":
        from guardian.intel.breach_lookup import watchlist_remove

        out = watchlist_remove(entry_id)
        if "error" in out:
            return JSONResponse(out, status_code=404)
        return JSONResponse(out)

    @app.post("/api/breach/password-check")
    async def breach_password_check(request: Request, body: dict) -> "JSONResponse":
        """Legacy endpoint — prefer /api/breach/password-range (client-side SHA-1)."""
        from guardian.intel.breach_lookup import check_pwned_password

        unwrapped = _unwrap(body, "/api/breach/password-check", request)
        if isinstance(unwrapped, JSONResponse):
            return unwrapped
        body = unwrapped
        password = str(body.get("password", ""))
        result = check_pwned_password(password)
        return JSONResponse(result.to_dict())

    @app.post("/api/breach/password-range")
    async def breach_password_range(request: Request, body: dict) -> "JSONResponse":
        """Pwned Passwords k-anonymity — only SHA-1 prefix/suffix, never full password."""
        from guardian.intel.breach_lookup import check_pwned_password_range

        unwrapped = _unwrap(body, "/api/breach/password-range", request)
        if isinstance(unwrapped, JSONResponse):
            return unwrapped
        body = unwrapped
        prefix = str(body.get("prefix", ""))
        suffix = str(body.get("suffix", ""))
        result = check_pwned_password_range(prefix, suffix)
        return JSONResponse(result.to_dict())

    @app.post("/api/breach/watchlist/recheck")
    async def breach_watchlist_recheck() -> "JSONResponse":
        from guardian.intel.breach_lookup import watchlist_recheck_all

        return JSONResponse(watchlist_recheck_all())

    @app.get("/api/breach/alerts")
    async def breach_alerts() -> "JSONResponse":
        from guardian.intel.breach_lookup import watchlist_alerts

        return JSONResponse({"alerts": watchlist_alerts(unread_only=True)})

    @app.post("/api/breach/alerts/read")
    async def breach_alerts_read(body: dict | None = None) -> "JSONResponse":
        from guardian.intel.breach_lookup import watchlist_alerts_mark_read

        body = body or {}
        alert_id = body.get("alert_id")
        return JSONResponse(watchlist_alerts_mark_read(alert_id))

    @app.post("/api/verify-alert")
    async def verify_alert(body: dict) -> "JSONResponse":
        """Re-check an alert's IOC against the original live source feed."""
        from guardian.intel.verifier import verify_on_source, source_label

        alert_id = body.get("alert_id")
        ioc_value = body.get("ioc_value", "")
        ioc_type = body.get("ioc_type", "")
        source = body.get("source", body.get("global_source", ""))

        if alert_id and not ioc_value:
            with ds._lock:
                match = next((a for a in reversed(ds._alerts) if a.get("id") == alert_id), None)
            if not match:
                return JSONResponse({"error": "alert not found"}, status_code=404)
            meta = match.get("metadata") or {}
            ioc_value = match.get("evidence") or meta.get("ioc_value", "")
            ioc_type = meta.get("ioc_type", "")
            source = match.get("global_source") or meta.get("global_source", "")

        if not ioc_value:
            return JSONResponse({"error": "ioc_value or alert_id required"}, status_code=400)

        result = verify_on_source(ioc_value, ioc_type, source)
        result["source_label"] = source_label(source)

        if alert_id:
            updated: dict | None = None
            with ds._lock:
                for a in ds._alerts:
                    if a.get("id") == alert_id:
                        a["verified"] = result.get("verified", False)
                        a["verified_found"] = result.get("found", False)
                        a["verified_at"] = result.get("checked_at")
                        a["verified_detail"] = result.get("detail", "")
                        a["verified_method"] = result.get("method", "live_recheck")
                        if a.get("metadata") is not None:
                            a["metadata"].update({
                                "verified": a["verified"],
                                "verified_found": a["verified_found"],
                                "verified_at": a["verified_at"],
                                "verified_detail": a["verified_detail"],
                            })
                        updated = dict(a)
                        break
            if updated:
                try:
                    from guardian.web.persistence import save_alert
                    save_alert(updated)
                except Exception:
                    pass

        return JSONResponse(result)

    @app.post("/api/cross-verify")
    async def cross_verify_endpoint(body: dict | None = None) -> "JSONResponse":
        """
        5-stage cross-source verification (AbuseIPDB, abuse.ch, NVD, CISA KEV).
        Body: { "alert_id": "..." } | { "alerts": [...] } | { "all": true, "limit": 50 }
        """
        from guardian.intel.cross_verify import verify_alert_dict, verify_alerts

        payload = body or {}
        limit = int(payload.get("limit", 50))

        if payload.get("all"):
            with ds._lock:
                batch = list(reversed(ds._alerts))[:limit]
            report = verify_alerts(batch)
            return JSONResponse(report.to_dict())

        if "alerts" in payload:
            batch = payload["alerts"]
            report = verify_alerts(batch if isinstance(batch, list) else [batch])
            return JSONResponse(report.to_dict())

        alert_id = payload.get("alert_id")
        if alert_id:
            with ds._lock:
                match = next((a for a in reversed(ds._alerts) if a.get("id") == alert_id), None)
            if not match:
                return JSONResponse({"error": "alert not found"}, status_code=404)
            return JSONResponse(verify_alert_dict(match).to_dict())

        if payload.get("ioc_value"):
            synthetic = {
                "id": "manual",
                "evidence": payload.get("ioc_value"),
                "title": payload.get("title", "Manual IOC check"),
                "description": payload.get("description", ""),
                "metadata": {
                    "ioc_value": payload.get("ioc_value"),
                    "ioc_type": payload.get("ioc_type", ""),
                    "global_source": payload.get("source", "manual"),
                },
            }
            return JSONResponse(verify_alert_dict(synthetic).to_dict())

        return JSONResponse(
            {"error": "Provide alert_id, ioc_value, alerts[], or all:true"},
            status_code=400,
        )

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
            from guardian.intel.unified_scan import scan_ioc
            return JSONResponse(scan_ioc(value))
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.get("/api/scan/status")
    async def scan_status() -> "JSONResponse":
        from guardian.intel.clamav_scan import clamav_status
        return JSONResponse(clamav_status())

    @app.post("/api/scan/file")
    async def scan_file_upload(file: "UploadFile" = File(...)) -> "JSONResponse":
        from guardian.intel.clamav_scan import scan_file_bytes
        try:
            content = await file.read()
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        if not content:
            return JSONResponse({"error": "empty file"}, status_code=400)
        try:
            return JSONResponse(scan_file_bytes(content, file.filename or "upload"))
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @app.websocket("/ws")
    async def websocket_endpoint(ws: "WebSocket") -> None:
        from guardian.security.auth import api_auth_enabled, verify_request_token

        if api_auth_enabled() and sessions is not None:
            token = ws.query_params.get("token", "")
            if not verify_request_token(sessions, token):
                await ws.close(code=4401)
                return
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


def tls_enabled() -> bool:
    from guardian.web.deploy import tls_enabled as _tls
    return _tls()


def dashboard_base_url(host: str = "127.0.0.1", port: int = 8765) -> str:
    from guardian.web.deploy import dashboard_base_url as _url
    return _url(host, port)


def run_server(host: str = "127.0.0.1", port: int = 8765,
               dashboard_state: "DashboardState | None" = None) -> None:
    if not _HAS_FASTAPI:
        raise ImportError("pip install fastapi uvicorn")
    try:
        import websockets  # noqa: F401
    except ImportError:
        try:
            import wsproto  # noqa: F401
        except ImportError:
            print(
                "[dashboard] WARN: WebSocket library missing — live push disabled; "
                "dashboard will poll /api/alerts instead.\n"
                "[dashboard] Fix: pip install 'uvicorn[standard]'  or  pip install websockets"
            )
    app = create_app(dashboard_state)
    from guardian.security.tls import ensure_local_tls_cert

    tls = ensure_local_tls_cert()
    ssl_cert = (tls[0] if tls else None) or os.environ.get("GUARDIAN_TLS_CERT")
    ssl_key = (tls[1] if tls else None) or os.environ.get("GUARDIAN_TLS_KEY")
    if tls:
        print(f"[dashboard] TLS enabled — https://{host}:{port}/")
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="error",
        ssl_certfile=ssl_cert or None,
        ssl_keyfile=ssl_key or None,
    )


def _websocket_ready(host: str, port: int) -> bool:
    """Best-effort check that /ws accepts a WebSocket upgrade."""
    import http.client

    conn = http.client.HTTPConnection(host, port, timeout=1.5)
    try:
        conn.request(
            "GET",
            "/ws",
            headers={
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            },
        )
        resp = conn.getresponse()
        # 101 = upgraded; 400/426 = route exists but handshake incomplete
        return resp.status in (101, 400, 426)
    except (OSError, TimeoutError):
        return False
    finally:
        conn.close()


def wait_for_server_ready(host: str = "127.0.0.1", port: int = 8765,
                          timeout: float = 15.0) -> bool:
    """Return True once the HTTP(S) API responds on /api/stats."""
    import ssl
    import urllib.error
    import urllib.request

    scheme = "https" if tls_enabled() else "http"
    url = f"{scheme}://{host}:{port}/api/stats"
    ctx = None
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.5, context=ctx) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError, TimeoutError):
            pass
        time.sleep(0.3)
    return False


def run_server_background(host: str = "127.0.0.1", port: int = 8765,
                          dashboard_state: "DashboardState | None" = None) -> "threading.Thread":
    t = threading.Thread(
        target=run_server,
        kwargs={"host": host, "port": port, "dashboard_state": dashboard_state},
        daemon=True,
    )
    t.start()
    return t
