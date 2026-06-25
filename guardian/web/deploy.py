"""Deployment profile — local PC vs VPS (public subdomain)."""

from __future__ import annotations

import os


def deploy_mode() -> str:
    """local (default) or vps."""
    mode = os.environ.get("GUARDIAN_DEPLOY_MODE", "local").lower().strip()
    return mode if mode in ("local", "vps") else "local"


def public_host() -> str | None:
    host = os.environ.get("GUARDIAN_PUBLIC_HOST", "").strip()
    return host or None


def public_port() -> int | None:
    raw = os.environ.get("GUARDIAN_PUBLIC_PORT", "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def tls_enabled() -> bool:
    if os.environ.get("GUARDIAN_TLS_CERT", "").strip():
        return True
    return os.environ.get("GUARDIAN_TLS_AUTO", "").lower() in ("1", "true", "yes")


def default_bind_host() -> str:
    explicit = os.environ.get("GUARDIAN_BIND_HOST", "").strip()
    if explicit:
        return explicit
    return "0.0.0.0" if deploy_mode() == "vps" else "127.0.0.1"


def dashboard_base_url(bind_host: str = "127.0.0.1", bind_port: int = 8765) -> str:
    """
    Public URL shown to users and used for readiness checks on VPS.
    Local: http(s)://127.0.0.1:8765/
    VPS:   https://guardian.learniam.online/ (when GUARDIAN_PUBLIC_HOST is set)
    """
    explicit = os.environ.get("GUARDIAN_PUBLIC_URL", "").strip().rstrip("/")
    if explicit:
        return f"{explicit}/"

    if deploy_mode() == "vps":
        host = public_host()
        if host:
            scheme = "https" if tls_enabled() else "http"
            port = public_port()
            if port is None:
                port = 443 if scheme == "https" else 80
            if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
                return f"{scheme}://{host}/"
            return f"{scheme}://{host}:{port}/"

    scheme = "https" if tls_enabled() else "http"
    return f"{scheme}://{bind_host}:{bind_port}/"


def deployment_info(bind_host: str = "127.0.0.1", bind_port: int = 8765) -> dict[str, object]:
    return {
        "mode": deploy_mode(),
        "public_host": public_host(),
        "public_url": dashboard_base_url(bind_host, bind_port),
        "bind_host": bind_host,
        "bind_port": bind_port,
        "tls_enabled": tls_enabled(),
    }
