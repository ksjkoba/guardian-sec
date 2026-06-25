"""Simple in-memory rate limiting for VPS deployments."""

from __future__ import annotations

import os
import time
from collections import defaultdict
from threading import Lock

_lock = Lock()
_hits: dict[str, list[float]] = defaultdict(list)


def rate_limit_enabled() -> bool:
    if os.environ.get("GUARDIAN_RATE_LIMIT", "").lower() in ("0", "false", "no"):
        return False
    try:
        from guardian.web.deploy import deploy_mode
        return deploy_mode() == "vps"
    except ImportError:
        return False


def _limit_per_minute() -> int:
    try:
        return max(10, int(os.environ.get("GUARDIAN_RATE_LIMIT", "120")))
    except ValueError:
        return 120


def allow_request(client_ip: str) -> bool:
    if not rate_limit_enabled():
        return True
    if client_ip in ("127.0.0.1", "::1", "localhost"):
        return True
    now = time.time()
    window = 60.0
    cap = _limit_per_minute()
    with _lock:
        bucket = _hits[client_ip]
        _hits[client_ip] = [t for t in bucket if now - t < window]
        if len(_hits[client_ip]) >= cap:
            return False
        _hits[client_ip].append(now)
    return True
