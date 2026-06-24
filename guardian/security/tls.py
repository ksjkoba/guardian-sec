"""Optional local TLS certificate helpers."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def ensure_local_tls_cert() -> tuple[str, str] | None:
    """
    Return (cert_path, key_path) for local HTTPS.
    Uses GUARDIAN_TLS_CERT/KEY if set, or generates a self-signed cert in ~/.guardian/tls/
    when GUARDIAN_TLS_AUTO=1.
    """
    cert = os.environ.get("GUARDIAN_TLS_CERT", "").strip()
    key = os.environ.get("GUARDIAN_TLS_KEY", "").strip()
    if cert and key:
        return cert, key
    if os.environ.get("GUARDIAN_TLS_AUTO", "").lower() not in ("1", "true", "yes"):
        return None

    from guardian.security.vault import data_dir

    tls_dir = data_dir() / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert_path = tls_dir / "guardian-local.crt"
    key_path = tls_dir / "guardian-local.key"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path),
            "-out", str(cert_path),
            "-days", "825",
            "-nodes",
            "-subj", "/CN=Guardian Local/O=Guardian/C=US",
        ],
        check=True,
        capture_output=True,
    )
    try:
        cert_path.chmod(0o644)
        key_path.chmod(0o600)
    except OSError:
        pass
    return str(cert_path), str(key_path)
