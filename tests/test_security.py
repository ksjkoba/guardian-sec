"""Tests for Guardian AES-256-GCM and E2E session encryption."""

import os

import pytest

cryptography = pytest.importorskip("cryptography")

from guardian.security.crypto import decrypt_text, encrypt_text, has_crypto
from guardian.security.keys import get_master_key
from guardian.security.session import SessionManager


@pytest.fixture(autouse=True)
def _isolate_master_key(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("GUARDIAN_API_AUTH", "0")
    monkeypatch.setenv("GUARDIAN_ALLOW_PLAINTEXT", "1")
    monkeypatch.delenv("GUARDIAN_MASTER_KEY", raising=False)
    import guardian.security.keys as keys

    keys._master_key = None
    yield
    keys._master_key = None


def test_has_crypto():
    assert has_crypto() is True


def test_aes_roundtrip():
    key = get_master_key()
    assert len(key) == 32
    token = encrypt_text(key, "dana.porter1988@outlook.com", aad="watchlist:email:abc")
    plain = decrypt_text(key, token, aad="watchlist:email:abc")
    assert plain == "dana.porter1988@outlook.com"


def test_e2e_session_encrypt_decrypt():
    mgr = SessionManager()
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import base64

    client_private = x25519.X25519PrivateKey.generate()
    client_public_b64 = base64.urlsafe_b64encode(
        client_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii").rstrip("=")

    hs = mgr.handshake(client_public_b64)
    server_public = x25519.X25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(hs["server_public_key"] + "==")
    )
    shared = client_private.exchange(server_public)
    client_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"guardian-e2e-v1"
    ).derive(shared)

    payload = {"type": "email", "value": "test@example.com"}
    import json
    from guardian.security.crypto import encrypt_bytes

    session_id = hs["session_id"]
    token = hs["token"]
    plaintext = json.dumps(payload).encode("utf-8")
    blob = encrypt_bytes(client_key, plaintext, session_id.encode("utf-8"))
    body = {
        "encrypted": True,
        "session_id": session_id,
        "iv": base64.urlsafe_b64encode(blob[:12]).decode("ascii").rstrip("="),
        "data": base64.urlsafe_b64encode(blob[12:]).decode("ascii").rstrip("="),
    }
    out = mgr.decrypt_payload(body, token)
    assert out == payload


def test_watchlist_sealed_at_rest():
    from guardian.intel.breach_lookup import _watchlist_seal, _watchlist_unseal

    sealed = _watchlist_seal("secret@example.com", "email:deadbeef")
    assert sealed.startswith("enc:v1:")
    assert "secret@example.com" not in sealed
    assert _watchlist_unseal(sealed, "email:deadbeef") == "secret@example.com"


def test_password_range_invalid():
    from guardian.intel.breach_lookup import check_pwned_password_range

    r = check_pwned_password_range("BAD", "XYZ")
    assert r.status == "invalid"


def test_api_auth_token():
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import base64

    mgr = SessionManager()
    pub = base64.urlsafe_b64encode(
        x25519.X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode().rstrip("=")
    hs = mgr.handshake(pub)
    assert mgr.verify_token_any(hs["token"]) is True
    assert mgr.verify_token_any("wrong") is False
