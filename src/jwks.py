#!/usr/bin/env python3
"""
Carbonio OIDC Connector - JWKS fetch, cache, and id_token verification.
Supports EdDSA (Ed25519) only — as advertised by test.oidc.encedo.com.
"""

import base64
import json
import logging
import threading
import time
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

_cache: dict = {}          # kid -> Ed25519PublicKey
_cache_lock = threading.Lock()
_cache_expires_at: float = 0.0
_CACHE_TTL = 3600          # 1 hour


def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _fetch_jwks(jwks_uri: str) -> None:
    """Fetch JWKS and populate key cache."""
    logger.info("Fetching JWKS from %s", jwks_uri)
    try:
        req = urllib.request.Request(jwks_uri, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        logger.error("JWKS fetch failed: %s", e)
        return

    new_cache: dict = {}
    for jwk in data.get("keys", []):
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            logger.warning("JWKS: skipping unsupported key kty=%s crv=%s", jwk.get("kty"), jwk.get("crv"))
            continue
        kid = jwk.get("kid", "default")
        try:
            x_bytes = _b64url_decode(jwk["x"])
            public_key = Ed25519PublicKey.from_public_bytes(x_bytes)
            new_cache[kid] = public_key
            logger.info("JWKS: loaded key kid=%s", kid)
        except Exception as e:
            logger.error("JWKS: failed to load key kid=%s: %s", kid, e)

    global _cache_expires_at
    with _cache_lock:
        _cache.clear()
        _cache.update(new_cache)
        _cache_expires_at = time.monotonic() + _CACHE_TTL

    logger.info("JWKS cache updated (%d keys)", len(new_cache))


def prefetch(jwks_uri: str) -> None:
    """Fetch JWKS in a background thread."""
    t = threading.Thread(target=_fetch_jwks, args=(jwks_uri,), daemon=True, name="jwks-prefetch")
    t.start()


def _get_keys(jwks_uri: str) -> dict:
    """Return cached keys, refreshing if expired."""
    with _cache_lock:
        if _cache and time.monotonic() < _cache_expires_at:
            return dict(_cache)

    _fetch_jwks(jwks_uri)

    with _cache_lock:
        return dict(_cache)


def verify_id_token(id_token: str, jwks_uri: str, expected_issuer: str, client_id: str) -> dict:
    """
    Verify EdDSA id_token signature and standard claims.
    Returns decoded payload dict on success.
    Raises ValueError with a descriptive message on any failure.
    """
    parts = id_token.split(".")
    if len(parts) != 3:
        raise ValueError("id_token must have 3 parts")

    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception as e:
        raise ValueError(f"id_token decode error: {e}")

    alg = header.get("alg")
    if alg != "EdDSA":
        raise ValueError(f"Unsupported id_token alg: {alg!r} (expected EdDSA)")

    kid = header.get("kid", "default")
    keys = _get_keys(jwks_uri)
    if not keys:
        raise ValueError("JWKS unavailable — cannot verify id_token")

    public_key = keys.get(kid)
    if public_key is None:
        raise ValueError(f"No JWKS key for kid={kid!r}")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    try:
        sig_bytes = _b64url_decode(sig_b64)
        public_key.verify(sig_bytes, signing_input)
    except InvalidSignature:
        raise ValueError("id_token signature verification failed")

    # Validate claims
    now = time.time()
    exp = payload.get("exp")
    if exp is None or now > exp:
        raise ValueError(f"id_token expired (exp={exp}, now={int(now)})")

    iss = payload.get("iss")
    if iss != expected_issuer:
        raise ValueError(f"id_token issuer mismatch: got {iss!r}, expected {expected_issuer!r}")

    aud = payload.get("aud")
    if isinstance(aud, str):
        aud = [aud]
    if client_id not in aud:
        raise ValueError(f"id_token audience mismatch: {aud!r} does not contain {client_id!r}")

    logger.info("id_token verified OK (sub=%s)", payload.get("sub"))
    return payload
