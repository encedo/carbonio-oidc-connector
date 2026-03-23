#!/usr/bin/env python3
"""
Carbonio OIDC Connector - JWKS fetch, cache, and id_token verification.

Supported algorithms:
  EdDSA (Ed25519)  — OKP / crv: Ed25519
  RS256, RS384, RS512 — RSA / PKCS1v15
  ES256, ES384, ES512 — EC / P-256, P-384, P-521
"""

import base64
import json
import logging
import threading
import time
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, EllipticCurvePublicNumbers, SECP256R1, SECP384R1, SECP521R1,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

logger = logging.getLogger(__name__)

_cache: dict = {}          # kid -> public key object
_cache_lock = threading.Lock()
_cache_expires_at: float = 0.0
_CACHE_TTL = 3600          # 1 hour

_RSA_ALGS = {
    "RS256": hashes.SHA256(),
    "RS384": hashes.SHA384(),
    "RS512": hashes.SHA512(),
}
_EC_ALGS = {
    "ES256": hashes.SHA256(),
    "ES384": hashes.SHA384(),
    "ES512": hashes.SHA512(),
}
_EC_CURVES = {
    "P-256": SECP256R1(),
    "P-384": SECP384R1(),
    "P-521": SECP521R1(),
}
SUPPORTED_ALGS = {"EdDSA"} | set(_RSA_ALGS) | set(_EC_ALGS)


def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _load_key(jwk: dict):
    """Parse a JWK dict and return a public key object, or None if unsupported."""
    kty = jwk.get("kty")

    if kty == "OKP" and jwk.get("crv") == "Ed25519":
        x_bytes = _b64url_decode(jwk["x"])
        return Ed25519PublicKey.from_public_bytes(x_bytes)

    if kty == "RSA":
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        return RSAPublicNumbers(e, n).public_key()

    if kty == "EC":
        crv = jwk.get("crv", "P-256")
        curve = _EC_CURVES.get(crv)
        if curve is None:
            raise ValueError(f"Unsupported EC curve: {crv!r}")
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        return EllipticCurvePublicNumbers(x=x, y=y, curve=curve).public_key()

    return None


def _raw_ecdsa_to_der(raw_sig: bytes) -> bytes:
    """Convert JWT raw ECDSA signature (r || s) to DER-encoded form."""
    half = len(raw_sig) // 2
    r = int.from_bytes(raw_sig[:half], "big")
    s = int.from_bytes(raw_sig[half:], "big")

    def _encode_int(n: int) -> bytes:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return bytes([0x02, len(b)]) + b

    body = _encode_int(r) + _encode_int(s)
    return bytes([0x30, len(body)]) + body


def _verify_sig(public_key, alg: str, sig_bytes: bytes, signing_input: bytes) -> None:
    """Verify signature. Raises InvalidSignature or ValueError on failure."""
    if alg == "EdDSA":
        public_key.verify(sig_bytes, signing_input)

    elif alg in _RSA_ALGS:
        public_key.verify(sig_bytes, signing_input, padding.PKCS1v15(), _RSA_ALGS[alg])

    elif alg in _EC_ALGS:
        der_sig = _raw_ecdsa_to_der(sig_bytes)
        public_key.verify(der_sig, signing_input, ECDSA(_EC_ALGS[alg]))

    else:
        raise ValueError(f"Unsupported algorithm: {alg!r}")


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
        kid = jwk.get("kid", "default")
        try:
            key = _load_key(jwk)
            if key is None:
                logger.warning("JWKS: skipping unsupported key kty=%s crv=%s kid=%s",
                               jwk.get("kty"), jwk.get("crv"), kid)
                continue
            new_cache[kid] = key
            logger.info("JWKS: loaded key kid=%s kty=%s", kid, jwk.get("kty"))
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
    Verify id_token signature and standard claims.
    Supports EdDSA, RS256/384/512, ES256/384/512.
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
    if alg not in SUPPORTED_ALGS:
        raise ValueError(f"Unsupported id_token alg: {alg!r} (supported: {', '.join(sorted(SUPPORTED_ALGS))})")

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
        _verify_sig(public_key, alg, sig_bytes, signing_input)
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

    logger.info("id_token verified OK (sub=%s alg=%s)", payload.get("sub"), alg)
    return payload
