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
import urllib.parse
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
    """Convert JWT raw ECDSA signature (r || s) to DER-encoded form.

    RFC 7518 §3.4: raw signature is r || s, each zero-padded to the key size.
    ES512 (P-521) produces a body > 127 bytes, requiring DER long-form length.
    """
    half = len(raw_sig) // 2
    r = int.from_bytes(raw_sig[:half], "big")
    s = int.from_bytes(raw_sig[half:], "big")

    def _encode_int(n: int) -> bytes:
        # max(1, ...) guards against n == 0 (theoretically invalid but prevents IndexError)
        b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return bytes([0x02, len(b)]) + b

    body = _encode_int(r) + _encode_int(s)
    body_len = len(body)
    # DER length: short form for < 128 bytes, long form (0x81 + 1 byte) otherwise.
    # P-521 body can reach ~138 bytes; we never exceed 255 so one extra byte suffices.
    if body_len < 128:
        length_enc = bytes([body_len])
    else:
        length_enc = bytes([0x81, body_len])
    return bytes([0x30]) + length_enc + body


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


def _parse_and_load_keys(data: dict) -> dict:
    """Parse a JWKS document dict and return {kid: public_key} for supported keys."""
    result: dict = {}
    for jwk in data.get("keys", []):
        kid = jwk.get("kid", "default")
        try:
            key = _load_key(jwk)
            if key is None:
                logger.warning("JWKS: skipping unsupported key kty=%s crv=%s kid=%s",
                               jwk.get("kty"), jwk.get("crv"), kid)
                continue
            result[kid] = key
            logger.info("JWKS: loaded key kid=%s kty=%s", kid, jwk.get("kty"))
        except Exception as e:
            logger.error("JWKS: failed to load key kid=%s: %s", kid, e)
    return result


def _fetch_jwks(jwks_uri: str) -> None:
    """Fetch full JWKS and replace key cache."""
    logger.info("Fetching JWKS from %s", jwks_uri)
    try:
        req = urllib.request.Request(jwks_uri, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        logger.error("JWKS fetch failed: %s", e)
        return

    new_cache = _parse_and_load_keys(data)

    global _cache_expires_at
    with _cache_lock:
        _cache.clear()
        _cache.update(new_cache)
        _cache_expires_at = time.monotonic() + _CACHE_TTL

    logger.info("JWKS cache updated (%d keys)", len(new_cache))


def _fetch_single_key(jwks_uri: str, kid: str) -> None:
    """Fetch a single key via ?kid=<kid> and merge it into the cache.

    VENDOR-SPECIFIC BEHAVIOUR: the ?kid= query parameter is NOT part of the
    OIDC/JWKS standard (RFC 7517).  It is supported by Encedo HSM and some
    custom OIDC providers, but most mainstream providers (Keycloak, Microsoft
    Entra ID, Google, Auth0, Okta) simply ignore it and return the full keyset.
    Either way the response is handled correctly — _parse_and_load_keys accepts
    any number of keys and merges them into the cache.

    If your OIDC provider returns HTTP 4xx on an unrecognised query parameter,
    comment out the 3 lines below marked [VENDOR-SPECIFIC] and uncomment the
    _fetch_jwks() fallback line to always fetch the full keyset instead.
    """
    # [VENDOR-SPECIFIC] build URL with ?kid= — comment out these 3 lines and
    # replace with: url = jwks_uri  to fall back to a full-keyset fetch.
    sep = "&" if "?" in jwks_uri else "?"
    url = f"{jwks_uri}{sep}kid={urllib.parse.quote(kid, safe='')}"
    # [VENDOR-SPECIFIC end]
    logger.info("Fetching single JWKS key kid=%r from %s", kid, url)
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        logger.error("JWKS single-key fetch failed (kid=%r): %s", kid, e)
        return

    loaded = _parse_and_load_keys(data)
    if not loaded:
        logger.warning("JWKS single-key response contained no usable keys (kid=%r)", kid)
        return

    with _cache_lock:
        _cache.update(loaded)

    logger.info("JWKS cache: merged %d key(s) from single-key fetch", len(loaded))


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
        # Unknown kid — OP may have rotated keys; fetch just this key and retry.
        logger.info("Unknown kid=%r — fetching single key from JWKS endpoint", kid)
        _fetch_single_key(jwks_uri, kid)
        with _cache_lock:
            keys = dict(_cache)
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
    _CLOCK_SKEW = 60  # seconds — tolerance for clock drift between parties
    now = time.time()
    exp = payload.get("exp")
    if exp is None or now > exp + _CLOCK_SKEW:
        raise ValueError(f"id_token expired (exp={exp}, now={int(now)})")

    nbf = payload.get("nbf")
    if nbf is not None and now < nbf - _CLOCK_SKEW:
        raise ValueError(f"id_token not yet valid (nbf={nbf}, now={int(now)})")

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
