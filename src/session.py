#!/usr/bin/env python3
"""
Carbonio OIDC Connector - In-memory session store.
"""

import logging
import secrets
import threading
import time

logger = logging.getLogger(__name__)

COOKIE_NAME = "__oidc_session"

_store: dict = {}
_lock = threading.Lock()
_ttl = 300  # default, overridden by init()


def init(ttl_seconds: int) -> None:
    """Set TTL and start background cleanup thread."""
    global _ttl
    _ttl = ttl_seconds
    t = threading.Thread(target=_cleanup_loop, daemon=True, name="session-cleanup")
    t.start()
    logger.info("Session store initialized (TTL=%ss)", ttl_seconds)


def create(data: dict) -> str:
    """Create a new session with given data. Returns session_id."""
    session_id = secrets.token_urlsafe(32)
    expires_at = time.monotonic() + _ttl
    with _lock:
        _store[session_id] = {"data": dict(data), "expires_at": expires_at}
    return session_id


def get(session_id: str) -> dict | None:
    """Return session data or None if missing/expired."""
    with _lock:
        entry = _store.get(session_id)
        if entry is None:
            return None
        if time.monotonic() > entry["expires_at"]:
            del _store[session_id]
            return None
        return dict(entry["data"])


def delete(session_id: str) -> None:
    """Delete session."""
    with _lock:
        _store.pop(session_id, None)


def cookie_header(session_id: str) -> str:
    """Return Set-Cookie header value."""
    return (
        f"{COOKIE_NAME}={session_id}; "
        "HttpOnly; Secure; SameSite=Lax; Path=/oidc/"
    )


def parse_cookie(cookie_header_value: str) -> str | None:
    """Extract session_id from Cookie header value. Returns None if not found."""
    if not cookie_header_value:
        return None
    for part in cookie_header_value.split(";"):
        part = part.strip()
        if part.startswith(COOKIE_NAME + "="):
            return part[len(COOKIE_NAME) + 1:]
    return None


def _cleanup_loop() -> None:
    while True:
        time.sleep(60)
        now = time.monotonic()
        with _lock:
            expired = [k for k, v in _store.items() if now > v["expires_at"]]
            for k in expired:
                del _store[k]
        if expired:
            logger.debug("Session cleanup: removed %d expired sessions", len(expired))
