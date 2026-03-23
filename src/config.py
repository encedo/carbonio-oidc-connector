#!/usr/bin/env python3
"""
Carbonio OIDC Connector - Configuration loader and OIDC discovery.
"""

import json
import logging
import os
import sys
import threading
import urllib.request
import urllib.error


logger = logging.getLogger(__name__)

CONFIG_PATH = os.environ.get("OIDC_CONFIG", "/opt/zextras/oidc/config.json")

REQUIRED_FIELDS = [
    "port",
    "host",
    "carbonio_base_url",
    "oidc_discovery_url",
    "oidc_client_id",
    "oidc_client_secret",
    "oidc_redirect_uri",
    "domains",
]

# Discovery cache — populated in background after startup
_discovery = {}
_discovery_lock = threading.Lock()


def load_config() -> dict:
    """Load and validate config.json. Exits on missing file or required fields."""
    logger.info("Loading config from %s", CONFIG_PATH)
    try:
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        logger.error("Config file not found: %s", CONFIG_PATH)
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error("Config JSON parse error: %s", e)
        sys.exit(1)

    missing = [f for f in REQUIRED_FIELDS if f not in config]
    if missing:
        logger.error("Missing required config fields: %s", ", ".join(missing))
        sys.exit(1)

    logger.info("Config loaded OK (host=%s port=%s)", config["host"], config["port"])
    return config


def _fetch_discovery(url: str) -> None:
    """Fetch OIDC discovery document and populate cache. Called from background thread."""
    logger.info("Fetching OIDC discovery from %s", url)
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        logger.warning("OIDC discovery fetch failed: %s", e)
        return

    required_keys = ["authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"]
    missing = [k for k in required_keys if k not in data]
    if missing:
        logger.warning("Discovery document missing keys: %s", ", ".join(missing))
        return

    with _discovery_lock:
        _discovery.update(data)

    logger.info("OIDC discovery OK: issuer=%s", data.get("issuer"))

    # Prefetch JWKS keys in background now that we know jwks_uri
    jwks_uri = data.get("jwks_uri")
    if jwks_uri:
        import jwks as jwks_module
        jwks_module.prefetch(jwks_uri)


def start_discovery_background(config: dict) -> None:
    """Kick off discovery fetch in a background thread (non-blocking)."""
    t = threading.Thread(
        target=_fetch_discovery,
        args=(config["oidc_discovery_url"],),
        daemon=True,
        name="oidc-discovery",
    )
    t.start()


def get_discovery(config: dict) -> dict:
    """
    Return cached discovery document.
    If cache is empty, attempt a synchronous fetch (retry path for /authorize).
    Returns empty dict if discovery is unavailable.
    """
    with _discovery_lock:
        if _discovery:
            return dict(_discovery)

    # Synchronous retry
    logger.info("Discovery cache empty — retrying synchronously")
    _fetch_discovery(config["oidc_discovery_url"])

    with _discovery_lock:
        return dict(_discovery)
