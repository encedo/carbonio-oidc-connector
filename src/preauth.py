#!/usr/bin/env python3
"""
Carbonio OIDC Connector - Zimbra PreAuth token generator.

Carbonio CE uses HmacSHA1 (not SHA256!) with pipe | separator and fields
sorted alphabetically by key name:
    account|by|expires|timestamp
Source: PreAuthKey.java in carbonio-mailbox (github.com/zextras/carbonio-mailbox)

NOTE: timestamp in milliseconds (not seconds).
"""

import hashlib
import hmac
import logging
import time
import urllib.parse

logger = logging.getLogger(__name__)


def generate_preauth(key: str, account: str, timestamp: int, expires: int = 0) -> str:
    """
    Generate Carbonio PreAuth HmacSHA1 token.

    Args:
        key:       zimbraPreAuthKey for the domain (hex string)
        account:   email address
        timestamp: current time in MILLISECONDS
        expires:   token expiry offset (0 = no expiry)

    Returns:
        hex digest string
    """
    # Fields sorted alphabetically by key name: account, by, expires, timestamp
    # Separator: pipe |, algorithm: HmacSHA1
    msg = f"{account}|name|{expires}|{timestamp}"
    token = hmac.new(
        key.encode("utf-8"),
        msg.encode("utf-8"),
        hashlib.sha1,
    ).hexdigest()
    return token


def preauth_redirect_url(base_url: str, account: str, key: str, login_redirect: str = "/carbonio/") -> str:
    """
    Build full Carbonio PreAuth redirect URL.
    Carbonio authenticates the user and redirects to login_redirect.
    """
    ts = int(time.time() * 1000)   # milliseconds
    expires = 0
    token = generate_preauth(key, account, ts, expires)

    params = urllib.parse.urlencode({
        "account": account,
        "by": "name",
        "timestamp": ts,
        "expires": expires,
        "preauth": token,
    })
    url = f"{base_url}/service/preauth?{params}"
    logger.info("preauth URL built for account=%s ts=%d", account, ts)
    return url
