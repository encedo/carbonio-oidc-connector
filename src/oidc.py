#!/usr/bin/env python3
"""
Carbonio OIDC Connector - /oidc/authorize handler.
Initiates OIDC Authorization Code flow with PKCE S256.
"""

import base64
import hashlib
import html
import http.server
import logging
import secrets
import urllib.parse

import config as cfg
import session

logger = logging.getLogger(__name__)


def handle_authorize(handler: http.server.BaseHTTPRequestHandler, app_config: dict) -> None:
    """
    GET /oidc/authorize
    Generates PKCE challenge, stores state in session, redirects to OP.
    """
    discovery = cfg.get_discovery(app_config)
    if not discovery:
        _error(handler, 502, "OIDC Provider discovery unavailable. Try again later.")
        return

    authorization_endpoint = discovery.get("authorization_endpoint")
    if not authorization_endpoint:
        _error(handler, 502, "OIDC discovery missing authorization_endpoint.")
        return

    # Parse optional ?domain= hint from query string
    parsed = urllib.parse.urlparse(handler.path)
    qs = urllib.parse.parse_qs(parsed.query)
    domain_hint = qs.get("domain", [None])[0]

    # PKCE S256
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    state = secrets.token_urlsafe(32)

    # Store in session
    session_data = {
        "state": state,
        "code_verifier": code_verifier,
    }
    if domain_hint:
        session_data["domain_hint"] = domain_hint

    session_id = session.create(session_data)

    # Build authorization URL
    scopes = " ".join(app_config.get("oidc_scopes", ["openid", "email", "profile"]))
    params = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": app_config["oidc_client_id"],
        "redirect_uri": app_config["oidc_redirect_uri"],
        "scope": scopes,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    })
    redirect_url = f"{authorization_endpoint}?{params}"

    logger.info("authorize: redirecting to OP (state=%s...)", state[:8])

    # Set session cookie and redirect
    handler.send_response(302)
    handler.send_header("Location", redirect_url)
    handler.send_header("Set-Cookie", session.cookie_header(session_id))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()


def _error(handler: http.server.BaseHTTPRequestHandler, code: int, message: str) -> None:
    logger.error("authorize error %s: %s", code, message)
    safe_message = html.escape(message)
    body = (
        f"<!DOCTYPE html><html><body>"
        f"<h2>OIDC Error</h2><p>{safe_message}</p>"
        f'<p><a href="/login/">Back to login</a></p>'
        f"</body></html>"
    ).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
