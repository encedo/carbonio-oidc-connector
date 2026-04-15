#!/usr/bin/env python3
"""
Carbonio OIDC Connector - /oidc/callback handler.
Completes the Authorization Code + PKCE flow and issues Zimbra PreAuth redirect.
"""

import html
import http.server
import json
import logging
import urllib.parse
import urllib.request
import urllib.error

import config as cfg
import session
import jwks
import preauth

logger = logging.getLogger(__name__)


def handle_callback(handler: http.server.BaseHTTPRequestHandler, app_config: dict) -> None:
    """GET /oidc/callback?code=...&state=..."""

    parsed = urllib.parse.urlparse(handler.path)
    qs = urllib.parse.parse_qs(parsed.query)

    # --- 1. Load session ---
    cookie_value = handler.headers.get("Cookie", "")
    session_id = session.parse_cookie(cookie_value)
    if not session_id:
        return _error(handler, 400, "Missing session cookie.")

    sess = session.get(session_id)
    if not sess:
        return _error(handler, 400, "Session expired or invalid. Please start login again.")

    # --- 2. Check for error from OP ---
    if "error" in qs:
        err = qs["error"][0]
        desc = qs.get("error_description", [""])[0]
        session.delete(session_id)
        return _error(handler, 400, f"OIDC Provider error: {err} — {desc}")

    # --- 3. Verify state (CSRF) ---
    returned_state = qs.get("state", [None])[0]
    if not returned_state or returned_state != sess.get("state"):
        session.delete(session_id)
        return _error(handler, 400, "State mismatch — possible CSRF attack.")

    code = qs.get("code", [None])[0]
    if not code:
        session.delete(session_id)
        return _error(handler, 400, "Missing authorization code.")

    # --- 4. Exchange code for tokens ---
    discovery = cfg.get_discovery(app_config)
    if not discovery:
        return _error(handler, 502, "OIDC discovery unavailable.")

    token_endpoint = discovery.get("token_endpoint")
    if not token_endpoint:
        return _error(handler, 502, "OIDC discovery missing token_endpoint.")

    token_data = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": app_config["oidc_redirect_uri"],
        "client_id": app_config["oidc_client_id"],
        "client_secret": app_config.get("oidc_client_secret", ""),
        "code_verifier": sess["code_verifier"],
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            token_endpoint,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            token_response = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        logger.error("Token endpoint HTTP error %s: %s", e.code, body)
        return _error(handler, 502, f"Token exchange failed (HTTP {e.code}).")
    except Exception as e:
        logger.error("Token endpoint error: %s", e)
        return _error(handler, 502, "Token exchange failed.")

    id_token = token_response.get("id_token")
    if not id_token:
        logger.error("Token response missing id_token: %s", token_response)
        return _error(handler, 502, "Token response missing id_token.")

    # --- 5. Verify id_token ---
    jwks_uri = discovery.get("jwks_uri")
    issuer = discovery.get("issuer")
    try:
        claims = jwks.verify_id_token(
            id_token,
            jwks_uri=jwks_uri,
            expected_issuer=issuer,
            client_id=app_config["oidc_client_id"],
        )
    except ValueError as e:
        logger.error("id_token verification failed: %s", e)
        session.delete(session_id)
        return _error(handler, 403, f"Token verification failed: {e}")

    # --- 6. Extract account (email) ---
    claim_field = app_config.get("account_claim", "email")
    fallback_field = app_config.get("account_claim_fallback", "preferred_username")
    account = claims.get(claim_field) or claims.get(fallback_field)
    if not account:
        session.delete(session_id)
        return _error(handler, 400, f"id_token missing claim '{claim_field}' (and fallback '{fallback_field}').")

    # --- 7. Domain lookup ---
    if "@" not in account:
        session.delete(session_id)
        return _error(handler, 400, f"Account '{account}' is not an email address — cannot determine domain.")

    domain = account.split("@")[1]
    domain_config = app_config.get("domains", {}).get(domain)
    if not domain_config:
        session.delete(session_id)
        return _error(handler, 403, f"Domain '{domain}' is not configured in OIDC connector.")

    preauth_key = domain_config.get("preauth_key")
    if not preauth_key:
        session.delete(session_id)
        return _error(handler, 500, f"preauth_key missing for domain '{domain}'.")

    # --- 8. Build PreAuth URL and redirect ---
    session.delete(session_id)

    redirect_url = preauth.preauth_redirect_url(
        base_url=app_config["carbonio_base_url"],
        account=account,
        key=preauth_key,
        login_redirect=app_config.get("login_redirect", "/carbonio/"),
    )

    logger.info("callback: redirecting account=%s to Carbonio PreAuth", account)

    handler.send_response(302)
    handler.send_header("Location", redirect_url)
    handler.send_header("Cache-Control", "no-store")
    # Clear session cookie
    handler.send_header(
        "Set-Cookie",
        f"{session.COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/oidc/; Max-Age=0",
    )
    handler.end_headers()


def _error(handler: http.server.BaseHTTPRequestHandler, code: int, message: str) -> None:
    logger.error("callback error %s: %s", code, message)
    safe_message = html.escape(message)
    body = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>OIDC Error</title></head><body>"
        f"<h2>OIDC Login Error</h2>"
        f"<p>{safe_message}</p>"
        f'<p><a href="/login/">Back to login</a></p>'
        "</body></html>"
    ).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
