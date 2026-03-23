# carbonio-oidc-connector

OIDC Relying Party sidecar for [Carbonio CE](https://www.zextras.com/carbonio/) (open-source mail server based on Zimbra).

Adds **SSO login via any OIDC Provider** as an alternative to username/password — without modifying Carbonio files and without breaking existing authentication. Survives `apt upgrade` of all Carbonio packages.

---

## How it works

```
Browser                nginx              sidecar (Python)        OIDC Provider
  |                      |                      |                       |
  |-- GET /static/login/ |                      |                       |
  |<-- HTML + OIDC button (sub_filter injects <a href="/oidc/authorize">)
  |                      |                      |                       |
  |-- GET /oidc/authorize|--------------------->|                       |
  |                      |    PKCE S256 + state |                       |
  |<-- 302 to OP ----------------------------------------------------- >|
  |                      |                      |    user authenticates  |
  |<-- 302 /oidc/callback?code=...&state=... ----------------------- <--|
  |-- GET /oidc/callback |--------------------->|                       |
  |                      |   token exchange +   |                       |
  |                      |   id_token verify    |---------------------->|
  |                      |                      |<-- id_token (EdDSA)   |
  |                      |   Carbonio PreAuth   |                       |
  |<-- 302 /service/preauth?account=...&preauth=... (HmacSHA1 token)
  |-- Carbonio logs user in, redirects to /carbonio/
```

**Stack:** Python 3 stdlib + `cryptography` library. Zero Node.js, zero external frameworks.

---

## OIDC Provider compatibility

| Algorithm | Supported | Common providers |
|---|---|---|
| **EdDSA / Ed25519** | Yes | Encedo HSM, Keycloak (EdDSA configured) |
| **RS256 / RS384 / RS512** | Yes | Google, Azure AD, Okta, Auth0, Keycloak (default), Authentik |
| **ES256 / ES384 / ES512** | Yes | Cloudflare Access, Apple, AWS Cognito |

Works with any standards-compliant OIDC Provider that uses one of the above algorithms.

---

## Requirements

- Carbonio CE 4.x (tested on 4.5.2, Ubuntu 22.04)
- Python 3.8+ (Python 3.10 pre-installed on Carbonio CE)
- `cryptography` Python library (`pip3 install cryptography` or system package)
- OIDC Provider with **EdDSA / Ed25519** signing keys
- `zimbraPreAuthKey` configured for each Carbonio domain (see [Configuration](#configuration))

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/encedo/carbonio-oidc-connector.git
cd carbonio-oidc-connector
```

### 2. Configure

```bash
cp config.json.example config.json
# Edit config.json — fill in your OIDC provider URL, client credentials, and preauth keys
```

See [Configuration](#configuration) for all fields.

Get the PreAuth key for your domain:
```bash
su - zextras -c "carbonio prov gd yourdomain.com zimbraPreAuthKey"
```

If the domain has no PreAuth key yet, generate one:
```bash
su - zextras -c "carbonio prov generateDomainPreAuthKey yourdomain.com"
```

### 3. Install

```bash
sudo bash install.sh
```

The script:
1. Copies `src/*.py` to `/opt/zextras/oidc/`
2. Installs `config.json` (skips if already exists)
3. Sets ownership `zextras:zextras` and permissions
4. Installs nginx extension files to `/opt/zextras/conf/nginx/extensions/`
5. Installs and enables the systemd service
6. Runs `nginx -t` and reloads nginx

### 4. Start the service

```bash
systemctl start carbonio-oidc
curl http://127.0.0.1:8754/oidc/health
# {"status": "ok", "version": "1.0.0"}
```

### 5. Enable login redirect (optional)

To make the OIDC button the default entry point for a domain:

```bash
# Global — all domains
su - zextras -c "carbonio prov mcf zimbraWebClientLoginURL https://mail.example.com/oidc/authorize"

# Per domain
su - zextras -c "carbonio prov md yourdomain.com zimbraWebClientLoginURL https://mail.example.com/oidc/authorize"
```

### Uninstall

```bash
sudo bash uninstall.sh
# config.json is preserved — remove manually if needed: rm -rf /opt/zextras/oidc
```

---

## Upgrade

The connector survives `apt upgrade carbonio-*` — nginx extension files in
`/opt/zextras/conf/nginx/extensions/` are not touched by Carbonio package upgrades.

To update the connector itself:
```bash
git pull
sudo bash install.sh
systemctl restart carbonio-oidc
```

---

## Configuration

All configuration is in `/opt/zextras/oidc/config.json` (chmod 640, owner zextras:zextras).

| Field | Required | Default | Description |
|---|---|---|---|
| `port` | yes | — | Port the sidecar listens on (recommended: 8754) |
| `host` | yes | — | Bind address (use `127.0.0.1`) |
| `log_file` | no | `/var/log/carbonio-oidc.log` | Log file path |
| `log_level` | no | `INFO` | Log level: DEBUG, INFO, WARNING, ERROR |
| `session_ttl_seconds` | no | `300` | OIDC flow session TTL in seconds |
| `carbonio_base_url` | yes | — | Base URL of your Carbonio server, e.g. `https://mail.example.com` |
| `login_redirect` | no | `/carbonio/` | Where Carbonio redirects after successful PreAuth |
| `oidc_discovery_url` | yes | — | OIDC Provider discovery endpoint (`/.well-known/openid-configuration`) |
| `oidc_client_id` | yes | — | Client ID registered at the OIDC Provider |
| `oidc_client_secret` | yes | — | Client secret (used in token exchange, `client_secret_post`) |
| `oidc_redirect_uri` | yes | — | Must be `https://your-carbonio/oidc/callback` |
| `oidc_scopes` | no | `["openid","email","profile"]` | Requested OIDC scopes |
| `button_label` | no | — | Login button label (informational, currently hardcoded in nginx) |
| `domains` | yes | — | Map of domain → `preauth_key` (see below) |
| `account_claim` | no | `email` | JWT claim used as Carbonio account (must be `user@domain.com`) |
| `account_claim_fallback` | no | `preferred_username` | Fallback claim if primary is missing |

### Multi-domain setup

Each Carbonio domain has its own `zimbraPreAuthKey`:

```json
"domains": {
    "company.com": {
        "preauth_key": "abc123..."
    },
    "subsidiary.com": {
        "preauth_key": "def456..."
    }
}
```

The connector selects the key based on the domain part of the email returned in the `account_claim`.

### Example config.json

See [`config.json.example`](config.json.example).

---

## File layout on server

```
/opt/zextras/oidc/
  ├── server.py       # HTTP server, routing
  ├── config.py       # config loader + OIDC discovery
  ├── session.py      # in-memory session store (TTL-based)
  ├── oidc.py         # /oidc/authorize — PKCE S256
  ├── jwks.py         # JWKS fetch, cache, Ed25519 verify
  ├── preauth.py      # Zimbra PreAuth token (HmacSHA1)
  ├── callback.py     # /oidc/callback — full flow
  └── config.json

/opt/zextras/conf/nginx/extensions/
  ├── upstream-oidc.conf   # upstream oidc_connector { server 127.0.0.1:8754; }
  └── backend-oidc.conf    # location /oidc/ + sub_filter for login button

/etc/systemd/system/carbonio-oidc.service
/var/log/carbonio-oidc.log
```

---

## Building a release package

```bash
bash build.sh
# creates: carbonio-oidc-connector-1.0.0.tar.gz
```

The tarball contains all files needed for manual deployment (no git history, no dev files).

---

## Standards compliance

| Standard | Usage |
|---|---|
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | Authorization Code flow, id_token validation |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) — PKCE | S256 code challenge, mandatory for all flows |
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — OAuth 2.0 | Authorization Code grant, token endpoint |
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) — OAuth Discovery | `/.well-known/openid-configuration` |
| [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) — JWK | JWKS endpoint, Ed25519 public key (`OKP` / `crv: Ed25519`) |
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) — JWT | id_token parsing, `exp` / `iss` / `aud` validation |
| [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037) — OKP JWK | Ed25519 key representation in JWKS |

---

## Security notes

- PKCE S256 is always used — authorization code interception attacks are mitigated
- `state` parameter prevents CSRF
- Session cookies: `HttpOnly; Secure; SameSite=Lax`
- PreAuth tokens are single-use and short-lived (Carbonio enforces ~1 minute window)
- `config.json` is chmod 640, readable only by `zextras` user
- The sidecar binds to `127.0.0.1` only — not exposed directly to the internet
- Sidecar errors never block the standard username/password login form

---

## License

MIT
