# OAuth 2.0 / OpenID Connect — Advanced Attack Reference
> Source: RFC 6749, RFC 6750, RFC 7636 (PKCE), RFC 9101 (PAR), OAuth 2.0 Security BTP, PortSwigger OAuth labs | RAG Knowledge Base | Full detail preserved
> Related: `portswigger-advanced.md` (OAuth basics), `saml-attacks.md`, `bug-chains.md` (CHAIN-001), `browser-security.md`

---

## Overview

OAuth 2.0 = authorization framework (delegated access). OpenID Connect (OIDC) = identity layer on OAuth (id_token, UserInfo). Nearly every modern app uses one or both.

**Parties:**
- Resource Owner (user)
- Client (application)
- Authorization Server (AS) — issues tokens
- Resource Server (RS) — API protected by tokens

**Bug bounty focus:** redirect_uri validation, state/nonce, PKCE, token handling, client authentication, OIDC id_token validation.

---

## OAuth Flows (Attack Surface by Flow)

| Flow | Tokens in | Primary attacks |
|---|---|---|
| Authorization Code | Query param `code` → token exchange | Redirect steal, CSRF, PKCE bypass |
| Authorization Code + PKCE | Same + code_verifier | PKCE downgrade, verifier leak |
| Implicit (deprecated) | URL fragment `#access_token` | Token leak via Referer, fragment exposure |
| Hybrid | Code + tokens in fragment | Combined attack surface |
| Client Credentials | Server-to-server | Client secret leak, scope escalation |
| Device Code | User enters code on device | Code phishing, slow polling abuse |
| Refresh Token | Long-lived renewal | Token rotation bypass, scope persistence |

---

## Attack Class 1: Redirect URI Manipulation

**CWE-601** | Highest-frequency OAuth bug

### Validation Bypass Patterns

**Path-relative redirect:**
```
redirect_uri=https://target.com/callback/../../../redirect?url=https://attacker.com
redirect_uri=/open-redirect?url=https://attacker.com
```

**Subdomain wildcard:**
```
redirect_uri=https://attacker.target.com/callback
# If registered: https://*.target.com
```

**Open redirect on allowed domain:**
```
redirect_uri=https://target.com/logout?next=https://attacker.com
```

**Fragment injection:**
```
redirect_uri=https://target.com/callback%23@attacker.com
```

**Parameter pollution:**
```
redirect_uri=https://target.com/callback&redirect_uri=https://attacker.com
```

**Encoding tricks:**
```
redirect_uri=https://target.com%2f%2fattacker.com
redirect_uri=https://target.com\@attacker.com
```

### Impact
Authorization code or access token delivered to attacker → account takeover.

### Testing
1. Register/intercept OAuth client (or use public client_id from JS)
2. Fuzz `redirect_uri` with bypass payloads
3. Complete flow — check if code/token hits attacker endpoint
4. Test each OAuth provider separately (Google, Facebook, custom)

---

## Attack Class 2: Authorization Code Interception / CSRF

### OAuth CSRF (Login CSRF)
Attacker initiates OAuth flow → victim completes → victim's account linked to attacker's OAuth identity at client app.

**Missing `state` parameter** or predictable state → CSRF on OAuth callback.

**Fix:** Cryptographically random `state`, validated server-side.

### Code Replay
Use authorization code twice if AS doesn't enforce one-time use.

### Code Leak via Referer
After redirect to `redirect_uri?code=XXX`, page loads third-party resources → Referer header leaks code to third party.

**Mitigation:** Referrer-Policy, code exchange server-side immediately.

---

## Attack Class 3: PKCE Bypass

**RFC 7636** — Proof Key for Code Exchange

### Downgrade Attacks
```
code_challenge_method=plain
code_challenge=attacker_known_value
code_verifier=attacker_known_value
```
If AS accepts `plain` instead of mandatory S256 → MITM can exchange stolen code.

### Missing PKCE on Public Clients
Mobile/SPA apps without PKCE → authorization code interception on custom URL schemes:
```
myapp://callback?code=STOLEN
```

### code_verifier Leak
Verifier in browser storage, logs, or referrer — combined with stolen code.

### Testing
1. Capture auth request — check `code_challenge` and method
2. Replay with `code_challenge_method=plain`
3. Omit PKCE entirely on public client
4. Test custom URL scheme hijacking on mobile

---

## Attack Class 4: Implicit / Hybrid Flow Token Theft

### Fragment Token Exposure
```
https://client.com/callback#access_token=eyJ...&token_type=Bearer
```
- Visible in browser history
- Leaked via Referer to third-party subresources
- XSS steals fragment (if JS reads location.hash)

### Hybrid Flow
Code in query + token in fragment — double exfiltration surface.

**Recommendation:** Authorization code + PKCE only. Report implicit flow usage as finding on sensitive apps.

---

## Attack Class 5: OpenID Connect id_token Attacks

### id_token Structure
JWT containing: `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `email`, etc.

### Algorithm Confusion (RS256 → HS256)
Server verifies with public key as HMAC secret → forge id_token with public key.

### alg:none
```json
{"alg":"none","typ":"JWT"}
```

### Missing Signature Verification
Accept unsigned id_token if `alg` header stripped.

### aud Claim Bypass
Accept id_token with wrong `aud` (different client_id) → cross-client impersonation.

### iss Confusion
Accept id_token from attacker-controlled issuer if `iss` not strictly validated.

### nonce Replay / Missing
OIDC CSRF protection via `nonce` in id_token matching auth request. Missing validation → login CSRF.

### kid Header Injection
```json
{"kid":"../../dev/null"}
{"kid":"attacker-key-id"}
```
Path traversal or key substitution in JWKS lookup.

### Testing id_token
1. Capture id_token from callback (fragment or token endpoint response)
2. jwt_tool / manual decode
3. Re-sign with none/HS256/confusion
4. Modify claims: `sub`, `email`, `admin` claims
5. Replay expired token
6. Swap id_token between clients

---

## Attack Class 6: Token Endpoint Attacks

### Token Substitution
Exchange code with different `client_id` if client auth weak.

### Missing client_secret on Confidential Client
Public exposure of secret in mobile app → full client impersonation.

### Scope Escalation
```
scope=openid email admin
# vs granted: openid email
# RS accepts broader scope than AS granted
```

### Refresh Token Attacks
- Refresh token doesn't rotate → stolen token persists
- Refresh token works after logout/password change
- Refresh token accepted for different client_id

---

## Attack Class 7: Dynamic Client Registration (RFC 7591)

If AS allows open registration:
```json
POST /register
{
  "redirect_uris": ["https://attacker.com/callback"],
  "client_name": "Legitimate App Clone"
}
```
Register malicious client → phish users through legitimate-looking OAuth consent.

---

## Attack Class 8: Pushed Authorization Requests (PAR — RFC 9126)

Authorization parameters pushed to AS server-side, reference returned to client.

### request_uri SSRF
If AS fetches `request_uri` server-side:
```
request_uri=https://169.254.169.254/latest/meta-data/
request_uri=https://internal-admin.local/params.json
```

### request_uri Open Redirect Chain
AS follows redirects from attacker URL to internal targets.

---

## Attack Class 9: Resource Indicator (RFC 8707)

`resource` parameter specifies target RS. Confusion between multiple RS — token intended for RS-A accepted at RS-B.

---

## Attack Class 10: OAuth for Native/Mobile Apps

### Custom URI Scheme Hijacking
```
com.target.app://oauth/callback
# Any app can register same scheme on Android
```

**Fix:** App Links (Android), Universal Links (iOS), claimed HTTPS redirect.

### PKCE + Custom Scheme
Without PKCE, malicious app intercepts code.

### Embedded WebView
OAuth in WebView → SSL stripping, JS injection, cookie theft. Report if app uses WebView for OAuth on sensitive targets.

---

## Attack Class 11: Account Takeover via OAuth Identity

### Pre-Account Takeover
1. Victim email known, no account yet
2. Attacker registers OAuth with victim email (if IdP doesn't verify)
3. Victim later creates account → attacker's OAuth linked

### Unlink/Re-link Race
Unlink OAuth, re-link attacker's OAuth before victim notices.

### Email Change After OAuth Bind
OAuth login → change email to attacker's → password reset on email login.

---

## Attack Class 12: SSRF via OAuth Features

- `request_uri` fetch (PAR)
- JWKS URL fetch: `jwks_uri` pointing to internal
- Dynamic client `logo_uri`, `policy_uri`, `tos_uri` fetched server-side
- RFC 7662 token introspection endpoint SSRF

---

## Platform-Specific Notes

### Google OAuth
- Strict redirect_uri exact match (usually)
- Test `redirect_uri` with `.googleusercontent.com` patterns
- `approval_prompt=force` for consent phishing tests

### Facebook Login
- `redirect_uri` must match app settings exactly
- Test `response_type=token` legacy

### Azure AD / Microsoft
- Multi-tenant apps: `common` vs `organizations` vs tenant ID
- Token for tenant A used against tenant B
- `/.well-known/openid-configuration` for metadata

### Auth0 / Okta
- Custom rules/actions may inject claims unsafely
- Management API token exposure in SPA

### Keycloak
- Admin console default creds (authorized testing)
- Client scope misconfiguration

---

## OIDC Discovery & Metadata

```
GET /.well-known/openid-configuration
GET /.well-known/oauth-authorization-server
```

Extract: `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `registration_endpoint`, supported grants/scopes.

Fuzz all endpoints discovered.

---

## Testing Methodology

```
Phase 1: Recon
  [ ] Find client_id in JS/mobile app
  [ ] Fetch OIDC discovery document
  [ ] Map all redirect_uris registered
  [ ] Identify flows used (code, implicit, hybrid)

Phase 2: redirect_uri
  [ ] Fuzz bypass payloads
  [ ] Chain with open redirect on same domain
  [ ] Subdomain takeover on allowed redirect host

Phase 3: Token handling
  [ ] id_token alg confusion, none, claim tampering
  [ ] Access token scope vs RS enforcement
  [ ] Refresh token rotation and revocation

Phase 4: PKCE / state / nonce
  [ ] PKCE downgrade to plain
  [ ] Missing state → login CSRF PoC
  [ ] Missing nonce → OIDC CSRF

Phase 5: Advanced
  [ ] PAR request_uri SSRF
  [ ] Dynamic client registration abuse
  [ ] Mobile custom scheme hijack
```

---

## Tools

| Tool | Use |
|---|---|
| Burp Suite | Intercept/modify OAuth flows |
| jwt_tool | JWT/id_token manipulation |
| oauth.tools | Flow visualization |
| OAuth2 Attacker (Burp BApp) | Automated OAuth testing |
| PKCE generator | code_verifier/challenge pairs |
| auth0-scan, oauthscan | Automated misconfig detection |

---

## Bug Bounty Report Template

```markdown
## Summary
Open redirect at /logout chained with OAuth redirect_uri validation bypass
allows authorization code theft → full account takeover.

## Steps
1. Visit: /oauth/authorize?client_id=X&redirect_uri=https://target.com/logout?next=https://attacker.com&response_type=code
2. Authenticate as victim
3. Code delivered to https://attacker.com/?code=AUTH_CODE

## Impact
Account takeover on any user who clicks crafted link.

## CWE
CWE-601: URL Redirection to Untrusted Site
CWE-287: Improper Authentication

## Remediation
Strict exact-match redirect_uri validation.
Block open redirects or use allowlist-only post-login redirects.
```

---

## Chain References

- **CHAIN-001:** Open Redirect → OAuth token theft (`bug-chains.md`)
- **CHAIN-009:** Subdomain takeover → OAuth redirect_uri
- SAML comparison: `saml-attacks.md` — many enterprise apps offer both

---

## CWE / RFC Reference

| Issue | CWE | RFC |
|---|---|---|
| Redirect bypass | CWE-601 | RFC 6749 §4.1.3 |
| PKCE missing | CWE-287 | RFC 7636 |
| Token forgery | CWE-347 | OIDC Core §2 |
| Login CSRF | CWE-352 | OIDC nonce |
| SSRF via request_uri | CWE-918 | RFC 9126 |
