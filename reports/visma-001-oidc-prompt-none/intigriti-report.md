# OIDC `prompt=none` Not Returning `login_required` Redirect in Visma Connect — Breaks Silent Authentication for All Integrated Applications

## Description

Visma Connect's authorization endpoint advertises support for `prompt=none` in its OIDC discovery document (`"prompt_values_supported": ["none", ...]`), but when a client sends a `prompt=none` authorization request without an active session, the server redirects to an internal error page (`/error?errorId=...`) instead of redirecting back to the client's `redirect_uri` with `error=login_required`.

This violates OIDC Core §3.1.2.6, which requires: *"If the End-User is not already authenticated, the Authorization Server MUST NOT attempt to prompt the End-User for authentication or consent. In this case, the Authorization Server MUST return an error, typically `login_required`"* — as a redirect to the registered `redirect_uri`.

Every Visma application that relies on `prompt=none` for silent token refresh (SPAs refreshing sessions in background iframes, mobile apps performing silent re-auth) receives a generic error page instead of the expected error signal. Those apps can never gracefully handle session expiry or redirect users to re-authenticate.

## Steps to Reproduce

**Setup:** No active session on Visma Connect (unauthenticated state). No account required.

**Step 1:** Send this request:

```
GET /connect/authorize?client_id=vismaonline&prompt=none&redirect_uri=https://www.vismaonline.com/&response_type=code&scope=openid&state=TESTSTATE123 HTTP/1.1
Host: connect.identity.stagaws.visma.com
```

**Step 2:** Observe the redirect:

```
HTTP/1.1 302 Found
Location: https://connect.identity.stagaws.visma.com/error?errorId=CfDJ8KIv3qOHS15GnSIKeUavAMGBv-bWz4cNGeP4x3_4vqA1ROmkOK03o0ucqM3...
```

**Step 3:** Follow the redirect — the user sees:

```
"Ooops! Something went wrong while processing your request.
 We advise you to close the browser and try again later."
```

**Expected behavior per OIDC Core §3.1.2.6:**

```
HTTP/1.1 302 Found
Location: https://www.vismaonline.com/?error=login_required&state=TESTSTATE123
```

The client application never receives the `login_required` error code and cannot proceed.

---

**Confirmed on all tested client IDs:**

| client_id | redirect_uri tested | Result |
|---|---|---|
| `vismaonline` | `https://www.vismaonline.com/` | → `/error?errorId=...` |
| `dinero` | `https://app.dinero.dk/` | → `/error?errorId=...` |
| `accountsettings` | `https://account.visma.com/` | → `/error?errorId=...` |

**Also confirmed on production (`connect.visma.com`).**

---

**The server's own discovery document advertises this capability:**

```
GET https://connect.identity.stagaws.visma.com/.well-known/openid-configuration

"prompt_values_supported": ["none", "login", "consent", "select_account"]
```

The server claims to support `prompt=none` but does not implement the correct error response path.

## Impact

`prompt=none` is the standard mechanism for silent session refresh in OAuth2/OIDC. SPAs (including Visma's own eaccounting, myservices, and account settings apps) use it to silently check whether a user is still logged in — typically inside a hidden iframe. When the server returns a generic error page instead of the spec-required `login_required` redirect:

1. **The client application receives no usable signal** — it cannot distinguish "user not logged in" from "server error"
2. **Silent re-authentication loops break** — the SPA has no way to trigger a visible login redirect
3. **Users are stranded on a generic error page** with no call to action and no way back to the application
4. **All Visma-integrated applications** that use the standard silent auth pattern are affected simultaneously

This is an availability impact on Visma Connect's core SSO function, affecting all integrated Relying Parties.

CVSS 3.1 Score: **5.3 (Medium)** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`

## Recommended Fix

In the OIDC authorization pipeline, when `prompt=none` is set and no active session exists, catch the `LoginRequired` (or equivalent) exception and redirect to the client's registered `redirect_uri` with the error parameters instead of rendering an error page:

```
302 Found
Location: {redirect_uri}?error=login_required&error_description=...&state={state}
```

For IdentityServer-based implementations, this is typically handled in the `AuthorizeInteractionResponseGenerator` by returning an `InteractionResponse` with `IsLogin = true` and ensuring the framework serializes it back to the client when `prompt=none` is active.

## References

- OIDC Core §3.1.2.6: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest (`prompt` parameter definition)
- RFC 6749 §4.1.2.1: OAuth 2.0 error response format
- IdentityServer GitHub Issue #2605: "IdentityServer4 does not report errors back to clients as per OpenID Connect and OAuth 2.0 specifications"

## Attachments

- `evidence/curl-prompt-none.txt` — Full curl output showing wrong redirect across 3 client IDs and production
