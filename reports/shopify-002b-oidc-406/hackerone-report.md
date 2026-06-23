# OIDC `prompt=none` returns HTTP 406 instead of `login_required` error redirect on Customer Account authentication endpoint

## Summary

The Shopify Customer Account OIDC endpoint (`shopify.com/authentication/{store_id}/oauth/authorize`) returns HTTP 406 when `prompt=none` is requested for an unauthenticated session, instead of redirecting to the `redirect_uri` with `error=login_required` as required by OIDC Core §3.1.2.6. This breaks any relying party app that uses the silent authentication pattern — the app never receives the error redirect, so it cannot fall back to an interactive login prompt. The result is a silent failure that leaves the user stuck.

## Vulnerability Details

**Vulnerability Type:** OIDC Specification Non-Compliance (Broken Auth Error Handling)
**CVSS 3.1 Score:** 5.3 (Medium) — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
**Affected Endpoint:** `GET https://shopify.com/authentication/{store_id}/oauth/authorize`
**Affected Parameter:** `prompt=none`
**OIDC Reference:** [OIDC Core §3.1.2.6](https://openid.net/specs/openid-connect-core-1_0.html#AuthError)

**Spec requirement:**
> "If the End-User is not already authenticated… the Authorization Server MUST return the login_required error response."
> The error MUST be returned **as a redirect to the redirect_uri** with `error=login_required`.

**Actual behavior:** HTTP 406 Not Acceptable — the redirect never happens.

## Steps to Reproduce

**Environment:**
- Store: `ask92-bb-test.myshopify.com` (dev store, no active session)
- Client ID: `c2ff9e07-50c4-45e7-a935-3791a8dd8c92` (checkout SSO client)
- OIDC Issuer: `https://shopify.com/authentication/100419207467`

**Step 1 — Confirm OIDC discovery (baseline):**
```
GET https://shopify.com/authentication/100419207467/.well-known/openid-configuration
```
Response confirms `prompt` values supported include `none`.

**Step 2 — Send prompt=none with no active session:**
```
GET https://shopify.com/authentication/100419207467/oauth/authorize?
  client_id=c2ff9e07-50c4-45e7-a935-3791a8dd8c92&
  prompt=none&
  redirect_uri=https://ask92-bb-test.myshopify.com/customer_authentication/callback&
  response_type=code&
  scope=openid+email+customer-account-api&
  state=TEST123

Host: shopify.com
```

**Step 3 — Observe response:**
```
HTTP/2 406 Not Acceptable
content-type: text/html; charset=utf-8
```

**Expected:**
```
HTTP/2 302 Found
Location: https://ask92-bb-test.myshopify.com/customer_authentication/callback
  ?error=login_required
  &error_description=End-User+authentication+is+required
  &state=TEST123
```

## Impact

Any Shopify app or storefront integration that uses `prompt=none` for silent authentication (standard pattern for SPAs and checkout flows) will silently fail when the user has no session. The 406 response is not routable to the redirect_uri — the app receives no callback, cannot detect the unauthenticated state, and cannot initiate an interactive login. This produces broken checkout experiences and stranded sessions for end users.

The `sso=silent` parameter used in the new checkout flow (`/checkouts/cn/...?sso=silent`) internally initiates this exact OIDC request, making this a live issue in production checkout.

## Recommended Fix

When `prompt=none` is requested and no valid session exists, return:
```
302 Found
Location: {redirect_uri}?error=login_required&error_description=...&state={state}
```
per OIDC Core §3.1.2.6.

## Supporting Materials

See `evidence/curl-406-response.txt` for full curl output.
