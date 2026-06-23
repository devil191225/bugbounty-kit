# VISMA-002 Submission Notes

## Pre-Submit Checklist
- [x] Title: bug class + endpoint + impact
- [x] First sentence states exact impact
- [x] Exact HTTP requests included (copy-paste ready, both baseline and bypass)
- [x] CVSS calculated: 5.4 Medium (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N)
- [x] Fix is 2 options, both concrete
- [x] No "could potentially" language
- [x] Evidence saved: evidence/bypass-proof.txt (annotated + raw JWT)
- [x] auth_time staleness confirmed: 2275 seconds (37.9 min) — math shown
- [x] Bypass mechanism clearly explained (suppressed_max_age is internal param)
- [x] Tested on staging (identity.stage.vismaonline.com)
- [x] Step 1 confirmed on production (identity.vismaonline.com) — same suppressed_max_age=0 injection in redirect
- [ ] Screenshot of the token form response (optional but add if possible)

## Intigriti Submission Details
- Program: Visma (`app.intigriti.com/programs/visma/visma/detail`)
- Asset: `identity.stage.vismaonline.com` (also check production: identity.vismaonline.com)
- Severity: Medium (upgrade argument available if Visma confirms max_age=0 usage for step-up)
- Bug type: Improper Implementation of Authentication Algorithm / OIDC Spec Violation
- CVSS 3.1: 5.4 Medium — AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N

## Dup Check
- Not searchable on Intigriti without login
- No public report for "Visma suppressed_max_age" or "max_age bypass identity.vismaonline.com"
- IdentityServer4 does not have this specific internal parameter in its standard codebase — this appears to be a Visma-specific extension that introduces the vulnerability
- VISMA-001 (prompt=none) submitted same day — separate bug on different endpoint (connect.identity.stagaws.visma.com vs identity.stage.vismaonline.com)

## Technical Detail for Triager
The server's max_age enforcement works by:
1. Receiving max_age=0 from client
2. Checking if current session is fresh enough (it isn't → must re-auth)
3. Redirecting to /login with ReturnUrl containing suppressed_max_age=0
4. After login, the /login page POSTs back to /connect/authorize WITH suppressed_max_age=0
5. The authorize endpoint sees suppressed_max_age=0 and SKIPS the max_age check (treats it as "already handled")

The bug: step 5 logic is triggered by ANY request with suppressed_max_age=0, including one sent directly by a client, not just by the login flow. The server has no way to distinguish "came from our own login redirect" from "injected externally."

## max_age Usage Research (done before submission)
Checked all reachable Visma apps for max_age=0 in their auth flows:
- admin.stage.vismaonline.com → NO max_age in authorize request
- eaccounting.stage.vismaonline.com → NO max_age
- myservices.stage.vismaonline.com → JS bundles searched, NO max_age config
- account.visma.com (accountsettings client) → DNS doesn't resolve, staging equivalent not found
- identity.stage.vismaonline.com discovery doc → auth_time NOT in claims_supported

Conclusion: No concrete Visma app found using max_age=0. Medium 5.4 is correct. Do not claim High.
Also note: discovery doc doesn't advertise auth_time, yet server processes max_age — defense in depth is broken regardless.

## Potential Pushback
- "User needs existing session" → Counter: max_age=0 is specifically designed to gate access even FOR existing sessions. The whole point is to force re-auth. An attacker with access to a live session (shared device, XSS, shoulder surfing) bypasses the freshness gate.
- "Staging only" → Counter: Production (identity.vismaonline.com) confirmed same suppressed_max_age=0 injection.
- "Not a real-world scenario" → Counter: OIDC clients commonly rely on max_age=0 to enforce fresh authentication before sensitive actions. When the AS allows external injection of suppressed_max_age=0, relying parties can no longer trust that freshness requirement was enforced.
- "Low severity" → Counter: The server-side enforcement is the only layer. Relying parties trust the server to enforce max_age. Once the server is bypassed, no client-side check can compensate.
- "auth_time not in discovery doc" → Server demonstrably processes max_age (Step 1 redirect proves it) and issues tokens with auth_time — the feature exists and is bypassed regardless of documentation.

## Status
READY TO SUBMIT
