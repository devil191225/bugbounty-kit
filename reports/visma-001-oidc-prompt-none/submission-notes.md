# VISMA-001 Submission Notes

## Pre-Submit Checklist
- [x] Title: bug class + endpoint + impact
- [x] First sentence states exact impact
- [x] Exact HTTP request included (copy-paste ready)
- [x] CVSS calculated: 5.3 Medium (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)
- [x] Fix is 2 sentences
- [x] No "could potentially" language
- [x] Evidence saved: evidence/curl-prompt-none.txt
- [x] Confirmed on 3 client_ids (vismaonline, dinero, accountsettings)
- [x] Confirmed on production (connect.visma.com)
- [x] Discovery document shows server ADVERTISES prompt=none support
- [ ] Screenshot / video of error page (optional but add before submitting)

## Intigriti Submission Details
- Program: Visma (`app.intigriti.com/programs/visma/visma/detail`)
- Asset: `connect.identity.stagaws.visma.com`
- Severity: Medium
- Bug type: Improper Implementation of Authentication Algorithm / OIDC Spec Violation
- CVSS 3.1: 5.3 Medium — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
  Availability impact: silent auth flows fail platform-wide; no confidentiality impact, hence 5.3 Medium.

## Dup Check Results
- Searched HacktActivity: no H1 API (401 pending support fix)
- Searched web: no public reports for "Visma Connect prompt=none login_required"
- Intigriti disclosed: not searchable without login
- IdentityServer4 issue #2605 is upstream bug — not a prior Visma report
- Scope was updated 2026-06-09 (today) — maximum freshness

## Key Differentiator (vs pure upstream IS4 bug)
Visma's server explicitly advertises `"prompt_values_supported": ["none", ...]` in OIDC discovery.
They claim the feature works. Confirmed broken on both staging AND production.
This is not "unknown" behavior — it's a broken advertised capability.
Result: any SPA relying on silent SSO (prompt=none) cannot refresh sessions and must bounce users through an interactive login, breaking seamless SSO flows.

## Potential Pushback
- "This is an upstream IdentityServer4/Duende issue"
  → Counter: Server explicitly advertises prompt=none support. Visma owns the behavior.
- "Low impact — no data exposure"
  → Counter: All Visma applications using silent auth are broken. Affects eaccounting,
    myservices, account settings, dinero — their core product suite.
- "Staging only" 
  → Counter: Production (connect.visma.com) confirmed same behavior.

## Status
READY TO SUBMIT
