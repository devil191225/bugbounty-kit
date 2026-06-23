# Session: 2026-06-09 — Monzo

## Target
Monzo (Intigriti) — £12,500 max bounty — Reopened 2026-06-04

## Scope
- auth.monzo.com
- business.monzo.com
- webviews.monzo.com
- pay.monzo.com
- *.prod-ffs.io (wildcard, no live subdomains found yet)
- Open Banking OAuth focus

## Findings

### MONZO-VULN-001 [HIGH - READY TO SUBMIT]
**QR Code Login Session Hijacking — Monzo Business Account Takeover**

Chain:
1. auth.monzo.com client credentials in public __NEXT_DATA__
2. Origin header bypass on /login/qr-link/unauth-initiated/* endpoints
3. Unbound PKCE challenge at authorize time

Attack: Attacker generates QR session using auth.monzo.com's public creds + spoofed Origin, displays QR to victim, victim scans + approves, attacker calls authorize with own PKCE challenge, gets auth code in magic_link_uri response, exchanges for victim's Monzo Business access token.

CVSS 4.0: 8.1 High (AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N)

Report: reports/MONZO-VULN-001-qr-session-hijacking.md
Evidence: sessions/2026-06-09/monzo/MONZO-VULN-001-evidence.txt

All technical steps confirmed. Social engineering step (victim scans QR) not executed.

### MONZO-VULN-002 [MEDIUM - DOCUMENT ONLY]
**Plaid Development Environment in Production**

plaidEnv: "development" in webviews.monzo.com __NEXT_DATA__ runtimeConfig
Affects Monzo US bank account linking (Plaid integration)
plaidPublicKey: "41bc8674f390fd17aa8e161dfea9a9"
Plaid dev env limited to 100 real items, less stable

## Tested But Dead Ends
- OIDC redirect_uri validation: properly enforced on QR start endpoint
- S3 bucket listing: all access denied
- internal-api.monzo.com mTLS: required for some endpoints
- openbanking.eu.monzo.com: requires real QWAC cert (mTLS)
- prod-ffs.io: no live subdomains found in certs or CSP

## Client Credentials Found (all mnzpub - intentionally public)
- auth.monzo.com: oauth2client_0000Anvymwf9DuwnMsAJCz / mnzpub.H1sqLYd9...
- business.monzo.com: oauth2client_00009rxnCG1wrCdTQmUUSn / mnzpub.Ba++eKTb...
- webviews.monzo.com: oauthclient_000094oi2ytifdsiO84Xfl / mnzpub.EKqqOjZA...
- pay.monzo.com: oauth2client_00009dFUM4BKfa5YIDRG4H / mnzpub.FoaYQ8mv...
- developers.monzo.com: oauthclient_000094PvINDGzT3k6tz8jp (explicitly public per code comment)

## Next Steps
1. Submit MONZO-VULN-001 to Intigriti
2. Consider submitting MONZO-VULN-002 (Plaid dev env) as a separate lower-severity report
3. Investigate *.prod-ffs.io more — check if any staging DNS entries reveal prod subdomain patterns
4. Look at additional-risk-assessment and invoices webviews (need user token for meaningful IDOR test)
