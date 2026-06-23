# Shopify — HackerOne Bug Bounty
**Program:** https://hackerone.com/shopify  
**Researcher:** ask92 (`ask92@wearehackerone.com`)  
**Last synced:** 2026-06-08

---

## Active Campaign — Auth & ATO Bounty Multiplier
**Asset:** `Authentication & ATO` — 0 resolved reports (added Jun 5, 2026)  
**Window:** June 8 → June 26, 2026 (18 days remaining)

| Severity | Multiplier | Avg Bounty |
|----------|-----------|------------|
| Low | 1× | $500–$1,000 |
| Medium | **1.25×** | $1,000–$14,000 |
| High | **1.5×** | $14,000–$50,000 |
| Critical | **2×** | $50,000–$200,000 |

**To claim multiplier:** file report against the `Authentication & ATO` asset.

### Campaign — In Scope (multiplier eligible)
- Authentication bypass on any covered surface
- MFA bypass or downgrade
- OAuth, SSO, SAML, SCIM flaws with concrete ATO impact
- Session management issues on auth surfaces
- Account takeover via authentication flows
- Authorization flaws in auth/account APIs (MFA settings, OAuth grants, recovery email, sessions)

### Campaign — Covered Surfaces
- Merchant admin (`admin.shopify.com`)
- Partners dashboard (`partners.shopify.com`)
- `accounts.shopify.com`
- Shop App authentication + Login with Shop
- Checkout authentication
- Session token issuance (Admin, Storefront, app contexts)
- B2B buyer auth — merchant-configured SSO and SAML
- 2FA recovery flows

### Campaign — Out of Scope (standard payout only, no multiplier)
- Pre-account squatting
- Customer storefront accounts
- POS staff authentication (known PIN/app-token limitations)
- Account enumeration
- Brute force without rate-limit bypass
- Self-XSS on login surfaces
- OAuth open redirects, missing state param, redirect_uri misconfig (without ATO proof)
- Generic vulns chained to ATO where root cause is outside auth (e.g. storefront XSS → session theft)

---

## Full Asset Scope

### Tier 1 — Critical bounty eligible, LOW competition (hunt here first)

| Asset | Env | Resolved | Notes |
|-------|-----|----------|-------|
| `Authentication & ATO` | — | **0 (0%)** | Campaign asset, added Jun 5 |
| `shopify.plus` | Core | 2 (0%) | Enterprise merchant auth |
| `arrive-server.shopifycloud.com` | Core | 2 (0%) | — |
| `*.shopifycs.com` | Non-core | 2 (0%) | PCI credit card handling |
| `*.pci.shopifyinc.com` | Core | 1 (0%) | PCI environment |

### Tier 2 — Critical bounty eligible, moderate competition

| Asset | Env | Resolved | Notes |
|-------|-----|----------|-------|
| `shop.app` | Core | 53 (2%) | Consumer shopping app |
| `partners.shopify.com` | Core | 102 (4%) | Partner/app developer auth |
| `accounts.shopify.com` | Core | 120 (5%) | Centralized Shopify auth |
| `admin.shopify.com` | Core | 126 (5%) | Merchant admin |
| `your-store.myshopify.com` | Core | 495 (21%) | Dev store — requires partners.shopify.com account |

### Tier 3 — Medium max, bounty eligible

| Asset | Env | Max | Resolved | Notes |
|-------|-----|-----|----------|-------|
| `Shopify Developed Apps` | Non-core | Medium | 236 (10%) | apps.shopify.com/collections/made-by-shopify |
| `*.shopify.com` | Non-core | Medium | 248 (10%) | Per case basis |
| `*.shopifycloud.com` | Non-core | Medium | 84 (3%) | Avoid test/third-party subdomains |
| `*.shopify.io` | Non-core | Medium | 34 (1%) | Avoid test/third-party subdomains |
| `https://github.com/Shopify/*` | Non-core | Medium | 34 (1%) | Public repos |
| `*.shopifykloud.com` | Non-core | Medium | 36 (1%) | Email bugbounty@ if unsure |
| `linkpop.com` | Non-core | Medium | 11 (0%) | — |
| `shopifyinbox.com` | Non-core | Medium | 6 (0%) | — |

### Out of Scope — Do Not Test

| Asset | Reason |
|-------|--------|
| `cdn.shopify.com` | File upload is intended behavior |
| `community.shopify.com` | Third-party service |
| `community.shopify.dev` | Third-party service |
| `academy.shopify.com` | Third-party operated |
| `investors.shopify.com` | Third-party operated |
| `livechat.shopify.com` | Do not contact support |
| `*.email.shopify.com` | Third-party operated |
| `supplier-portal.shopifycloud.com` | Ineligible |
| `Shopify Third Party Stores` | Ineligible |
| `Shopify Third Party Apps` | Ineligible (escalate to dev first) |

---

## Bounty Calculator

Standard bounty via https://www.shopify.com/bugbounty/calculator  
Non-core assets scored with C/I/A requirements = Low.  
Score < 3 → $500 flat. Score ≥ 3 → calculator output. Max = $200,000.

---

## Rules (Critical)
- **Only test stores YOU created** via `partners.shopify.com` with `ask92@wearehackerone.com`
- Never test live merchant stores
- Working PoC required — reports without one are closed N/A
- No contact with Shopify Support (instant disqualification)
- Report as soon as validated — do not hold findings
- Add `X-HackerOne-Research: ask92` to all test requests

---

## Already Reported (skip)
| ID | Finding | Status |
|----|---------|--------|
| SHOPIFY-VULN-001 | Unauthenticated SSRF in `/api/ucp/mcp` on `*.myshopify.com` | Submitted 2026-06-07 |
