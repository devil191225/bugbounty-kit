# SHOPIFY-002b Submission Notes

## Pre-Submit Checklist
- [x] Title: bug class + endpoint + impact
- [x] First sentence states exact impact
- [x] Exact HTTP request included (copy-paste ready)
- [x] CVSS calculated
- [x] Fix is 2 sentences
- [x] No "could potentially" language
- [x] Campaign asset: "Authentication & ATO" → 1.25x multiplier on Low
- [ ] Add curl evidence to evidence/curl-406-response.txt before submitting

## Evidence Needed Before Submit
Run this and save output to evidence/curl-406-response.txt:
```bash
curl -sv "https://shopify.com/authentication/100419207467/oauth/authorize?\
client_id=c2ff9e07-50c4-45e7-a935-3791a8dd8c92&\
prompt=none&\
redirect_uri=https://ask92-bb-test.myshopify.com/customer_authentication/callback&\
response_type=code&scope=openid+email+customer-account-api&state=TEST123" 2>&1
```

## H1 Submission Details
- Program: Shopify (hackerone.com/shopify)
- Asset: Authentication & ATO
- Severity: Low
- Multiplier: 1.25x → ~$625–$1,250

## Dup Check
- Searched: site:hackerone.com/reports shopify "prompt=none" "406"
- Searched: shopify hackerone OIDC "login_required" 406
- Result: No matching public reports found

## Status
READY TO SUBMIT — run evidence curl first
