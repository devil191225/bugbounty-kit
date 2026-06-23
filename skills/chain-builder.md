# SKILL: Vulnerability Chaining
**Top researchers don't just find bugs — they chain them into maximum-impact reports.**

---

## THE CHAINING MINDSET

Every "low" or "medium" finding is a potential link in a critical chain.
Before closing any finding, ask: **"What can I do WITH this?"**

```
Open Redirect         → OAuth Token Theft
SSRF                  → AWS Metadata → Cloud Credentials → Account Takeover
XSS                   → CSRF → Admin Action
IDOR (read-only)      → PII Disclosure + Account Recon for targeted attack
JWT weak secret       → Forge admin JWT → Full ATO
Subdomain Takeover    → Cookie theft (if parent sets cookies on wildcard)
XXE                   → SSRF → Internal service access
Path Traversal        → Read /proc/environ → Secrets → RCE
```

---

## HIGH-VALUE CHAIN PATTERNS

### Chain 1: Self-XSS → Admin CSRF → ATO
```
Step 1: Find self-XSS in profile field (normally "low" / won't fix)
Step 2: Find CSRF on admin "view user profile" action
Step 3: Chain: Attacker sets malicious XSS payload in their profile
         → CSRF tricks admin into viewing attacker profile
         → XSS fires in admin context
         → XSS exfiltrates admin session / performs admin action
Result: CRITICAL — no user interaction beyond admin viewing a profile
```

### Chain 2: IDOR + PII → Account Takeover
```
Step 1: IDOR on /api/users/{id} → leaks email, phone
Step 2: Password reset sends OTP to phone
Step 3: Combine: enumerate users via IDOR, collect phones
         → Use leaked phone to receive OTP reset
         → Full account takeover on any user
Result: CRITICAL chain from two Medium findings
```

### Chain 3: Subdomain Takeover → Session Hijack
```
Step 1: Find subdomain pointing to abandoned Heroku/GitHub Pages
Step 2: Check if main domain sets cookies with domain=.example.com
Step 3: Register the abandoned service
         → Serve a page that reads the cookie
         → Any user visiting old.example.com sends their session
Result: HIGH — depends on cookie scope
```

### Chain 4: SSRF → Internal Admin → RCE
```
Step 1: Find SSRF in webhook/import/fetch parameter
Step 2: Probe internal network: 127.0.0.1:8080, 10.0.0.1, etc.
Step 3: Find internal admin panel on port 8080 (no auth, internal only)
Step 4: Use SSRF to interact with internal admin API
         → Trigger file write / command execution
Result: CRITICAL RCE
```

### Chain 5: Open Redirect → OAuth Token Theft
```
Step 1: Find open redirect: /redirect?url=https://attacker.com
Step 2: Target uses OAuth with redirect_uri validation
Step 3: Craft: /oauth/authorize?...&redirect_uri=/redirect%3Furl%3Dhttps://attacker.com
         → Some OAuth implementations allow redirect to any path on the domain
         → Code/token gets appended to attacker URL via Referer or fragment
Result: HIGH → Account takeover depending on OAuth flow
```

---

## CHAIN DISCOVERY PROCESS

```
1. Map all confirmed findings (even Low/Info)

2. For each finding, list what it ENABLES:
   - Information it reveals (emails, IDs, tokens, internal URLs)
   - State it can modify
   - Requests it can make on your behalf
   - Resources it can access

3. Look for BRIDGES between findings:
   - Finding A reveals X → Finding B requires X as input
   - Finding A gives you access to Y → Y enables Finding B

4. Test the full chain end-to-end before reporting
   - Document every step with screenshots/requests
   - Calculate the ACTUAL final impact (what can an attacker do?)

5. Report as ONE finding at the highest severity the chain achieves
   - Title: "Chained: [Component A] + [Component B] leads to [IMPACT]"
   - Show the full chain in reproduction steps
```

---

## SEVERITY AMPLIFIERS

When writing up a chain, these factors push severity up:

| Factor | Severity Impact |
|--------|----------------|
| No user interaction required | +1 level |
| Affects all users (not just self) | +1 level |
| Financial/data impact | +1 level |
| PII exposure | Regulatory attention |
| Leads to persistent access | +1 level |
| Bypasses MFA | +1 level |

---

## CHAIN DOCUMENTATION TEMPLATE

```markdown
## Chain Summary
**Start:** [Finding A] — [brief description]
**End:** [Final impact — e.g., Account Takeover on arbitrary user]
**Severity:** CRITICAL (CVSS 9.1)

## Step-by-Step Chain

### Step 1: [Finding A Title]
- URL: 
- Method: 
- Request:
- Response/Evidence:

### Step 2: [Finding B Title]
- Uses [what was obtained in Step 1]
- URL:
- Request:
- Response/Evidence:

### Step 3: Final Impact
- Demonstrate final result
- Screenshot or response showing impact

## Why This Matters
[Business impact explanation — what can an attacker actually do with this?]
```
