# SKILL: Bug Bounty Report Writing
**A great report gets triaged fast and paid at the highest severity. A bad one gets N/A'd.**

---

## REPORT QUALITY PRINCIPLES

1. **Reproducibility first** — If the triager can't reproduce it, it doesn't exist
2. **Business impact** — Explain what a real attacker could DO, not just what's wrong
3. **No speculation** — Every claim backed by evidence (request/response, screenshot)
4. **Concise and scannable** — Triagers handle hundreds of reports
5. **Professional tone** — You're a researcher, not an adversary

---

## CVSS SCORING GUIDE

Use CVSS 3.1. Calculate at: https://www.first.org/cvss/calculator/3.1

| Vector | Options |
|--------|---------|
| AV (Attack Vector) | Network(N) > Adjacent(A) > Local(L) > Physical(P) |
| AC (Attack Complexity) | Low(L) > High(H) |
| PR (Privileges Required) | None(N) > Low(L) > High(H) |
| UI (User Interaction) | None(N) > Required(R) |
| S (Scope) | Changed(C) > Unchanged(U) |
| C/I/A | High(H) > Low(L) > None(N) |

**Common scores:**
- Unauthenticated SQLi → 9.8 (CVSS: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- Auth IDOR → 6.5 (CVSS: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- Stored XSS (no auth) → 8.8 (CVSS: AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

---

## REPORT TEMPLATE

```markdown
# [Vulnerability Type]: [Specific Description of Impact]

**Severity:** [Critical/High/Medium/Low]  
**CVSS Score:** [X.X] ([CVSS vector string])  
**Asset:** [Affected domain/endpoint]  
**Weakness:** [CWE-XXX: Name]  

---

## Summary

[2-3 sentences max. What is the bug, where is it, and what can an attacker do?]

Example: "An Insecure Direct Object Reference vulnerability in the `/api/v2/invoices/{id}` endpoint allows any authenticated user to read, modify, or delete invoices belonging to other users by incrementing the numeric `id` parameter. This exposes financial records for all customers and allows unauthorized invoice manipulation."

---

## Impact

[Describe the BUSINESS impact. What can an attacker actually achieve?]

- **Confidentiality:** An attacker can read [specific data type] for any [user/account/record]
- **Integrity:** An attacker can modify [what] leading to [consequence]  
- **Availability:** [if applicable]
- **Financial:** [if applicable — unauthorized charges, credit theft]
- **Regulatory:** [GDPR/PCI-DSS implications if PII or payment data involved]

---

## Steps to Reproduce

**Prerequisites:**
- Account A (attacker): `attacker@example.com` / `password123`
- Account B (victim): `victim@example.com` (any other valid account)

**Steps:**

1. Log in as Account A
2. Navigate to `https://target.com/invoices/` and note your invoice ID: `INV-10482`
3. Send the following request, replacing `INV-10482` with `INV-10481` (another user's invoice):

```http
GET /api/v2/invoices/10481 HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbGc....[Account A token]
```

4. Observe the response returns Account B's invoice data:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 10481,
  "owner_email": "victim@example.com",
  "amount": 4250.00,
  "status": "pending",
  ...
}
```

5. The response contains Account B's financial data despite using Account A's session token.

---

## Proof of Concept

[Attach screenshot clearly showing: your session identifier (partial), the modified request, the victim's data in the response]

> ⚠️ Note: Screenshots have been redacted to protect victim privacy. Full PoC available upon request.

---

## Affected Endpoints

- `GET /api/v2/invoices/{id}` — Read any invoice
- `PUT /api/v2/invoices/{id}` — Modify any invoice [if applicable]
- `DELETE /api/v2/invoices/{id}` — Delete any invoice [if applicable]

---

## Root Cause

The API endpoint queries the database using only the user-supplied `id` parameter without verifying that the requesting user is the owner of the resource:

```
SELECT * FROM invoices WHERE id = ? 
// Missing: AND owner_id = current_user.id
```

---

## Remediation

1. **Immediate:** Add ownership verification to all invoice-related queries:
   ```sql
   SELECT * FROM invoices WHERE id = ? AND owner_id = ?
   ```
2. **Short-term:** Audit all other object types (`/orders/`, `/documents/`, `/users/`) for the same pattern
3. **Long-term:** Implement a centralized authorization layer that enforces object ownership for all API resources

**References:**
- [OWASP API Security Top 10: BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

---

## Timeline

| Date | Event |
|------|-------|
| [DATE] | Vulnerability discovered |
| [DATE] | Initial report submitted |
| [DATE] | Awaiting triage |
```

---

## PLATFORM-SPECIFIC TIPS

### HackerOne
- Use the CVSS calculator built into the submission form
- Attach screenshots inline, not as ZIP
- Keep title under 100 characters
- Mark as "Needs more info" explicitly if you need something from them
- Set "Weakness" field correctly — it affects triage routing

### Bugcrowd
- Use their VRT (Vulnerability Rating Taxonomy) for severity
- Attach a video PoC for complex chains — significantly faster triage
- P1-P4 maps to Critical-Low; don't confuse with CVSS

### Intigriti
- European programs — GDPR impact is weighted heavily
- They have an internal review before disclosure to company

---

## REPORT ANTI-PATTERNS (Don't Do These)

- ❌ "I found a vulnerability that could allow an attacker to..."  — Be specific
- ❌ Reporting without PoC — Instant N/A
- ❌ Exaggerating severity — Damages credibility, gets downgraded
- ❌ Walls of text — Use headers and numbered steps
- ❌ Including real victim data in report — GDPR/legal issue
- ❌ "This is a critical vulnerability!!!" — Let the CVSS score speak
- ❌ Submitting within minutes of finding — Validate thoroughly first
- ❌ Duplicate checking — Search for the bug on Hacktivity first
