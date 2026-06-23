# Report Templates — Platform-Specific Submission Formats
> Source: HackerOne, Intigriti, Bugcrowd, Immunefi submission standards | RAG Knowledge Base | Full detail preserved
> Related: `report-writer.md`, `cvss-guide.md`, `program-intelligence.md`

---

## Universal Principles (All Platforms)

1. **Title:** [Vuln type] on [location] allows [impact]
2. **First line:** Business impact — what attacker achieves
3. **Repro:** Numbered steps, copy-paste HTTP requests
4. **Evidence:** Screenshots/response snippets, redact PII
5. **Severity:** CVSS 3.1 vector + calculated score
6. **Remediation:** Specific fix, not generic advice
7. **No speculation** — "attacker can" not "attacker might"

---

## HackerOne Template

```markdown
## Summary
[2-3 sentences: vulnerability + impact. Lead with what attacker achieves.]

## Steps To Reproduce
1. Log in as User A (test account: user-a@test.com)
2. Send the following request:
```
GET /api/v1/users/USER_B_ID HTTP/2
Host: api.target.com
Authorization: Bearer [USER_A_TOKEN]
```
3. Observe response contains User B's email, phone, and address

## Impact
An authenticated attacker can enumerate and access PII for all [X] users
by iterating the user ID parameter. This violates [regulation if applicable]
and enables targeted phishing and account takeover via password reset.

## Supporting Material/References
- Screenshot: idor-proof-redacted.png
- CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5 High)

## Remediation
Implement server-side authorization check verifying request.user.id == resource.owner_id
before returning user object. Return 403 for unauthorized access.

## Weakness
CWE-639: Authorization Bypass Through User-Controlled Key
```

### HackerOne Severity Guide
| H1 Severity | When to use |
|---|---|
| Critical | RCE, mass data breach, auth bypass all users, financial loss |
| High | IDOR PII, stored XSS, SSRF internal, significant ATO |
| Medium | Limited IDOR, reflected XSS, CSRF on state change |
| Low | Minor info disclosure, low-impact logic flaw |
| None | Self-XSS alone, missing headers (if accepted at all) |

### HackerOne Chain Report Title
```
Chained: Open Redirect + OAuth redirect_uri bypass leads to Account Takeover
```

---

## Intigriti Template

Intigriti triage prefers concise impact-first writing. EU programs often stricter on GDPR framing.

```markdown
## Description
[Impact statement first]

A broken access control on `GET /api/users/{id}` allows any authenticated user
to retrieve personal data belonging to other users.

## Proof of Concept
**Request:**
[Full HTTP request]

**Response (redacted):**
[Relevant JSON snippet]

**Video PoC:** [link if complex chain]

## Impact
- Personal data exposure: email, phone, full name
- Affected users: all platform users (~[N] if estimable)
- Attack complexity: low — single HTTP request
- No user interaction required

## Recommended Fix
Enforce object-level authorization. Verify session user owns requested resource.

## CVSS
Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
Score: 6.5 (Medium on Intigriti scale — verify program-specific mapping)
```

### Intigriti Severity Notes
- Intigriti uses Exceptional/Critical/High/Medium/Low
- GDPR-relevant findings: explicitly state personal data categories exposed
- Some programs cap certain classes — check program rules

---

## Bugcrowd Template

Bugcrowd VRT aligns closely with HackerOne.

```markdown
## Bug Title
IDOR on User API Exposes PII

## Target
https://api.target.com (in-scope per program brief v2.1)

## Vulnerability Details
[Technical description — 1 paragraph]

## Steps to Reproduce
1. [Step]
2. [Step]
3. [Step]

## Proof of Concept
[HTTP request/response or screenshot]

## Impact
[Business impact paragraph]

## Recommended Fix
[Specific remediation]

## References
- CWE-639
- OWASP A01:2021 Broken Access Control
```

### Bugcrowd P5/P4 Notes
- P5 (Informational) common for self-XSS, missing headers
- Always attempt chain before accepting P5 classification

---

## Immunefi Template (Web3)

Immunefi requires fund-loss quantification for Critical/High.

```markdown
## Brief/Intro
[One sentence: vulnerability + maximum fund loss scenario]

## Vulnerability Details
[Smart contract or web app technical details]

## Impact Details
**Funds at risk:** [X ETH / $Y USD]
**Attack cost:** [Gas needed]
**Affected contracts:** [addresses]

## Proof of Concept
[Foundry/Hardhat test or step-by-step for web vuln]

## Recommended Mitigation Steps
[Specific code fix or access control change]

## References
[Similar incidents, SWC IDs for smart contracts]
```

### Immunefi Severity
- Critical: direct fund loss, governance takeover
- High: conditional fund loss, significant protocol disruption
- Web2 bugs on Immunefi programs: follow web template but emphasize financial impact

---

## Chained Vulnerability Template (All Platforms)

```markdown
## Summary
Chained vulnerabilities [A] and [B] achieve [Critical Impact] —
single finding reported at highest severity.

## Chain Overview
Finding A (Open Redirect, /logout?next=) +
Finding B (OAuth redirect_uri accepts path-relative URL) =
Authorization code theft → full account takeover

## Step-by-Step Reproduction

### Step 1 — Confirm Open Redirect
[Request/response]

### Step 2 — OAuth Code Theft
Crafted URL:
https://target.com/oauth/authorize?client_id=X&redirect_uri=/logout?next=https://attacker.com&response_type=code

### Step 3 — Account Takeover
Exchange stolen code at token endpoint → access victim account

## Impact
Complete account takeover of any user clicking crafted link.
No phishing credentials required.

## Severity Justification
Individual findings: Medium (redirect) + High (OAuth) = Critical chain (ATO)

## CWE
CWE-601, CWE-287
```

---

## CVSS Block (Copy-Paste Ready)

Always include calculator link: https://www.first.org/cvss/calculator/3.1

```markdown
## CVSS 3.1
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
**Score:** 9.1 Critical

| Metric | Value | Rationale |
|--------|-------|-----------|
| AV | Network | Exploitable remotely |
| AC | Low | No special conditions |
| PR | None | Unauthenticated |
| UI | None | No victim interaction |
| S | Unchanged | Impact within same security authority |
| C | High | Full PII access |
| I | High | Can modify user data |
| A | None | No availability impact |
```

See `cvss-guide.md` for full metric reference and worked examples.

---

## Evidence Standards

### HTTP Request Format
```
POST /api/endpoint HTTP/2
Host: target.com
Cookie: session=abc123
Content-Type: application/json
Content-Length: 45

{"id": 12345, "action": "delete"}
```

### Screenshot Rules
- Redact: real user emails, tokens, session IDs (partial OK: `eyJ...redacted`)
- Show: status code, relevant response field, URL bar
- Annotate: arrows/boxes on key fields

### Video PoC (When to Use)
- Multi-step chains (OAuth, SAML XSW)
- Race conditions
- CSRF with user interaction simulation
- Keep under 2 minutes, no background music

---

## Severity Dispute Response Template

```markdown
Thank you for the triage review. I'd like to respectfully clarify the impact:

1. [Specific impact triage may have missed]
2. [Business context — e.g., admin access, PII scale]
3. Updated CVSS vector: [vector] — Score: [X.X]

I've attached additional evidence demonstrating [specific claim].
Happy to provide a live walkthrough if helpful.
```

---

## N/A / Duplicate Response Template

If YOUR report marked dup:
```markdown
Thank you. Could you share the original report number so I can identify
the delta? My finding differs in [endpoint/version/impact] because [specific reason].
```

If closing as informative:
Accept gracefully unless chain potential unexplored.

---

## Platform-Specific Fields

| Platform | Extra fields |
|---|---|
| HackerOne | Weakness type dropdown, CVE field (optional) |
| Intigriti | Category, endpoint URL, type selector |
| Bugcrowd | VRT category, Bug URL |
| Immunefi | Asset type (smart contract address), fork block |

---

## Report Quality Checklist

```
[ ] Title describes impact not mechanism
[ ] Reproducible by triager without guessing
[ ] All requests include Host, method, headers
[ ] Impact paragraph answers "so what?"
[ ] CVSS vector included and accurate
[ ] CWE/OWASP reference included
[ ] Remediation is specific
[ ] In-scope asset explicitly stated
[ ] Chain tested end-to-end if chained report
[ ] No "could/might/potentially" language
[ ] Evidence files attached and referenced
```

---

## Related Files

- `report-writer.md` — principles and CVSS quick reference
- `cvss-guide.md` — full CVSS 3.1 specification
- `program-intelligence.md` — triage psychology, dup avoidance
- `bug-chains.md` — chain documentation template
- `templates/finding.md` — kit internal finding template
