# CVSS v3.1 Scoring Guide — Complete Reference
> Source: FIRST.org CVSS v3.1 Specification | RAG Knowledge Base | Full detail preserved
> Version: CVSS 3.1 | Published: 2019

---

## Overview

CVSS (Common Vulnerability Scoring System) v3.1 provides a standardized framework for assessing the severity of vulnerabilities. It produces scores from 0.0 to 10.0 organized into severity bands.

Bug bounty programs use CVSS as a baseline for payout tiers, though programs frequently adjust based on business impact and actual exploitability context.

---

## Score Ranges and Severity Bands

| Severity | Score Range |
|---|---|
| None | 0.0 |
| Low | 0.1 – 3.9 |
| Medium | 4.0 – 6.9 |
| High | 7.0 – 8.9 |
| Critical | 9.0 – 10.0 |

---

## Base Metric Groups

CVSS v3.1 has three metric groups:
- **Base** — inherent properties of a vulnerability (doesn't change with time or environment)
- **Temporal** — changes over time (exploit availability, patch status) — rarely used in bug bounty
- **Environmental** — organization-specific modifiers — rarely used in bug bounty

Bug bounty focuses entirely on **Base Score**.

---

## Base Metrics — All Values with Numeric Weights

### Exploitability Metrics

#### Attack Vector (AV)

| Value | Code | Numeric Score | Description |
|---|---|---|---|
| Network | N | 0.85 | Remotely exploitable over internet; no physical access/network adjacency needed |
| Adjacent | A | 0.62 | Requires access to same logical/physical network segment (VLAN, Bluetooth, LAN, WiFi) |
| Local | L | 0.55 | Requires local account access or authenticated local system access |
| Physical | P | 0.20 | Requires physical interaction with the target hardware |

**Bug Bounty Use:**
- Web vulnerabilities → AV:N (almost always)
- Local file path traversal requiring local shell → AV:L
- Bluetooth/WiFi attacks → AV:A
- Hardware tampering → AV:P

#### Attack Complexity (AC)

| Value | Code | Numeric Score | Description |
|---|---|---|---|
| Low | L | 0.77 | No special conditions required; attack is repeatable, reliable, and consistent |
| High | H | 0.44 | Success depends on conditions beyond attacker's control (race conditions, specific non-default configuration, timing) |

**Bug Bounty Use:**
- Standard injection, IDOR, missing auth → AC:L
- Race condition exploitation → AC:H
- Exploit requiring specific non-default config → AC:H
- Blind SSRF with callback → AC:L (reliable even if asynchronous)

#### Privileges Required (PR)

| Value | Code | Numeric (Scope:Unchanged) | Numeric (Scope:Changed) | Description |
|---|---|---|---|---|
| None | N | 0.85 | 0.85 | No authentication or authorization required |
| Low | L | 0.62 | 0.68 | Low-privilege account (regular user, guest) required |
| High | H | 0.27 | 0.50 | Administrative control required |

**Important:** PR numeric values **change** when Scope = Changed.

**Bug Bounty Use:**
- Unauthenticated endpoint → PR:N
- Logged-in user account → PR:L
- Admin-only endpoint exploited → PR:H (but usually this means it's not a vuln)
- Self-XSS (requires own account) → PR:L or PR:H

#### User Interaction (UI)

| Value | Code | Numeric Score | Description |
|---|---|---|---|
| None | N | 0.85 | Exploit executes without any victim action |
| Required | R | 0.62 | Victim must perform specific action (click link, open file, visit page) |

**Bug Bounty Use:**
- Stored XSS auto-fires on page load → UI:N
- Reflected XSS requires victim to click link → UI:R
- CSRF requires victim to visit malicious page → UI:R
- SSRF triggered by authenticated request → UI:N
- Phishing requires victim interaction → UI:R

### Impact Metrics

#### Scope (S)

| Value | Code | Description |
|---|---|---|
| Unchanged | U | Vulnerability impact is confined to the vulnerable component's security authority |
| Changed | C | Vulnerability causes impact beyond the vulnerable component (crosses security boundaries) |

**Scope Changed Examples:**
- XSS in a JavaScript sandbox that reads data from the parent page (different origin)
- Container escape to host OS
- Hypervisor escape to host hardware
- SSRF that accesses cloud metadata (exits the application's security boundary to cloud control plane)
- Stored XSS on one user that affects other users (the "other user's browser" is the new security context)

**Scope Unchanged Examples:**
- SQLi that reads the application's own database (same security boundary)
- Path traversal reading files on the application's own server
- Most web application vulnerabilities where impact stays within the app

**Bug Bounty Common Mistake:** Assigning S:Changed when impact stays within the same application. S:Changed is specifically for cross-boundary impact.

#### Confidentiality Impact (C)

| Value | Code | Numeric Score | Description |
|---|---|---|---|
| High | H | 0.56 | Total loss of confidentiality — all data in vulnerable component accessible |
| Low | L | 0.22 | Some access to data but limited scope or content |
| None | N | 0.00 | No impact on confidentiality |

**Examples:**
- SQLi reading full database → C:H
- IDOR reading one user record → C:L
- SSRF to internal metadata → C:H (all IAM credentials accessible)
- XSS reading document.cookie → C:L (partial — just session cookie)
- Subdomain takeover (no auth flows) → C:N or C:L

#### Integrity Impact (I)

| Value | Code | Numeric Score | Description |
|---|---|---|---|
| High | H | 0.56 | Total loss of integrity — all data in vulnerable component can be modified |
| Low | L | 0.22 | Some modification possible but limited scope or effect |
| None | N | 0.00 | No impact on integrity |

**Examples:**
- SQLi with DML privileges → I:H
- IDOR allowing update of another user's data → I:H (that user's data)
- Stored XSS injecting content → I:L
- Information disclosure only → I:N
- Self-XSS → I:N (no other users affected)

#### Availability Impact (A)

| Value | Code | Numeric Score | Description |
|---|---|---|---|
| High | H | 0.56 | Total loss of availability — component completely unavailable |
| Low | L | 0.22 | Reduced performance or intermittent unavailability |
| None | N | 0.00 | No impact on availability |

**Examples:**
- DoS via resource exhaustion causing full outage → A:H
- Rate limit bypass causing degraded performance → A:L
- Most injection vulnerabilities without DoS intent → A:N
- ReDoS causing partial slowdown → A:L

---

## Scoring Formulas

### Step 1 — Impact Sub-Score (ISS)
```
ISS = 1 - [(1 - C) × (1 - I) × (1 - A)]
```

### Step 2 — Impact Score

**If Scope = Unchanged:**
```
Impact = 6.42 × ISS
```

**If Scope = Changed:**
```
Impact = 7.52 × [ISS - 0.029] - 3.25 × [ISS - 0.02]^15
```

### Step 3 — Exploitability Score
```
Exploitability = 8.22 × AV × AC × PR × UI
```

### Step 4 — Base Score

**If Scope = Unchanged:**
```
If Impact = 0: BaseScore = 0
Else: BaseScore = Roundup(Minimum[(Impact + Exploitability), 10])
```

**If Scope = Changed:**
```
If Impact = 0: BaseScore = 0
Else: BaseScore = Roundup(Minimum[1.08 × (Impact + Exploitability), 10])
```

**Roundup** function: rounds to the nearest tenth (one decimal place), rounding up.

---

## Worked Examples

### Example 1: Unauthenticated Network RCE — Full Compromise

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

```
Metrics: AV=0.85, AC=0.77, PR=0.85, UI=0.85, C=0.56, I=0.56, A=0.56

ISS = 1 - [(1-0.56)(1-0.56)(1-0.56)] = 1 - (0.44^3) = 1 - 0.085 = 0.915

Impact (S:U) = 6.42 × 0.915 = 5.874

Exploitability = 8.22 × 0.85 × 0.77 × 0.85 × 0.85 = 3.887

BaseScore = Roundup(min(5.874 + 3.887, 10)) = Roundup(9.761) = 9.8 (Critical)
```

### Example 2: SQL Injection — Full DB Read, No Auth

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

```
ISS = 1 - [(0.44)(1)(1)] = 0.56
Impact = 6.42 × 0.56 = 3.595
Exploitability = 8.22 × 0.85 × 0.77 × 0.85 × 0.85 = 3.887
BaseScore = Roundup(7.482) = 7.5 (High)
```

### Example 3: SSRF to AWS IMDS (IAM Credential Theft)

**Scope = Changed** (exits application boundary to cloud control plane)

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

```
Score: 10.0 (Critical)
```

Scope:Changed + full C:H/I:H/A:H + no auth + no interaction = maximum score.

### Example 4: Stored XSS — Authenticated User, Scope Changed

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`

```
Metrics: AV=0.85, AC=0.77, PR=0.68 (S:C Low), UI=0.62, C=0.22, I=0.22, A=0

ISS = 1 - [(0.78)(0.78)(1)] = 1 - 0.608 = 0.392

Impact (S:C) = 7.52 × (0.392-0.029) - 3.25 × (0.392-0.02)^15
            = 7.52 × 0.363 - 3.25 × 0.372^15
            ≈ 2.729 - 0.002 = 2.727

Exploitability = 8.22 × 0.85 × 0.77 × 0.68 × 0.62 = 2.268

BaseScore = Roundup(1.08 × (2.727 + 2.268)) = Roundup(1.08 × 4.995) = Roundup(5.395) = 5.4 (Medium)
```

### Example 5: Reflected XSS — No Auth, User Interaction Required

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Score: 6.1 (Medium)**

### Example 6: IDOR — Read Another User's Order

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`

```
ISS = 1 - [(0.78)(1)(1)] = 0.22
Impact = 6.42 × 0.22 = 1.412
Exploitability = 8.22 × 0.85 × 0.77 × 0.62 × 0.85 = 2.789
BaseScore = Roundup(4.201) = 4.3 (Medium)
```

### Example 7: IDOR with Write Access (Modify Another User's Data)

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`

**Score: 7.1 (High)**

### Example 8: Local Privilege Escalation (Kernel Exploit)

**Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

**Score: 7.8 (High)**

(AV:L reduces score significantly despite full C/I/A impact)

### Example 9: Subdomain Takeover (Full Control + Cookie Theft Possible)

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`

**Score: ~7.5 (High)**

### Example 10: Missing DMARC (Email Spoofing)

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`

**Score: 5.4 (Medium)** — Requires victim to believe spoofed email (UI:R).

### Example 11: Hardcoded API Key in Public Repo

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Score: 9.8 (Critical)** — if key gives full access to production systems.

---

## Common Vulnerability Type Scoring Reference

| Vulnerability | Typical Vector | Typical Score |
|---|---|---|
| RCE (unauth, network) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 Critical |
| SQLi (unauth, full DB read/write) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 Critical |
| SQLi (read-only, unauth) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 High |
| SSRF → cloud metadata | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 Critical |
| SSRF → blind (no creds) | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 Medium |
| Stored XSS (unauth trigger) | AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N | 6.1 Medium |
| Stored XSS (admin panel) | AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N | 5.4 Medium |
| Reflected XSS | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 Medium |
| DOM XSS | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 Medium |
| CSRF (account changes) | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N | 6.5 Medium |
| IDOR (read) | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N | 4.3 Medium |
| IDOR (write/delete) | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N | 7.1 High |
| BFLA (admin endpoint unauth) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 Critical |
| Path Traversal (read /etc/passwd) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 High |
| OS Command Injection | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 Critical |
| XXE → file read | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 High |
| SSTI → RCE | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 Critical |
| File Upload → RCE | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 High |
| Insecure Deserialization → RCE | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 Critical |
| JWT alg:none bypass | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 Critical |
| Open Redirect | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N | 5.4 Medium |
| Subdomain Takeover | AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N | ~7.5 High |
| Missing DMARC | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N | 5.4 Medium |
| Hardcoded API key (full access) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 Critical |
| Sensitive data in error messages | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 Medium |
| Missing rate limiting (brute force) | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N | 5.3 Medium |
| Default credentials | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 Critical |
| Race condition (limit bypass) | AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N | 6.3 Medium |

---

## How Bug Bounty Programs Use CVSS

**Typical Payout Mapping:**

| Severity | CVSS Range | Typical HackerOne Payout Range |
|---|---|---|
| Informational/None | 0.0 | $0 |
| Low | 0.1 – 3.9 | $100 – $500 |
| Medium | 4.0 – 6.9 | $500 – $2,500 |
| High | 7.0 – 8.9 | $2,500 – $10,000 |
| Critical | 9.0 – 10.0 | $10,000 – $100,000+ |

**Programs Often Override CVSS Based On:**
1. **Business impact** — IDOR on healthcare platform exposing PHI may be scored higher than CVSS due to HIPAA/GDPR risk
2. **Asset criticality** — Admin system vs. marketing page changes payout even for same CVSS
3. **Exploitability** — If bug requires very specific conditions not in Base Score, programs downgrade
4. **Duplicate threshold** — First reporter gets full bounty; later reporters may get partial
5. **Fix complexity** — Systemic bugs (e.g., all endpoints lack auth) may get single payout

**CVSS Is a Floor, Not a Ceiling:**
Programs can and do pay more than CVSS suggests when:
- Business logic impact is severe (financial fraud, mass ATO)
- Regulatory implications (GDPR, HIPAA, PCI-DSS)
- Chain of vulnerabilities amplifies impact

---

## Common Scoring Mistakes

| Mistake | Correct Approach |
|---|---|
| S:Changed for all web bugs | S:Changed only when crossing security boundaries (different origin, different system) |
| C:H when only partial data disclosed | C:L unless all data in the vulnerable component is accessible |
| AV:Network for bugs requiring local shell | AV:Local for bugs requiring authenticated local access |
| Conflating CIA independently | Each C, I, A scored separately based on that dimension's impact |
| Forgetting PR changes with S:Changed | PR:Low = 0.62 (S:U) but 0.68 (S:C); PR:High = 0.27 (S:U) but 0.50 (S:C) |
| I:H for reflected XSS with no content change | Reflected XSS typically I:L unless modifying persistent state |
| A:H for rate limit bypass | Rate limit bypass rarely causes full unavailability → A:L or A:N |

---

## CVSS Vector String Format

Always include the full CVSS vector string in reports:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
       ^   ^   ^   ^   ^   ^   ^   ^   ^   ^
       |   |   |   |   |   |   |   |   |   Availability
       |   |   |   |   |   |   |   |   Integrity
       |   |   |   |   |   |   |   Confidentiality
       |   |   |   |   |   |   Scope
       |   |   |   |   |   User Interaction
       |   |   |   |   Privileges Required
       |   |   |   Attack Complexity
       |   |   Attack Vector
       |   CVSS version
       Prefix
```

**Calculator:** https://www.first.org/cvss/calculator/3.1

---

## Temporal and Environmental Metrics (Reference)

These are rarely used in bug bounty but included for completeness.

### Temporal Metrics

| Metric | Values | Numeric |
|---|---|---|
| Exploit Code Maturity (E) | Not Defined (1.0), Unproven (0.91), Proof-of-Concept (0.94), Functional (0.97), High (1.0) | Multiply base |
| Remediation Level (RL) | Not Defined (1.0), Official Fix (0.87), Temporary Fix (0.90), Workaround (0.95), Unavailable (1.0) | Multiply base |
| Report Confidence (RC) | Not Defined (1.0), Unknown (0.92), Reasonable (0.96), Confirmed (1.0) | Multiply base |

### Environmental Metrics

Allow organizations to customize scores based on their specific environment:
- Security Requirements (CR, IR, AR): Low/Medium/High
- Modified Base Metrics: Override any Base metric with environment-specific value
