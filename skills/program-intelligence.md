# Program Intelligence — Bug Bounty Meta-Strategy
> Source: HackerOne VRT, disclosed report patterns, top researcher methodology | RAG Knowledge Base | Full detail preserved
> Related: `recon-playbook.md`, `report-templates.md`, `cvss-guide.md`

---

## Overview

Technical skill alone doesn't maximize payout. Program selection, scope reading, dup avoidance, and triage psychology determine ROI. This file is the meta-layer — how to pick targets and position findings for acceptance at highest severity.

---

## Reading Scope Documents

### First 5 Minutes on Any Program

```
[ ] What's IN scope — exact domains, apps, mobile apps, API bases?
[ ] What's OUT — third-party, staging, "corporate site only marketing"?
[ ] Asset tiers — do they pay more for core vs subsidiary?
[ ] Testing restrictions — no DoS, no social engineering, no automated scanning limits?
[ ] Safe harbor — legal protection for good-faith testing?
[ ] Credential requirements — need test accounts? how to obtain?
[ ] Excluded vuln types — self-XSS, missing headers, SPF without PoC?
[ ] Recent scope changes — acquisitions = new untested surface
```

### High-Value Scope Signals

| Signal | Why |
|---|---|
| Recent acquisition listed | New integration bugs, SSO misconfig |
| `*.target.com` wildcard | Subdomain takeover, wide surface |
| API explicitly in scope | IDOR, BOLA, GraphQL |
| Mobile apps listed | Harder to test = less competition |
| "Any subdomain" + many subs | Recon pays off |
| New program (<90 days) | Low dup rate |
| Recent major release/changelog | Fresh code, new features |
| CI/CD repos public (GitLab/GitHub) | Supply chain surface |

### Low-ROI Scope Signals

| Signal | Why |
|---|---|
| "Core domain only" + heavily tested program | Saturated |
| Self-XSS explicitly OOS | Chains required |
| "Best practices" exclusions | Headers, cookie flags N/A |
| Static marketing site only | Limited attack surface |
| Duplicate-prone: SPF/DMARC without impact | Usually N/A |

---

## Program Selection Framework

### Score Each Program (1-5)

| Factor | Weight | Score |
|---|---|---|
| Scope breadth | 25% | |
| Program age (newer = better) | 20% | |
| Average bounty (check disclosed) | 20% | |
| Response time / reputation | 15% | |
| Tech stack match to your skills | 10% | |
| Competition (hacktivity frequency) | 10% | |

### Under-Hunted Signals
- Program launched recently on platform
- Scope expanded in last 30 days
- Company IPO/acquisition/funding news
- No public hacktivity in 60+ days on major assets
- Beta features behind feature flag (check JS for `beta`, `preview`, `labs`)

### Saturated Programs (Still Huntable)
Focus on:
- New subdomains from CT logs not in old reports
- API v2/v3 while reports cover v1
- Mobile app updates
- Post-acquisition integration domains
- AI/LLM features (new, immature)

---

## What Gets Duped vs Paid

### High Dup Rate (Avoid Grinding)
- Missing security headers alone
- SSL/TLS configuration (unless direct impact)
- SPF/DMARC "missing" without email spoof PoC to inbox
- Self-XSS without chain
- Logout CSRF
- Username enumeration on login (many programs N/A)
- Version disclosure
- Clickjacking on non-sensitive pages

### Usually Paid (With Good PoC)
- IDOR with data access proof
- Auth bypass (any form)
- Stored XSS affecting other users
- SSRF with internal access proof
- SQLi with data extraction
- OAuth redirect bypass → ATO chain
- Subdomain takeover with cookie/OAuth impact
- RCE (file upload, deserialization, command injection)
- Chains elevating Medium → Critical

### Severity Disputes — Win Arguments
- **Business impact > technical novelty** — "attacker can access all customer PII" beats "interesting edge case"
- **Demonstrate real data** — redact, don't theorize
- **Show no user interaction** when true — raises severity
- **Compare to VRT** — cite HackerOne VRT category for your finding type
- **CVSS calculated correctly** — use `cvss-guide.md`

---

## HackerOne VRT (Vulnerability Rating Taxonomy)

Use VRT to predict triage severity: https://github.com/hacker0x01/hacker101/tree/master (H1 publishes VRT)

**Common mappings:**
| Finding | VRT Category | Typical H1 Severity |
|---|---|---|
| IDOR read PII | Broken Access Control | High |
| IDOR write | Broken Access Control | High-Critical |
| SSRF internal | Server-Side Request Forgery | High-Critical |
| OAuth redirect | Improper Authentication | High-Critical |
| Stored XSS | Cross-site Scripting | High |
| SQLi | SQL Injection | Critical |
| Subdomain takeover + impact | Subdomain Takeover | Medium-High |
| CI/CD secret leak | Privilege Escalation | Critical |

Platform differences:
- **Intigriti:** Often stricter on impact proof
- **Bugcrowd:** VRT similar to H1
- **Immunefi:** Web3 — fund loss quantification required

---

## Signals During Recon

### Technology Stack → Attack Priority

| Stack | Priority tests |
|---|---|
| Java/Spring | SSTI, deserialization, SpEL injection |
| PHP | LFI, file upload, SQLi |
| Node/Express | Prototype pollution, NoSQL, template injection |
| .NET | ViewState (legacy), deserialization |
| GraphQL | Introspection, batching, IDOR |
| AWS | SSRF→IMDS, S3 misconfig |
| SAML/Okta/Azure SSO | `saml-attacks.md` full methodology |
| GitHub/GitLab in org | `ci-cd-attacks.md` |

### JavaScript Bundle Intelligence
```javascript
// Search in JS for:
/api/v
graphql
client_id
internal.
admin
debug
staging
```

---

## Time Management (Token Budget Discipline)

| Target difficulty | Max effort before pivot |
|---|---|
| Easy (CTF-style, obvious vuln class) | 3-4 focused tests |
| Medium | Structured recon → 1 exploit path → verify |
| Hard | Full systematic coverage |

**Rule:** Same angle fails twice → pivot or escalate to user. Don't grind.

---

## Dup Avoidance Workflow

```
1. Search hacktivity: site:hackerone.com/reports target.com
2. Search Google: "target.com" site:hackerone.com inurl:reports
3. Check GitHub: target.com security advisories
4. Check CVEs for their stack (nuclei, intel_engine.py)
5. /intel target.com in kit
6. If similar report exists — need NEW impact or different endpoint
```

---

## Report Positioning for Fast Triage

### Title Formula
```
[Vuln Type] on [Endpoint] allows [Impact] on [Scope Asset]
```
Good: `IDOR on /api/v2/users/{id} allows access to any user's PII including email and phone`
Bad: `Security vulnerability found`

### Lead with Impact
First sentence = what attacker achieves. Not how it works.

### Reproducibility
- Exact HTTP request (Burp copy)
- Exact steps numbered
- Screenshots with sensitive data redacted
- Video for complex chains (optional, high acceptance rate)

### What Triage Teams Reject
- "Could potentially" / "might be able to" language
- No PoC, theory only
- Out of scope asset
- Self-XSS without chain
- Scanner dump without manual validation
- Missing impact statement

---

## Engagement Types

| Type | Strategy |
|---|---|
| Public VDP | Reputation building, no payout |
| Public BBP | Balance ROI vs competition |
| Private invite | Higher trust, often better bounties |
| Live hacking events | Speed > perfection, pre-mapped scope |

---

## Legal & Ethics (Operational)

- Stay in scope — `/scope` command before touching asset
- No real user data exfil beyond PoC minimum
- No DoS unless explicitly allowed
- Stop at RCE boundary — prove with `id`/`whoami`, don't pivot internally without permission
- Responsible disclosure timelines per program policy

---

## Quick Decision Tree

```
New program found
  → Read scope (5 min)
  → Score program (table above)
  → If score < 3: skip unless specific intel
  → Passive recon (recon-playbook.md Phase 1)
  → Rank attack surface (/surface)
  → Pick highest-ROI vuln class for stack
  → Test with 2-attempt limit per angle
  → Finding? → /validate → /chain → /report
  → No finding after 2 hours on easy surface? → pivot target
```

---

## Related Files

- `recon-playbook.md` — scope to first finding workflow
- `report-templates.md` — platform-specific formats
- `cvss-guide.md` — severity scoring
- `report-writer.md` — writing principles
- `bug-chains.md` — severity amplification via chains
