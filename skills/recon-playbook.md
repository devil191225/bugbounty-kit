# Recon Methodology Playbook — Scope to First Finding
> Source: Top researcher workflows, kit recon.md expanded | RAG Knowledge Base | Full detail preserved
> Related: `recon.md` (tool commands), `program-intelligence.md`, `cloud-enum.md`

---

## Overview

`recon.md` covers tool commands. This playbook covers **workflow** — the systematic sequence from scope document to ranked attack surface to first validated finding. Passive before active. Map before attack.

**Target output:** Ranked list of endpoints/features with assigned vuln classes and test priority.

---

## Phase 0 — Scope Lock (15 minutes)

```
INPUT:  SCOPE.md / program policy page
OUTPUT: scope-locked.txt with IN/OUT assets, restrictions, test accounts

Steps:
1. Parse every in-scope domain, IP range, app, API, mobile package
2. Note wildcard scope (*.target.com)
3. Record exclusions and testing limits
4. Obtain/create test accounts (2 users minimum for IDOR/auth)
5. python3 tools/scope_checker.py <url> — verify before any request
6. Create session folder: sessions/YYYY-MM-DD/target/
```

**Stop condition:** Cannot confirm asset in scope → do not proceed.

---

## Phase 1 — Passive Recon (Zero Target Interaction)

```
OUTPUT: passive-intel.txt — subdomains, tech stack, leaked secrets, historical URLs

1.1 Certificate Transparency
    crt.sh → subdomains list
    Compare against known scope list — find NEW subs

1.2 Passive DNS / Historical
    SecurityTrails, ViewDNS (if available)
    Wayback Machine: waybackurls target.com

1.3 GitHub/GitLab Dorking
    "{target}" filename:.env
    "{target}" API_KEY
    org:target-org path:.github/workflows
    → ci-cd-attacks.md if workflows found

1.4 Shodan/Censys (API keys in .env)
    ssl.cert.subject.cn:target.com
    org:"Target Corp"

1.5 Google Dorking
    site:*.target.com -www
    site:target.com ext:pdf | ext:docx (metadata leaks)
    site:target.com inurl:admin | inurl:api | inurl:graphql

1.6 Hacktivity / Prior Art
    site:hackerone.com/reports "target.com"
    Note duped vuln classes — avoid, find variants

1.7 Mobile App Store (if in scope)
    APK/IPA download for static analysis
    Deep link schemes in manifest
```

**Time budget:** 30-60 min for medium scope. Do NOT skip — prevents wasted active testing on OOS assets.

---

## Phase 2 — Active Discovery (Light Touch)

```
OUTPUT: live-hosts.txt, endpoints.txt, tech-stack.txt

2.1 Subdomain Validation
    cat subs.txt | httpx -silent -status-code -title -tech-detect -o live.txt

2.2 Content Discovery (per live host)
    katana -u https://target.com -d 3 -jc -o crawl.txt
    gau target.com >> urls.txt
    ffuf -u https://target.com/FUZZ -w wordlist -mc 200,301,302,403

2.3 Parameter Discovery
    /param-discover <url> or Arjun/x8
    Hidden params = hidden vulns

2.4 JavaScript Analysis
    Extract endpoints from JS bundles:
    LinkFinder, manual grep for /api/, graphql, fetch(
    /secrets-hunt --js-bundle <dir>
    → leads to hardcoded keys, internal URLs for SSRF

2.5 API Discovery
    /swagger, /api-docs, /graphql, /v1/, /v2/
    GraphQL introspection query
    OpenAPI spec download → map all endpoints

2.6 Technology Fingerprint
    Wappalyzer, httpx tech-detect
    Stack → vuln class priority (see program-intelligence.md)
```

**Time budget:** 1-2 hours. Stop when diminishing returns on new endpoints.

---

## Phase 3 — Attack Surface Ranking

```
OUTPUT: attack-surface-ranked.md

Score each endpoint/feature:

| Endpoint | Auth | Method | Params | Priority | Vuln classes |
|----------|------|--------|--------|----------|--------------|
| /api/users/{id} | User | GET | id | P1 | IDOR |
| /import?url= | Admin | POST | url | P1 | SSRF |
| /oauth/callback | None | GET | code,state | P1 | OAuth |
| /upload | User | POST | file | P2 | File upload |
| /search?q= | None | GET | q | P2 | XSS |

Priority formula:
  P1 = user-controlled input + sensitive action + auth boundary
  P2 = user input + reflected output or state change
  P3 = info disclosure, lower impact
  P4 = static, marketing, already duped classes
```

### Automatic P1 Triggers
- Object IDs in URL/body → IDOR
- URL/fetch/import params → SSRF
- File upload → RCE path
- OAuth/SAML endpoints → auth bypass
- Admin paths → access control
- GraphQL → introspection/batching
- Webhook/callback URLs → SSRF
- Password reset → logic flaws

---

## Phase 4 — Targeted Testing (Hypothesis-Driven)

**NOT scatter-shot.** One hypothesis per endpoint. Max 2 attempts before pivot.

```
For each P1 endpoint:
  1. State hypothesis: "id param allows horizontal IDOR"
  2. Single test: User A token → User B's id
  3. Evaluate: confirmed / dead / unclear
  4. If confirmed → /validate → /chain
  5. If dead twice → mark done, next endpoint
```

### Testing Order by Stack

```
Default order (adjust per recon):
1. Auth boundaries (IDOR, access control)
2. Injection (SQLi, XSS in highest-traffic params)
3. SSRF (url/webhook/import params)
4. OAuth/SAML (if present)
5. Business logic (race, price, workflow skip)
6. File upload
7. Advanced (smuggling, cache poison, deserialization)
```

Use Autorize (Burp) for IDOR at scale on API endpoints.

---

## Phase 5 — Chain Exploration

When ANY finding confirmed — even Low:
```
/chain
→ bug-chains.md checklist
→ Can this enable another attack?
→ Test chain end-to-end before reporting
```

---

## Phase 6 — Validation & Report

```
/validate  — 7-Question Gate
/report    — platform template from report-templates.md
/remember  — log pattern to hunt-memory
```

---

## Session Folder Structure

```
sessions/2026-06-10/target/
├── scope-locked.txt
├── passive-intel.txt
├── live-hosts.txt
├── endpoints.txt
├── attack-surface-ranked.md
├── findings/
│   └── IDOR-001-evidence.txt
└── notes.md
```

---

## Time Budgets by Target Size

| Scope size | Phase 1 | Phase 2 | Phase 3-4 | Total before first report |
|---|---|---|---|---|
| Single app | 30m | 1h | 2h | 3-4h |
| Medium (*.domain) | 1h | 2h | 4h | 1 day |
| Large enterprise | 2h | 4h | ongoing | multi-day |

---

## Integration with Kit Commands

| Phase | Command |
|---|---|
| 0 | `/scope <asset>` |
| 1-2 | `/recon target.com` |
| 3 | `/surface target.com` |
| 4 | `/hunt target.com`, `/param-discover` |
| 5 | `/chain` |
| 6 | `/validate`, `/report` |
| Intel | `/intel target.com` |
| Resume | `/pickup target.com` |

---

## Anti-Patterns

- Running nuclei on entire scope before understanding app (noisy, misses logic bugs)
- Testing XSS before mapping auth boundaries on API-heavy targets
- Grinding one endpoint for 40+ variations (token discipline)
- Skipping passive recon → testing OOS subdomain
- Reporting without second user account IDOR verification

---

## First Finding Checklist

```
[ ] Confirmed in-scope
[ ] Reproducible with exact steps
[ ] Impact articulated (not just "vulnerable parameter")
[ ] Tested with 2 accounts / roles where applicable
[ ] Checked hacktivity for dup
[ ] Chain explored (/chain)
[ ] Evidence saved to sessions/ folder
[ ] /validate passed
```

---

## Related Files

- `recon.md` — tool commands and one-liners
- `program-intelligence.md` — program selection
- `web-vulns.md` — vuln class reference
- `api-testing.md` — API-specific testing
- `cloud-enum.md` — cloud asset discovery
