# Skills Index — OWASP / CWE / MITRE Cross-Reference
> RAG Knowledge Base | Master index linking frameworks to skill files
> Use with `tools/rag_chunk.py` for retrieval metadata

**Tier key:** `SOTA` = exhaustive PortSwigger/OWASP-depth reference | `Playbook` = operational commands (real tools/paths only) | `Index` = cross-ref map | `Code-Audit` = Trail of Bits nested skills

**Accuracy:** All paths and tools in skills must exist or be standard external tools (SecLists, jwt_tool). See `.cursor/rules/no-fabrication.mdc`.

---

## Skill File Registry (Web Hunting — Top Level)

| File | Tier | Primary Topics |
|---|---|---|
| `portswigger-injection.md` | SOTA | SQLi, XSS, XXE, SSRF, cmdi, auth, IDOR, file upload |
| `portswigger-injection2.md` | SOTA | NoSQL, SSTI, cache deception, API testing |
| `portswigger-advanced.md` | SOTA | Smuggling, cache poison, GraphQL, OAuth, JWT, CORS, CSRF |
| `portswigger-extra.md` | SOTA | Path traversal, deserialization, race, DOM, clickjacking |
| `prototype-pollution.md` | SOTA | CSPP/SSPP detection, gadgets, oracles |
| `bug-chains.md` | SOTA | Chain encyclopedia (20+ patterns) |
| `oauth-oidc-advanced.md` | SOTA | OAuth/OIDC advanced attacks |
| `saml-attacks.md` | SOTA | SAML/XSW/SSO |
| `ci-cd-attacks.md` | SOTA | CI/CD pipeline attacks |
| `cloud-attacks.md` | SOTA | Cloud attack patterns, IMDS, S3 |
| `graphql-advanced.md` | SOTA | GraphQL batching, aliases, federation |
| `grpc-testing.md` | SOTA | gRPC/protobuf testing |
| `kubernetes-security.md` | SOTA | K8s/container security |
| `subdomain-takeover.md` | SOTA | Subdomain takeover |
| `browser-security.md` | SOTA | CSP, cookies, CORS, COOP |
| `email-security.md` | SOTA | SPF/DKIM/DMARC |
| `web3-blockchain.md` | SOTA | Smart contract / Web3 |
| `cvss-guide.md` | SOTA | CVSS 3.1 scoring |
| `owasp-api-top10-2023.md` | SOTA | OWASP API Top 10 2023 |
| `owasp-mobile-top10.md` | SOTA | OWASP Mobile Top 10 2024 |
| `cwe-top25-2024.md` | SOTA | CWE Top 25 2024 |
| `mitre-attack.md` | SOTA | MITRE ATT&CK (web-relevant) |
| `mitre-defend.md` | SOTA | MITRE D3FEND mapping |
| `mitre-atlas.md` | SOTA | MITRE ATLAS AI/ML |
| `nuclei-templates.md` | SOTA | Custom Nuclei templates |
| `recon-playbook.md` | Playbook | Recon workflow |
| `program-intelligence.md` | Playbook | Program selection / ROI |
| `report-templates.md` | Playbook | H1/Intigriti/Bugcrowd templates |
| `web-vulns.md` | Playbook | Core testing priority + commands |
| `api-testing.md` | Playbook | REST/API testing commands |
| `auth-bypass.md` | Playbook | Auth bypass operational |
| `logic-bugs.md` | Playbook | Business logic / race |
| `recon.md` | Playbook | Recon tool commands |
| `cloud-enum.md` | Playbook | Cloud enumeration commands |
| `chain-builder.md` | Playbook | How to chain findings |
| `report-writer.md` | Playbook | Report principles |
| `mobile-analysis.md` | Playbook | APK/IPA analysis |
| `owasp-top10-2021.md` | Index | OWASP Web Top 10 cross-ref |
| `skills-index.md` | Index | This file |
| `payloads/` | Synced | Structured payload library (separate layer) |

---

## Trail of Bits Skills (Code-Audit — Future Vision)

Nested under `skills/<package>/` — indexed in RAG with `skill_layer: code-audit`. Use when hunting shifts to **source review**, **SAST**, or **variant analysis** after black-box saturation.

| Package | Tier | Purpose | Entry |
|---|---|---|---|
| `sharp-edges/` | Code-Audit | API footguns, secure-by-default analysis | `SKILL.md` + `references/lang-*.md` |
| `codeql/` | Code-Audit | CodeQL database build, queries, SARIF | `SKILL.md` + `workflows/` |
| `variant-analysis/` | Code-Audit | Find variants of known bugs (Semgrep) | `METHODOLOGY.md` + `SKILL.md` |
| `semgrep-rule-creator/` | Code-Audit | Write Semgrep rules | `SKILL.md` |
| `constant-time-analysis/` | Code-Audit | Timing side-channel review | `SKILL.md` + language refs |
| `insecure-defaults/` | Code-Audit | Dangerous default configs | `SKILL.md` |
| `agentic-actions-auditor/` | Code-Audit | CI/agentic pipeline vectors | `SKILL.md` + `references/vector-*.md` |
| `sarif-parsing/` | Code-Audit | SARIF finding triage | `SKILL.md` |
| `burpsuite-project-parser/` | Tooling | Parse Burp project files | `SKILL.md` |
| `firebase-apk-scanner/` | Mobile-Audit | Firebase misconfig in APKs | `SKILL.md` |

**RAG query examples:**
```bash
python tools/rag_chunk.py --query "sharp edges javascript prototype pollution API"
python tools/rag_chunk.py --query "codeql build database javascript"
python tools/rag_chunk.py --query "variant analysis semgrep rule"
```

---

## OWASP Web Top 10 2021 → Skill Files

| ID | Category | Primary Skills | CWE (common) |
|---|---|---|---|
| A01:2021 | Broken Access Control | `portswigger-injection.md`, `bug-chains.md`, `api-testing.md` | CWE-639, CWE-862 |
| A02:2021 | Cryptographic Failures | `portswigger-advanced.md` (JWT), `auth-bypass.md` | CWE-327, CWE-330 |
| A03:2021 | Injection | `portswigger-injection.md`, `portswigger-injection2.md`, `payloads/` | CWE-89, CWE-79, CWE-918 |
| A04:2021 | Insecure Design | `logic-bugs.md`, `program-intelligence.md` | CWE-840 |
| A05:2021 | Security Misconfiguration | `cloud-attacks.md`, `kubernetes-security.md`, `subdomain-takeover.md` | CWE-16 |
| A06:2021 | Vulnerable Components | `ci-cd-attacks.md`, `nuclei-templates.md` | CWE-1104 |
| A07:2021 | Auth Failures | `auth-bypass.md`, `saml-attacks.md`, `oauth-oidc-advanced.md` | CWE-287 |
| A08:2021 | Software/Data Integrity | `ci-cd-attacks.md`, `web3-blockchain.md` | CWE-494 |
| A09:2021 | Logging Failures | `program-intelligence.md` | CWE-778 |
| A10:2021 | SSRF | `portswigger-injection.md`, `cloud-attacks.md`, `bug-chains.md` | CWE-918 |

---

## OWASP API Top 10 2023 → Skill Files

| ID | Category | Primary Skills |
|---|---|---|
| API1:2023 | Broken Object Level Authorization | `api-testing.md`, `graphql-advanced.md`, `bug-chains.md` |
| API2:2023 | Broken Authentication | `oauth-oidc-advanced.md`, `auth-bypass.md` |
| API3:2023 | Broken Object Property Level Authorization | `api-testing.md`, mass assignment in `logic-bugs.md` |
| API4:2023 | Unrestricted Resource Consumption | `graphql-advanced.md`, `grpc-testing.md` |
| API5:2023 | Broken Function Level Authorization | `api-testing.md`, `portswigger-injection.md` |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | `logic-bugs.md`, `bug-chains.md` |
| API7:2023 | Server Side Request Forgery | `portswigger-injection.md`, `cloud-attacks.md` |
| API8:2023 | Security Misconfiguration | `cloud-attacks.md`, `kubernetes-security.md` |
| API9:2023 | Improper Inventory Management | `recon-playbook.md`, `api-testing.md` |
| API10:2023 | Unsafe Consumption of APIs | `ci-cd-attacks.md`, `grpc-testing.md` |

---

## CWE Top 25 2024 → Skill Files (Top 15)

| Rank | CWE | Skill File |
|---|---|---|
| 1 | CWE-787 Out-of-bounds Write | `web-vulns.md`, C/C++ targets |
| 2 | CWE-79 XSS | `portswigger-injection.md`, `browser-security.md`, `payloads/xss/` |
| 3 | CWE-89 SQLi | `portswigger-injection.md`, `payloads/sqli/` |
| 4 | CWE-416 Use After Free | Native code targets |
| 5 | CWE-78 OS Command Injection | `portswigger-injection.md` |
| 6 | CWE-20 Improper Input Validation | All injection skills |
| 7 | CWE-125 OOB Read | Native code targets |
| 8 | CWE-22 Path Traversal | `portswigger-extra.md` |
| 9 | CWE-352 CSRF | `portswigger-advanced.md`, `browser-security.md` |
| 10 | CWE-434 File Upload | `portswigger-injection.md` |
| 11 | CWE-862 Missing Authorization | `bug-chains.md`, `api-testing.md` |
| 12 | CWE-476 NULL Dereference | Native code |
| 13 | CWE-287 Improper Authentication | `auth-bypass.md`, `saml-attacks.md`, `oauth-oidc-advanced.md` |
| 14 | CWE-190 Integer Overflow | `web3-blockchain.md` |
| 15 | CWE-502 Deserialization | `portswigger-extra.md` |

Full list: `cwe-top25-2024.md`

---

## MITRE ATT&CK → Skill Files (Web-Relevant)

| Tactic | Technique | Skill File |
|---|---|---|
| TA0001 Initial Access | T1190 Exploit Public-Facing Application | `portswigger-injection.md`, `web-vulns.md` |
| TA0001 | T1078 Valid Accounts | `auth-bypass.md`, `saml-attacks.md` |
| TA0006 Credential Access | T1552 Unsecured Credentials | `cloud-attacks.md`, `ci-cd-attacks.md` |
| TA0006 | T1557 Adversary-in-the-Middle | `oauth-oidc-advanced.md` |
| TA0008 Lateral Movement | T1021 Remote Services | `kubernetes-security.md` |
| TA0009 Collection | T1530 Data from Cloud Storage | `cloud-attacks.md` |
| TA0001 | T1195 Supply Chain Compromise | `ci-cd-attacks.md`, `web3-blockchain.md` |

Full reference: `mitre-attack.md`

---

## MITRE ATLAS → Skill Files (AI Targets)

| Technique | Skill File |
|---|---|
| AML.T0051 Prompt Injection | `mitre-atlas.md` |
| AML.T0058 LLM Data Leakage | `mitre-atlas.md`, `bug-chains.md` |
| AML.T0015 Poison Training Data | `mitre-atlas.md` |
| AML.T0040 ML Model Inference API | `mitre-atlas.md`, `api-testing.md` |

Full reference: `mitre-atlas.md`

---

## MITRE D3FEND → Offensive Mapping

"Absent defense = finding class" — see `mitre-defend.md` for full table.

| Missing Defense | Hunt For |
|---|---|
| Access Control Enforcement | IDOR, privilege escalation |
| Credential Hardening | Default creds, weak tokens |
| Input Validation | All injection classes |
| Software Integrity Verification | CI/CD supply chain |
| Network Isolation | SSRF to internal services |

---

## Vulnerability Class → Primary Skill (Quick Lookup)

| Vuln Class | Start Here |
|---|---|
| IDOR | `bug-chains.md` CHAIN-005/006, `api-testing.md` |
| SQLi | `portswigger-injection.md`, `payloads/sqli/` |
| XSS | `portswigger-injection.md`, `browser-security.md`, `payloads/xss/` |
| SSRF | `portswigger-injection.md`, `cloud-attacks.md`, `payloads/ssrf/` |
| SSTI | `portswigger-injection2.md`, `payloads/ssti/` |
| OAuth | `oauth-oidc-advanced.md`, `bug-chains.md` CHAIN-001 |
| SAML | `saml-attacks.md`, `bug-chains.md` CHAIN-018 |
| CI/CD | `ci-cd-attacks.md`, `bug-chains.md` CHAIN-019 |
| Subdomain takeover | `subdomain-takeover.md`, `bug-chains.md` CHAIN-009 |
| GraphQL | `graphql-advanced.md`, `portswigger-advanced.md`, `payloads/graphql/` |
| Prototype pollution | `prototype-pollution.md`, `payloads/prototype-pollution/` |
| gRPC | `grpc-testing.md` |
| K8s | `kubernetes-security.md`, `cloud-attacks.md` |
| Web3 | `web3-blockchain.md` |
| Email | `email-security.md` |
| Chains | `bug-chains.md` → `chain-builder.md` (how to report) |
| Scoring | `cvss-guide.md` |
| Reporting | `report-templates.md` → `report-writer.md` |

---

## RAG Index Coverage

```bash
python tools/rag_chunk.py --build    # Index skills + nested ToB + payloads
python tools/rag_chunk.py --stats    # Chunk counts per source
```

**Indexed:**
- All top-level `skills/*.md`
- Nested `skills/**/SKILL.md`, `METHODOLOGY.md`, `references/`, `workflows/`, `resources/`
- All `payloads/**/*.txt`

Each chunk carries `skill_layer`: `web-hunting` | `code-audit` | `mobile-audit` | `tooling`

---

Each chunk should carry:
```json
{
  "source_file": "bug-chains.md",
  "section": "CHAIN-002",
  "vuln_type": ["ssrf", "cloud"],
  "severity": "critical",
  "platform": ["web", "api"],
  "tools": ["burp", "curl"],
  "cwe": ["CWE-918"],
  "owasp_web": ["A10:2021"],
  "owasp_api": ["API7:2023"],
  "mitre_attack": ["T1530"],
  "chain_id": "CHAIN-002"
}
```

Generate chunks: `python tools/rag_chunk.py --build`

Query: `python tools/rag_chunk.py --query "SSRF to AWS metadata chain"`

---

## Build Status

| Priority | Item | Status |
|---|---|---|
| P0 | Core PortSwigger + OWASP + MITRE | Done |
| P1 | bug-chains, saml, ci-cd | Done |
| P2 | oauth, browser, program-intel, recon-playbook, report-templates | Done |
| P3 | kubernetes, graphql, grpc, nuclei, payloads | Done |
| P4 | portswigger-injection SOTA expansion | Done (1538 lines) |
| P4 | prototype-pollution.md | Done |
| P4 | RAG indexes nested Trail of Bits skills | Done (187 sources) |
| P5 | Expand thin playbooks (chain-builder, mobile-analysis) | Done |
| P6 | Mobile/WebSocket/gRPC payloads + nuclei | Done |
