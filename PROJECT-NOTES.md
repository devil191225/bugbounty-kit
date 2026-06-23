# PROJECT-NOTES.md
**Bug Bounty OS — Architecture & Decision Reference**

> Single source of truth for architectural decisions.  
> Last updated: 2026-06-10 (sandbox working copy — full autonomy + hard gates)

---

## 1. What This Project Is

**Not:** a notes repo, a payload dump, or a Claude prompt pack.  
**Is:** a layered **bug bounty operating system** — knowledge + payloads + retrieval + tools + memory + agent brain — designed to train and run an AI hunter under scope.

| Layer | Role | Primary paths |
|---|---|---|
| **Brain** | Agent identity, workflow, gates | `CLAUDE.md`, `SCOPE.md`, `SESSION.md` |
| **Skills** | Methodology & encyclopedic reference | `skills/` |
| **Payloads** | Structured attack strings & wordlists | `payloads/` |
| **RAG** | Chunked retrieval over skills + payloads | `rag/`, `tools/rag_chunk.py` |
| **Tools** | Executable pipeline (recon → validate) | `tools/` |
| **Memory** | Learned patterns across engagements | `hunt-memory/`, `memory/` |
| **Agents** | Specialized subagent prompts | `agents/` |
| **Safety** | Scope + evidence rules | `hooks/`, `rules/`, `.cursor/rules/` |

---

## 2. Repository Layout Rule

| Path | Role |
|---|---|
| `bugbounty-kit-sandbox/` | **Working copy** — all changes here |
| `bugbounty-kit/` (parent) | **Original backup** — do not modify |

When making architectural decisions, assume sandbox is the live system.

---

## 3. System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  AGENT HOST (Cursor / Claude Code) — not shipped in repo        │
│  Reads CLAUDE.md + slash commands (~/.claude/)                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│  BRAIN LAYER                                                     │
│  CLAUDE.md → SCOPE.md → SESSION.md → skills/skills-index.md     │
│  health_check.py --quick (session gate)                          │
└────────────────────────────┬────────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ SKILLS        │   │ PAYLOADS      │   │ MEMORY        │
│ SOTA refs     │   │ Synced lists  │   │ patterns.jsonl│
│ Playbooks     │   │ Curated seeds │   │ ctf_learn.py  │
│ ToB nested    │   │ sync_payloads │   │ pattern_db.py │
└───────┬───────┘   └───────┬───────┘   └───────┬───────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            ▼
                   ┌───────────────┐
                   │ RAG INDEX     │
                   │ chunks.jsonl  │
                   │ rag_chunk.py  │
                   └───────┬───────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│ hunt.py       │  │ validate.py   │  │ scope_checker │
│ recon engines │  │ 7-Q + 4 gates │  │ pre-tool hook │
│ intel_engine  │  │ CVSS 4.0      │  │               │
└───────────────┘  └───────────────┘  └───────────────┘
        │                  │
        ▼                  ▼
   sessions/           reports/
   (raw evidence)      (submissions)
```

---

## 4. Hunt Pipeline (Canonical Flow)

```
SCOPE.md
  → health_check.py --quick (abort if NOT READY)
  → scope_checker / pre-tool-check.py
  → memory: ctf_learn.py suggest + weights (BEFORE hunting)
  → recon (subfinder, httpx, katana, nuclei) via hunt.py or /recon
  → os_query / RAG (skill + payload retrieval)
  → autonomous hunt by class (Auth → IDOR → Injection → Logic)
  → evidence → sessions/{date}/
  → gate_check.py (7-Question + never-submit) — MUST PASS
  → tools/validate.py (optional: 4 gates + CVSS 4.0)
  → duplicate check (GitLab, H1 disclosed, OSS competition)
  → chain analysis (bug-chains.md, chain-builder)
  → report ONLY if GATE_STATUS: PASS + POC_FILE exists
  → /remember → hunt-memory/patterns.jsonl
```

## 6. AUTOMATION BOUNDARY (UPDATED — full autonomy)

**Deprecated:** "Recon only automated; IDOR/auth/logic manual."

**Current rule:** The agent may autonomously recon, hunt, validate, and draft reports. Bulk scanner output is **never** a report by itself.

| Stage | Autonomous? | Gate |
|---|---|---|
| Recon (subfinder, httpx, katana, nuclei) | Yes | scope_checker |
| Hunt (IDOR, auth, logic, injection) | Yes | memory prioritization + os_query |
| Draft report | Yes | **gate_check.py → PASS required** |
| Platform submit | No (default) | Human review |

**Dup rate control:** nuclei/ffuf find signals → `gate_check.py` + never-submit list + duplicate check filter ~80% of informatives.

---

## 5. Content Tier Taxonomy

Use these labels everywhere (skills, payloads, index). **Never inflate tiers.**

| Tier | Meaning | Example |
|---|---|---|
| **SOTA** | Exhaustive, PortSwigger/OWASP-depth reference | `portswigger-injection.md`, `bug-chains.md` |
| **Synced** | Upstream mirror (PAT, SecLists, Escape) | `sqli/union-select.txt`, GraphQL 10k wordlists |
| **Curated** | Hand-built entry points, not full fuzz DB | `cmdi/bypass-polyglot.txt`, `auth/jwt.txt` |
| **Playbook** | Operational commands, 130–270 lines OK | `recon.md`, `api-testing.md`, `chain-builder.md` |
| **Index** | Cross-reference maps only | `skills-index.md`, `owasp-top10-2021.md` |
| **Code-Audit** | Trail of Bits nested packages | `skills/codeql/`, `skills/sharp-edges/` |
| **Doc** | Methodology reference, not Intruder list | PAT deserialization docs |

**Principle:** Not every file needs 1,500 lines. Every file must be **truthful**.

---

## 6. Skills Layer

### 6.1 Top-level web hunting (39 `.md` files)

**SOTA references:** PortSwigger quartet, `prototype-pollution.md`, `bug-chains.md`, OAuth/SAML/CI-CD/cloud/K8s/GraphQL/gRPC, framework indexes (OWASP/CWE/MITRE).

**Playbooks:** `recon.md`, `web-vulns.md`, `api-testing.md`, `auth-bypass.md`, `logic-bugs.md`, `cloud-enum.md`, `mobile-analysis.md`, `chain-builder.md`, `report-writer.md`, `recon-playbook.md`, `program-intelligence.md`.

**Master index:** `skills/skills-index.md` — load at session start.

### 6.2 Trail of Bits nested packages (code-audit future vision)

Indexed by RAG with `skill_layer: code-audit | mobile-audit | tooling`:

- `sharp-edges/`, `codeql/`, `variant-analysis/`, `semgrep-rule-creator/`
- `constant-time-analysis/`, `insecure-defaults/`, `agentic-actions-auditor/`
- `sarif-parsing/`, `burpsuite-project-parser/`, `firebase-apk-scanner/`

**Pivot trigger:** black-box saturation → source review via ToB skills.

### 6.3 Ghost path migration (completed 2026-06-10)

These **do not exist** and must never be reintroduced:

```
skills/bug-bounty/
skills/bb-methodology/
skills/web2-recon/
skills/web2-vuln-classes/
skills/security-arsenal/
skills/triage-validation/
skills/report-writing/
commands/report.md
```

**Real replacements:**

| Need | Use |
|---|---|
| Master workflow | `recon-playbook.md`, `program-intelligence.md`, `skills-index.md` |
| Recon | `recon.md`, `recon-playbook.md` |
| Bug classes | `web-vulns.md` + PortSwigger suite |
| Payloads / bypass | `payloads/` + `payloads/README.md` |
| Triage / gates | `agents/validator.md`, `rules/reporting.md`, `tools/validate.py` |
| Reporting | `report-templates.md`, `report-writer.md`, `templates/finding.md` |

---

## 7. Payloads Layer

**~80 files** across 20+ categories. See `payloads/README.md` for full map.

| Category | Status |
|---|---|
| sqli, xss, ssrf, xxe, ssti, lfi, nosql, ldap, crlf | Synced + curated |
| graphql, prototype-pollution | SOTA (incl. Escape 10k wordlists) |
| file-upload, deserialization, auth/jwt, csrf | Curated |
| cmdi | `unix.txt`, `windows-powershell.txt`, `bypass-polyglot.txt` curated; `generic.txt` PAT may be Defender-quarantined |

**Sync:**

```powershell
python tools/sync_payloads.py              # PAT Intruder + XXE + deserialization
python tools/sync_payloads.py --external # + Escape GraphQL 10k wordlists
python tools/rag_chunk.py --build        # Re-index after updates
```

**Known gaps (honest):** HTTP smuggling, cache poisoning wordlists, OAuth fuzz seeds, full SSTI engine table, `nuclei/custom/` templates dir.

---

## 8. RAG Layer

| File | Purpose |
|---|---|
| `tools/rag_chunk.py` | Build + query index |
| `rag/chunks.jsonl` | 1,704 chunks from 187 sources (as of last build) |
| `rag/index_meta.json` | Build metadata |

**Indexed sources:**
- Top-level `skills/*.md`
- Nested ToB: `SKILL.md`, `METHODOLOGY.md`, `references/`, `workflows/`, `resources/`
- `payloads/**/*.txt` (with size limits)
- `agents/*.md`

**Query examples:**

```bash
python tools/rag_chunk.py --query "GraphQL batching IDOR" --top 5
python tools/rag_chunk.py --query "prototype pollution nodejs gadget" --top 3
python tools/rag_chunk.py --stats
```

**Windows:** Defender may quarantine `rag/chunks.jsonl`. Add folder exclusion for sandbox path, then rebuild.

---

## 9. Tools Layer

### 9.1 Core pipeline

| Tool | Role |
|---|---|
| `hunt.py` | Orchestrator: target select → recon → scan |
| `validate.py` | Interactive 4-gate validation + CVSS 4.0 + report skeleton |
| `scope_checker.py` | Scope validation |
| `rag_chunk.py` | RAG build/query |
| `health_check.py` | OS integrity gate (ghost paths, RAG, core dirs) |
| `ctf_learn.py` | CTF → pattern DB learning |
| `sync_payloads.py` | Upstream payload sync |
| `intel_engine.py` | CVE + disclosed report intel |
| `dup_check.py` | Pre-submit duplicate check (H1 + local reports/) |
| `recon_adapter.py` | Normalize recon output paths |
| `target_selector.py` | Program/target selection |

### 9.2 External tool dependencies

`hunt.py` expects on PATH: subfinder, httpx, nuclei, ffuf, nmap, amass, gau, dalfox, subjack.  
Install via `scripts/install-tools.sh` (Linux/Kali). Not bundled in Python.

### 9.3 Planned (not yet built)

| Tool | Purpose |
|---|---|
| `os_query.py` | Unified RAG + payload search CLI |
| `sync_seclists.py` | Wordlist sync (README still claims symlinks) |
| `audit_references.py` | Scan skills for ghost paths/scripts |

---

## 10. Memory Layer

| Path | Role |
|---|---|
| `hunt-memory/patterns.jsonl` | Successful technique patterns |
| `memory/pattern_db.py` | Read/write/match API |
| `memory/schemas.py` | Pattern entry validation |
| `memory/rotation.py` | JSONL rotation |
| `tools/ctf_learn.py` | CTF gym → live-safe strategy transfer |

**Three-phase model:** CTF (explore) → Live (exploit under scope) → Memory (weight by outcome).

**Blocked on live:** brute_force, credential_flood, endpoint_flood, destructive techniques.

**Future:** RAG ranking boost from patterns with high success_rate on matching tech stack.

---

## 11. Agents & Validation

### 11.1 Repo agents (`agents/`)

recon-agent, recon-ranker, validator, chain-builder, report-writer, autopilot, credential-hunter, web3-auditor, token-auditor.

### 11.2 Validation stack

| Component | Role |
|---|---|
| `agents/validator.md` | 7-Question Gate + never-submit list |
| `rules/reporting.md` | Reporting rules + always-rejected list §5 |
| `rules/hunting.md` | Behavioral hunting rules (referenced in CLAUDE.md) |
| `tools/validate.py` | Interactive 4 gates + CVSS 4.0 |

**Never-submit (standalone):** missing headers, GraphQL introspection alone, self-XSS, open redirect alone, SSRF DNS-only, logout CSRF, missing cookie flags alone, etc. — full list in `agents/validator.md`.

**Evidence rule:** No fabricated HTTP responses. `POC_FILE` mandatory. Pre-tool hook blocks reports without evidence.

---

## 12. Safety & Quality Rules

### 12.1 Cursor rules (always apply)

| Rule | File |
|---|---|
| Exhaustive research before stopping | `.cursor/rules/exhaustive-research.mdc` |
| No fabricated CVEs, scripts, paths, stats | `.cursor/rules/no-fabrication.mdc` |

### 12.2 Scope enforcement

- `hooks/pre-tool-check.py` — blocks out-of-scope hosts, dangerous commands
- `SCOPE.md` — per-engagement source of truth

### 12.3 Token budgets (agent sessions)

| Difficulty | Token budget |
|---|---|
| Easy | 10k |
| Medium | 20k |
| Hard | 40k |

---

## 13. Architectural Decision Records (ADRs)

Use this section when choosing between options. Add new ADRs here; do not scatter decisions across chat.

### ADR-001: Agent brain vs CLI product

**Decision:** Keep agent brain (`CLAUDE.md`) separate from CLI tools.  
**Rationale:** Autonomous hunting requires LLM host; tools are independently executable.  
**Consequence:** Ship `bbkit` CLI for tools; do not try to bundle Cursor/Claude into an exe.

### ADR-002: Skills as markdown, not code

**Decision:** Methodology lives in chunked markdown, not Python modules.  
**Rationale:** RAG retrieval, human editability, PortSwigger-style depth.  
**Consequence:** Playbooks stay short; SOTA refs stay long; tier tags prevent false completeness claims.

### ADR-003: Payloads as files, synced not invented

**Decision:** Payloads come from PAT/SecLists/Escape sync + curated seeds.  
**Rationale:** No fabricated attack strings; honest tier labeling.  
**Consequence:** `sync_payloads.py` is first-class; gaps are listed, not hidden.

### ADR-004: Ghost paths are bugs

**Decision:** Any reference to non-existent paths is a P0 defect.  
**Rationale:** Agent loads ghosts → wasted tokens, wrong behavior.  
**Enforcement:** `health_check.py` ghost scan; `.cursor/rules/no-fabrication.mdc`.

### ADR-005: RAG over skills + payloads, not tools

**Decision:** Index knowledge layers; do not index `tools/*.py` source.  
**Rationale:** Tools are invoked by name; skills explain when/how.  
**Exception:** `agents/*.md` indexed for validator/report workflows.

### ADR-006: Validation before reporting

**Decision:** 7-Question Gate + 4 gates + duplicate check before full report.  
**Rationale:** Protects validity ratio; kills theoretical bugs early.  
**Implementation:** `tools/gate_check.py` (non-interactive, hook-enforced) + `agents/validator.md` + `tools/validate.py` (CVSS).

### ADR-009: Full autonomy with hard gates (2026-06-10)

**Decision:** Agent may autonomously recon, hunt, and draft reports. No "manual only past recon" rule.  
**Rationale:** User intent is full autonomy; spam comes from skipping gates, not from hunting autonomously.  
**Enforcement:** `gate_check.py` PASS + `GATE_STATUS: PASS` in report + `POC_FILE` on disk; pre-tool hook blocks otherwise.  
**Consequence:** Nuclei/ffuf output = signals only; ~80% of informatives killed at gate.

### ADR-010: Memory before hunt and before report

**Decision:** Query `ctf_learn.py suggest/weights` before prioritizing endpoints; down-rank bug classes with 0% success rate on target type.  
**Rationale:** Stops reporting bugs that never pay on this target archetype.  
**Implementation:** Session startup + autopilot Step 4; live-safe filter via `get_live_strategies()`.

### ADR-007: Executable packaging = CLI + data bundle

**Decision:** If shipping executable, use Tier 1 CLI package + sidecar data dir.  
**Not chosen:** Single monolithic exe with nuclei/ffuf embedded.  
**Best full-stack option:** Docker image with `install-tools.sh` toolchain.

### ADR-008: Two-repo sandbox rule

**Decision:** All work in sandbox; parent kit is immutable backup.  
**Rationale:** Safe experimentation without losing known-good state.

### ADR-011: Private by default (2026-06-10)

**Decision:** Full OS stays private. No public release without redaction review.  
**Rationale:** Dual-use toolkit + operator memory/scopes are competitive moat; misuse risk if framed as "autonomous exploit kit."  
**Enforcement:** `.gitignore` blocks engagement data; `PRIVATE-POLICY.md`; never commit `SCOPE.md`, `reports/`, `hunt-memory/*.jsonl`.

---

## 14. Current State Scorecard

| Layer | Score | Notes |
|---|---|---|
| Skills (methodology) | 9/10 | PortSwigger + frameworks strong |
| Payloads | 8/10 | smuggling, cache-poison, oauth added |
| RAG | 8/10 | os_query + 1707 chunks |
| Tools | 8/10 | gate_check, health_check, os_query, audit |
| Agent brain (CLAUDE.md) | 9/10 | Full autonomy + hard gates aligned |
| Memory/learning | 9/10 | prioritize.py + RAG memory boost + safe_for_live |
| README accuracy | 8/10 | Synced with PROJECT-NOTES |
| **Overall OS** | **9/10** | Private ops + gates + memory wired |

**Health check:** `python tools/health_check.py` — target READY.

---

## 15. Roadmap (Priority Order)

| # | Task | Layer | Status |
|---|---|---|---|
| 1 | Fix CLAUDE.md ghost paths | Brain | ✅ Done |
| 2 | Add `health_check.py` | Tools | ✅ Done |
| 3 | Sync README.md with PROJECT-NOTES | Docs | ✅ Done |
| 4 | Full autonomy + hard gates (ADR-009) | Brain | ✅ Done |
| 5 | `tools/gate_check.py` + hook enforcement | Tools | ✅ Done |
| 6 | `.cursor/rules/bounty-os-workflow.mdc` | Brain | ✅ Done |
| 7 | `tools/os_query.py` unified search | RAG | ✅ Done |
| 8 | Payload gaps (smuggling, cache poison, oauth/) | Payloads | ✅ Done |
| 9 | `nuclei/custom/` templates dir | Payloads/Tools | ✅ Done |
| 10 | SecLists sync script | Wordlists | ✅ Done |
| 11 | `audit_references.py` ghost scanner | Quality | ✅ Done |
| 12 | `pyproject.toml` + `bbkit` CLI (deferred) | Packaging | ⬜ On hold |
| 13 | Memory → RAG ranking boost | Memory | ✅ Done |
| 14 | `safe_for_live` explicit field in patterns | Memory | ✅ Done |
| 15 | `tools/prioritize.py` hunt plan CLI | Memory | ✅ Done |
| 16 | `.gitignore` + PRIVATE-POLICY (ADR-011) | Safety | ✅ Done |
| 17 | SAML payload seeds | Payloads | ✅ Done |
| 18 | SSTI engines table (ERB, Pebble, Smarty) | Payloads | ✅ Done |
| 19 | `tools/dup_check.py` pre-submit dup helper | Tools | ✅ Done |

---

## 16. Executable Product Options

| Option | Ship | Does not ship |
|---|---|---|
| **CLI package (`bbkit`)** | validate, health_check, rag query, hunt wrapper | Agent autonomy |
| **Launcher scripts** | `bbkit.ps1` / `bbkit.bat` | External Go tools |
| **Docker** | Full Linux toolchain + kit data | Windows-native without Docker |
| **PyInstaller exe** | Python tools only | skills/payloads (ship as data dir beside exe) |

**Recommended path:** `pyproject.toml` → `bbkit health`, `bbkit query`, `bbkit validate`, `bbkit hunt` with `--data-dir` defaulting to repo root.

---

## 17. Key File Quick Reference

| Question | Read this |
|---|---|
| What exists in skills? | `skills/skills-index.md` |
| What payloads exist? | `payloads/README.md` |
| How does agent start? | `CLAUDE.md` § Session Startup |
| Is OS healthy? | `python tools/health_check.py` |
| Can I report this finding? | `python tools/gate_check.py` → must PASS |
| Is it a duplicate? | `python tools/dup_check.py --program <handle> --artifact "<EXACT>"` |
| Never submit list? | `agents/validator.md`, `rules/reporting.md` §5 |
| Report format? | `skills/report-templates.md`, `templates/finding.md` |
| Scope? | `SCOPE.md` |
| Session state? | `SESSION.md` |
| Learned patterns? | `hunt-memory/patterns.jsonl` |
| What to hunt first? | `python tools/prioritize.py --target-type <type>` |
| Private data policy? | `PRIVATE-POLICY.md` |
| Architecture decisions? | **This file** |

---

## 18. Session Commands Cheat Sheet

```bash
# Startup
python tools/health_check.py --quick
python tools/ctf_learn.py flush
python tools/prioritize.py --target-type saas --tech oauth,nodejs

# Knowledge retrieval
python tools/os_query.py "GraphQL batching IDOR" --target-type saas
python tools/rag_chunk.py --query "SSRF AWS metadata chain" --top 5

# Validation (mandatory before reports/)
python tools/gate_check.py --title "..." --vuln-class idor --endpoint "..." \
  --poc-file sessions/.../poc.txt --impact "..." --repro "curl ..."
python tools/dup_check.py --program shopify --artifact "exact_method" --endpoint "/api/foo"
python tools/validate.py

# Payload maintenance
python tools/sync_payloads.py
python tools/rag_chunk.py --build

# Learning
python tools/ctf_learn.py suggest --target-type saas
python tools/ctf_learn.py weights --target-type fintech
```

---

## 19. When Adding New Content — Checklist

Before merging any new skill, payload, or tool reference:

- [ ] Path exists on disk (or is a standard external tool like `ffuf`, `jwt_tool`)
- [ ] Tier tag is honest (SOTA / Synced / Curated / Playbook)
- [ ] No duplicate padding for line count
- [ ] RAG rebuild if skills/payloads changed: `python tools/rag_chunk.py --build`
- [ ] Ghost scan clean: `python tools/health_check.py --quick`
- [ ] Update `skills/skills-index.md` if new top-level skill
- [ ] Update `payloads/README.md` if new payload category
- [ ] Update this file if architectural decision made (new ADR)

---

## 20. Open Questions (Decision Needed)

| Question | Options | Recommendation |
|---|---|---|
| Unified CLI name? | `bbkit`, `recon-ai`, `bounty-os` | `bbkit` — short, namespace-friendly |
| README vs PROJECT-NOTES? | Merge, or README points here | README = quick start; PROJECT-NOTES = architecture |
| Nuclei templates? | Doc-only vs `nuclei/custom/` dir | Create dir; skill doc references real YAML |
| SecLists? | Symlinks vs sync script vs submodule | Sync script (Windows-safe) |
| Playbook depth? | Expand all vs keep short | Expand only where hunt-critical; never fabricate |

---

*End of PROJECT-NOTES.md — update this file when making architectural decisions.*
