# RECON-AI Bug Bounty Kit
**World-class autonomous security research environment for Claude Code**

---

## 5-Minute Setup

```bash
# 1. Clone / copy this kit
git clone https://github.com/you/bugbounty-kit ~/bugbounty-kit
cd ~/bugbounty-kit

# 2. Install all tools
chmod +x scripts/install-tools.sh
./scripts/install-tools.sh

# 3. Configure API keys
cp .env.example .env
nano .env   # Add your API keys

# 4. Configure MCP servers
# See MCP.md for full instructions
nano ~/.claude/claude_desktop_config.json

# 5. Set your target scope
nano SCOPE.md   # Fill in in-scope and out-of-scope targets

# 6. Open Claude Code in this directory
claude  # That's it — Claude reads CLAUDE.md and begins
```

---

## What Claude Code Does Autonomously

| Phase | What Happens |
|-------|-------------|
| **Session start** | Reads CLAUDE.md, SCOPE.md, SESSION.md — internalizes full context |
| **Passive recon** | Cert transparency, Shodan, GitHub dorking, Wayback URLs |
| **Active recon** | Subdomain enum, HTTP probing, port scanning, screenshots |
| **Surface mapping** | Crawling, JS analysis, parameter discovery |
| **Vuln hunting** | Nuclei scan + targeted manual testing per skills |
| **Chain analysis** | Evaluates if findings can be combined for higher impact |
| **Reporting** | Writes professional reports to `reports/` in HackerOne format |

---

## Directory Structure

```
bugbounty-kit/
├── CLAUDE.md          ← 🧠 Agent brain — read first on every session
├── SCOPE.md           ← 🎯 Target scope — EDIT THIS PER ENGAGEMENT  
├── SESSION.md         ← 💾 Persistent session state
├── MCP.md             ← 🔌 MCP server setup guide
├── INSTALL.md         ← 🛠  Tool installation guide
├── skills/
│   ├── recon.md       ← Passive + active reconnaissance
│   ├── web-vulns.md   ← Web vulnerability testing
│   ├── api-testing.md ← REST/GraphQL/gRPC
│   ├── auth-bypass.md ← JWT, OAuth, MFA, password reset
│   ├── logic-bugs.md  ← Business logic, race conditions
│   ├── cloud-enum.md  ← AWS/GCP/Azure misconfigs
│   ├── mobile-analysis.md ← APK/IPA analysis
│   ├── chain-builder.md ← Vuln chaining for max impact
│   └── report-writer.md ← Professional disclosure reports
├── hooks/
│   ├── pre-tool-check.py  ← Scope enforcement hook
│   └── post-tool-logger.py ← Auto session logging
├── scripts/
│   └── install-tools.sh   ← One-shot tool installer
├── templates/
│   └── finding.md         ← Finding report template
├── wordlists/             ← Symlinks to SecLists
├── reports/               ← Confirmed findings go here
└── sessions/              ← Raw tool output per date
```

---

## Starting a Session

Just open Claude Code in this directory:
```bash
cd ~/bugbounty-kit
claude
```

Claude will automatically:
1. Read CLAUDE.md and load its operating instructions
2. Check SCOPE.md for in-scope targets
3. Resume from SESSION.md if there's an active engagement
4. Announce its plan and start executing

To start a new engagement, tell Claude:
```
"Start a new bug bounty session for [target.com] on HackerOne"
```

---

## Example Session Prompts

```
"Start passive recon on target.com — gather everything without touching the target"

"Run the full recon pipeline on *.target.com"

"We found an IDOR on /api/users/{id} — investigate the full scope and write a report"

"Check if any of our findings can be chained for higher impact"

"Write a HackerOne report for VULN-003"

"What attack surface have we mapped so far? What's our next priority?"

"Run nuclei against the live subdomains we found"

"Investigate the GraphQL endpoint at api.target.com/graphql"
```

---

## Required API Keys (`.env`)

```bash
GITHUB_TOKEN=          # github.com → Settings → Developer settings → Fine-grained tokens
SHODAN_API_KEY=        # account.shodan.io/billing/member
BRAVE_API_KEY=         # api.search.brave.com → Subscriptions
CENSYS_API_ID=         # search.censys.io → Account → API Access
CENSYS_API_SECRET=
VIRUSTOTAL_API_KEY=    # www.virustotal.com/gui/user/settings/apikey
BURP_API_KEY=          # Burp Suite Pro → User options → REST API
```

---

## Scope Enforcement

The pre-tool hook (`hooks/pre-tool-check.py`) automatically:
- Reads `SCOPE.md` before every shell command
- Blocks commands targeting out-of-scope hosts
- Blocks dangerous commands without explicit confirmation (sqlmap --dump, etc.)
- Logs all blocked attempts

---

## Legal Notice

This kit is for authorized security research only. Always:
- Have explicit written authorization before testing
- Operate only within defined scope
- Follow responsible disclosure practices
- Comply with the program's legal terms

Unauthorized testing is illegal. This tool enforces scope, but the researcher bears full legal responsibility.
