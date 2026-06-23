# MCP.md — Claude Code MCP Integrations
# What to install, why, and how to configure each one

---

## HACKERONE MCP SERVER (Primary Integration)

This is the core integration that connects Claude Code to HackerOne directly.

### Install dependencies
```bash
pip install -r scripts/requirements-h1.txt
```

### Add credentials to .env
```bash
# Your HackerOne username (the one you log in with)
H1_USERNAME=your_h1_username

# API token — generate at: https://hackerone.com/settings/api_token/edit
# Required permissions: Programs:Read, Reports:Read, Reports:Write
H1_API_TOKEN=your_h1_api_token
```

### How it's configured (already in .mcp.json)
```json
"hackerone": {
  "command": "python",
  "args": ["C:\\Users\\ask92\\Downloads\\bugbounty-kit\\scripts\\hackerone_mcp.py"],
  "env": {
    "H1_USERNAME": "${H1_USERNAME}",
    "H1_API_TOKEN": "${H1_API_TOKEN}"
  }
}
```

### Verify the connection
After adding your credentials to .env, test the connection:
```
Ask Claude: "Call h1_whoami and confirm the HackerOne connection is working"
```

### Starting a new engagement with H1
```
1. Ask Claude: "Use h1_list_programs to find programs with high bounties"
2. Pick a program handle (e.g. 'shopify')
3. Ask Claude: "Call h1_sync_scope for shopify — populate SCOPE.md and start recon"
4. Claude will: pull scope → write SCOPE.md → update SESSION.md → begin passive recon
```

---

## REQUIRED MCP SERVERS

These are essential for the agent to operate autonomously.

---

### 1. mcp-server-shell (CRITICAL)
**Why:** Executes all recon tools, scanners, and scripts locally.
Without this, Claude Code can only write commands — not run them.

```bash
npm install -g @anthropic-labs/mcp-server-shell
```

**Add to ~/.claude/claude_desktop_config.json:**
```json
{
  "mcpServers": {
    "shell": {
      "command": "mcp-server-shell",
      "args": [],
      "env": {}
    }
  }
}
```

**Security note:** This gives Claude Code shell access. Only run on a dedicated research VM/machine.

---

### 2. mcp-server-filesystem (CRITICAL)
**Why:** Read/write sessions, findings, reports, and skill files automatically.
Claude Code needs to update SESSION.md, create report stubs, and read wordlists.

```bash
npm install -g @modelcontextprotocol/server-filesystem
```

**Config:**
```json
"filesystem": {
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/bugbounty-kit"],
  "env": {}
}
```

---

### 3. mcp-server-fetch (CRITICAL)
**Why:** Make HTTP requests directly to targets, probe endpoints, test payloads.
Gives Claude full HTTP client capability with header control.

```bash
npm install -g @anthropic-labs/mcp-server-fetch
```

**Config:**
```json
"fetch": {
  "command": "mcp-server-fetch",
  "args": [],
  "env": {}
}
```

**Use cases:**
- Probe discovered endpoints
- Test payloads manually
- Validate findings
- Interact with APIs

---

### 4. mcp-server-git (HIGH VALUE)
**Why:** Clone and analyze public repos of target organizations.
GitHub leaks (secrets, internal endpoints, API structures) are extremely common.

```bash
npm install -g @modelcontextprotocol/server-git
```

**Config:**
```json
"git": {
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-git"],
  "env": {
    "GITHUB_TOKEN": "${GITHUB_TOKEN}"
  }
}
```

---

### 5. mcp-server-brave-search (HIGH VALUE)
**Why:** Google/Bing dorking for passive recon without leaving traces.
OSINT, leaked credentials, tech stack research — all passive.

```bash
npm install -g @modelcontextprotocol/server-brave-search
```

**Config:**
```json
"brave-search": {
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-brave-search"],
  "env": {
    "BRAVE_API_KEY": "${BRAVE_API_KEY}"
  }
}
```

**Use cases:**
- Google dork: `site:target.com ext:env OR ext:sql`
- Find public GitHub repos mentioning the target
- Discover historical vulnerability reports
- Research company infrastructure

---

### 6. mcp-server-sqlite (USEFUL)
**Why:** Store and query findings database locally across sessions.
Lets Claude track findings, avoid duplicates, and build a persistent intel store.

```bash
npm install -g @modelcontextprotocol/server-sqlite
```

**Config:**
```json
"sqlite": {
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-sqlite", "--db-path", "/path/to/bugbounty-kit/findings.db"],
  "env": {}
}
```

---

## OPTIONAL BUT POWERFUL

### 7. Burp Suite MCP Bridge
**Why:** Burp Suite Pro + Claude Code = complete web app testing.
Claude can read Burp history, issue scanner tasks, and analyze results.

```bash
# Install Burp MCP extension from Burp App Store (search "MCP")
# Or use community bridge: https://github.com/PortSwigger/mcp-server-burpsuite
```

**Config:**
```json
"burpsuite": {
  "command": "node",
  "args": ["/path/to/burp-mcp-bridge/index.js"],
  "env": {
    "BURP_API_KEY": "${BURP_API_KEY}",
    "BURP_URL": "http://127.0.0.1:1337"
  }
}
```

---

### 8. mcp-server-shodan
**Why:** Shodan API access directly from Claude for passive recon.

```bash
pip install mcp-server-shodan  # or use community implementation
```

**Config:**
```json
"shodan": {
  "command": "python3",
  "args": ["-m", "mcp_server_shodan"],
  "env": {
    "SHODAN_API_KEY": "${SHODAN_API_KEY}"
  }
}
```

---

## COMPLETE CONFIG FILE

**~/.claude/claude_desktop_config.json**
```json
{
  "mcpServers": {
    "shell": {
      "command": "mcp-server-shell",
      "args": []
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/you/bugbounty-kit"]
    },
    "fetch": {
      "command": "mcp-server-fetch",
      "args": []
    },
    "git": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-git"],
      "env": {"GITHUB_TOKEN": "ghp_..."}
    },
    "brave-search": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-brave-search"],
      "env": {"BRAVE_API_KEY": "BSA..."}
    },
    "sqlite": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-sqlite", "--db-path", "/Users/you/bugbounty-kit/findings.db"]
    }
  }
}
```

---

## API KEYS NEEDED

Store all secrets in `.env` (never commit this):
```bash
# .env — add to .gitignore immediately
GITHUB_TOKEN=ghp_...          # GitHub fine-grained token (read:org, repo)
SHODAN_API_KEY=...            # shodan.io API key ($49/month or academic free)
BRAVE_API_KEY=...             # search.brave.com API ($3/1000 queries)
CENSYS_API_ID=...             # censys.io (free tier available)
CENSYS_API_SECRET=...
VIRUSTOTAL_API_KEY=...        # virustotal.com (free tier available)
BURP_API_KEY=...              # Burp Suite Pro REST API
INTERACTSH_TOKEN=...          # interact.sh for OOB testing (free self-hosted)
```

---

## SETUP VERIFICATION

Run this to confirm all MCP servers are connected:
```bash
# In Claude Code, ask:
# "List all available MCP tools and confirm shell, filesystem, and fetch are connected"
```
