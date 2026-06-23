#!/bin/bash
# scripts/install-tools.sh
# One-shot installer for the full bug bounty research toolchain
# Run on Kali Linux or Ubuntu 22.04

set -e
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[-]${NC} $1"; }

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   RECON-AI Tool Installer                ║"
echo "║   Bug Bounty Research Kit                ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Go Installation ──────────────────────────────────────────────────────────
if ! command -v go &> /dev/null; then
  log "Installing Go 1.22..."
  GO_VERSION="1.22.0"
  wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
  sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
  log "Go installed: $(go version)"
else
  log "Go already installed: $(go version)"
fi

export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# ── Go Tools ─────────────────────────────────────────────────────────────────
log "Installing Go-based recon tools..."

GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/ffuf/ffuf/v2@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/tomnomnom/qsreplace@latest"
  "github.com/tomnomnom/anew@latest"
  "github.com/hahwul/dalfox/v2@latest"
  "github.com/hakluke/hakrawler@latest"
  "github.com/haccer/subjack@latest"
  "github.com/sensepost/gowitness@latest"
  "github.com/tomnomnom/gf@latest"
)

for tool in "${GO_TOOLS[@]}"; do
  tool_name=$(basename ${tool%@*})
  if command -v "$tool_name" &> /dev/null; then
    log "$tool_name already installed"
  else
    log "Installing $tool_name..."
    go install -v "$tool" 2>/dev/null && log "$tool_name ✓" || warn "Failed: $tool"
  fi
done

# ── Python Tools ─────────────────────────────────────────────────────────────
log "Installing Python tools..."
pip3 install --quiet --upgrade pip 2>/dev/null

PYTHON_PACKAGES=(
  "sqlmap"
  "trufflehog"
  "arjun"
  "s3scanner"
  "shodan"
  "censys"
)

for pkg in "${PYTHON_PACKAGES[@]}"; do
  pip3 install --quiet "$pkg" && log "$pkg ✓" || warn "pip install failed: $pkg"
done

# ── System Tools ─────────────────────────────────────────────────────────────
log "Installing system tools..."
if command -v apt-get &> /dev/null; then
  sudo apt-get install -y -qq nmap amass whatweb dirb nikto curl jq 2>/dev/null
  log "apt packages installed ✓"
elif command -v brew &> /dev/null; then
  brew install -q nmap amass whatweb curl jq 2>/dev/null
  log "brew packages installed ✓"
fi

# ── jwt-tool ─────────────────────────────────────────────────────────────────
if ! command -v jwt-tool &> /dev/null; then
  log "Installing jwt-tool..."
  git clone -q https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null || true
  pip3 install --quiet -r /opt/jwt_tool/requirements.txt 2>/dev/null
  sudo ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt-tool
  sudo chmod +x /usr/local/bin/jwt-tool
  log "jwt-tool ✓"
fi

# ── SecLists ─────────────────────────────────────────────────────────────────
if [ ! -d "/opt/SecLists" ]; then
  log "Downloading SecLists (this takes a few minutes)..."
  git clone -q --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists
  log "SecLists downloaded ✓"
else
  log "SecLists already present ✓"
fi

# Link wordlists
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$SCRIPT_DIR/wordlists"
ln -sf /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt "$SCRIPT_DIR/wordlists/subdomains.txt" 2>/dev/null || true
ln -sf /opt/SecLists/Discovery/Web-Content/common.txt "$SCRIPT_DIR/wordlists/common.txt" 2>/dev/null || true
ln -sf /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt "$SCRIPT_DIR/wordlists/parameters.txt" 2>/dev/null || true
ln -sf /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt "$SCRIPT_DIR/wordlists/passwords-common.txt" 2>/dev/null || true

# ── Nuclei Templates ─────────────────────────────────────────────────────────
log "Updating nuclei templates..."
nuclei -update-templates -silent 2>/dev/null && log "Nuclei templates updated ✓" || warn "Nuclei template update failed"

# ── Node / MCP Servers ───────────────────────────────────────────────────────
if command -v npm &> /dev/null; then
  log "Installing MCP servers..."
  npm install -g --silent @modelcontextprotocol/server-filesystem \
    @modelcontextprotocol/server-brave-search \
    @modelcontextprotocol/server-git \
    @modelcontextprotocol/server-sqlite 2>/dev/null
  log "MCP servers installed ✓"
else
  warn "npm not found — install Node.js and run: npm install -g @modelcontextprotocol/server-filesystem @modelcontextprotocol/server-brave-search"
fi

# ── Verification ─────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════"
echo "  INSTALLATION VERIFICATION"
echo "═══════════════════════════════════════════"

TOOLS=(subfinder httpx nuclei katana gau ffuf dalfox sqlmap nmap jwt-tool)
ALL_OK=true

for tool in "${TOOLS[@]}"; do
  if command -v "$tool" &> /dev/null; then
    echo -e "  ${GREEN}✓${NC} $tool"
  else
    echo -e "  ${RED}✗${NC} $tool — NOT FOUND"
    ALL_OK=false
  fi
done

echo ""
if $ALL_OK; then
  echo -e "  ${GREEN}All core tools installed successfully!${NC}"
else
  echo -e "  ${YELLOW}Some tools missing — check output above${NC}"
fi
echo ""
echo "  Next steps:"
echo "  1. Edit SCOPE.md with your target"  
echo "  2. Add API keys to .env"
echo "  3. Configure MCP servers in ~/.claude/claude_desktop_config.json"
echo "  4. Open Claude Code in this directory"
echo "  5. Claude will read CLAUDE.md and begin the session"
echo ""
