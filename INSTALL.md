# INSTALL.md — Security Tool Installation
# Run these on a dedicated Kali Linux / Ubuntu research VM

---

## QUICK INSTALL (All Tools)

```bash
# Run the full installer
chmod +x scripts/install-tools.sh
./scripts/install-tools.sh
```

---

## GO TOOLS (Core Recon Suite)

```bash
# Install Go first
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc

# Core toolchain
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/qsreplace@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/hakluke/hakrawler@latest
go install -v github.com/bp0lr/gauplus@latest

# Update nuclei templates
nuclei -update-templates
```

---

## PYTHON TOOLS

```bash
# Ensure pip is up to date
pip3 install --upgrade pip

# Core Python tools
pip3 install sqlmap trufflehog arjun s3scanner jwt-tool wfuzz dirsearch

# OSINT
pip3 install theHarvester shodan censys

# For Kali Linux
sudo apt-get install -y amass nmap whatweb dirb nikto

# jwt-tool (manual install for latest)
git clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool
pip3 install -r /opt/jwt_tool/requirements.txt
ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt-tool
chmod +x /usr/local/bin/jwt-tool
```

---

## WORDLISTS

```bash
# SecLists (the gold standard)
git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists

# Link commonly used lists
ln -s /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt wordlists/subdomains.txt
ln -s /opt/SecLists/Discovery/Web-Content/common.txt wordlists/common.txt
ln -s /opt/SecLists/Discovery/Web-Content/api/objects.txt wordlists/api-objects.txt
ln -s /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt wordlists/parameters.txt
ln -s /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt wordlists/passwords-common.txt
ln -s /opt/SecLists/Usernames/xato-net-10-million-usernames-dup.txt wordlists/usernames.txt

# Nuclei templates (auto-updated)
nuclei -update-templates

# Custom API wordlists
cat > wordlists/api-docs.txt << 'EOF'
swagger.json
swagger.yaml
openapi.json
openapi.yaml
api-docs
api-docs.json
swagger-ui.html
swagger-ui
redoc
docs
api/swagger.json
v1/swagger.json
v2/swagger.json
api/docs
EOF

# API version wordlist
cat > wordlists/api-versions.txt << 'EOF'
api
api/v1
api/v2
api/v3
api/v4
v1
v2
v3
api/beta
api/internal
api/private
api/admin
EOF
```

---

## OPTIONAL BUT RECOMMENDED

```bash
# Burp Suite Pro
# Download from: https://portswigger.net/burp/pro
# Required for: Turbo Intruder, advanced interception, scanner

# Metasploit (for CVE verification only)
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall && sudo ./msfinstall

# gowitness (screenshots)
go install github.com/sensepost/gowitness@latest

# CloudFlair (origin IP discovery)
pip3 install cloudflair

# subjack (subdomain takeover)
go install github.com/haccer/subjack@latest

# Corsy (CORS scanner)
git clone https://github.com/s0md3v/Corsy /opt/Corsy
pip3 install -r /opt/Corsy/requirements.txt
ln -s /opt/Corsy/corsy.py /usr/local/bin/corsy
```

---

## VM SETUP RECOMMENDATION

```
OS: Kali Linux 2024 (or Ubuntu 22.04 + manual tool install)
RAM: 8GB minimum, 16GB recommended
Storage: 100GB+ (screenshots, scan output, wordlists)
Network: VPN (ProtonVPN/Mullvad) for additional privacy
Snapshot: Take clean snapshot before each major engagement
```

---

## VERIFY INSTALLATION

```bash
# Run this to verify all core tools are installed
for tool in subfinder httpx nuclei katana gau ffuf dalfox sqlmap nmap; do
  if command -v $tool &> /dev/null; then
    echo "✓ $tool: $(which $tool)"
  else
    echo "✗ $tool: NOT FOUND"
  fi
done
```
