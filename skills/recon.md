# SKILL: World-Class Recon
**Load this first for every new target. Passive before active. Map before attack.**

---

## PHASE 1 — PASSIVE RECON (Zero Target Requests)

Goal: Maximum intel with zero footprint on the target.

### 1.1 Certificate Transparency
```bash
# Find all subdomains via cert logs — no requests to target
curl -s "https://crt.sh/?q=%.{TARGET}&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > sessions/{DATE}/crt-{TARGET}.txt

# Cross-reference with Facebook CT
curl -s "https://crt.sh/?q=%.{TARGET}&output=json" | jq -r '.[].issuer_ca_id' | sort | uniq -c | sort -rn | head -20
```

### 1.2 Shodan / Censys (requires API key in .env)
```bash
# Shodan: find all IPs, open ports, banners for target org
shodan search "ssl.cert.subject.cn:{TARGET}" --fields ip_str,port,org,hostnames > sessions/{DATE}/shodan-{TARGET}.txt
shodan search "org:{ORG_NAME}" --fields ip_str,port,org,hostnames >> sessions/{DATE}/shodan-{TARGET}.txt

# Censys via CLI
censys search "parsed.subject.common_name:{TARGET}" --fields ip,protocols,443.https.tls.certificate
```

### 1.3 GitHub / GitLab Dorking
```bash
# Search for leaked secrets, internal endpoints, API keys
# Keywords to search on GitHub:
# "{target}.com" password
# "{target}.com" api_key
# "{target}.com" secret
# "{target}.com" internal
# filename:.env "{target}"
# filename:config.js "{target}"

# Use trufflehog on any found repos:
trufflehog github --org={ORG} --token=$GITHUB_TOKEN --only-verified > sessions/{DATE}/trufflehog-{TARGET}.txt
```

### 1.4 Wayback Machine / Historical URLs
```bash
# Get all historical URLs — often reveals removed endpoints that still work
gau --providers wayback,commoncrawl,otx {TARGET} | sort -u > sessions/{DATE}/gau-{TARGET}.txt

# Filter for interesting patterns
cat sessions/{DATE}/gau-{TARGET}.txt | grep -E "\.(js|json|env|bak|sql|log|conf|xml|yaml|yml|php|asp|aspx|jsp)$" > sessions/{DATE}/interesting-files-{TARGET}.txt
cat sessions/{DATE}/gau-{TARGET}.txt | grep -E "(\?|&)(id|user|account|token|key|secret|api|admin|debug)=" > sessions/{DATE}/params-{TARGET}.txt
```

### 1.5 DNS Intelligence
```bash
# Zone transfer attempt (usually fails but worth trying)
dig axfr {TARGET} @ns1.{TARGET}

# Find nameservers, MX, TXT records
dig any {TARGET}
dig txt {TARGET}  # SPF, DMARC, DKIM — reveals email infra

# Reverse DNS on IP ranges from Shodan
```

### 1.6 Job Listings & Tech Stack Intel
```bash
# Search LinkedIn/Indeed/Glassdoor for target's job postings
# Job postings reveal: tech stack, internal tool names, cloud provider, security posture
# Keywords: "{company} site engineer" "{company} backend" "{company} devops"
# Look for: AWS/GCP/Azure preference, frameworks, monitoring tools
```

### 1.7 ASN & IP Range Discovery  
```bash
# Find all IP ranges owned by the target org
amass intel -org "{ORG_NAME}" -whois > sessions/{DATE}/asn-{TARGET}.txt

# BGP prefix lookup
curl -s "https://api.bgpview.io/search?query_term={ORG_NAME}" | jq '.data.ipv4_prefixes[].prefix'
```

---

## PHASE 2 — ACTIVE RECON (Light Touch)

### 2.1 Subdomain Enumeration
```bash
# Multi-source subdomain enum (fastest first, then thorough)
subfinder -d {TARGET} -all -recursive -o sessions/{DATE}/subs-{TARGET}.txt

# Amass for deeper coverage
amass enum -passive -d {TARGET} -o sessions/{DATE}/amass-subs-{TARGET}.txt

# Combine and deduplicate
cat sessions/{DATE}/subs-{TARGET}.txt sessions/{DATE}/amass-subs-{TARGET}.txt | sort -u > sessions/{DATE}/all-subs-{TARGET}.txt
echo "Total unique subdomains: $(wc -l < sessions/{DATE}/all-subs-{TARGET}.txt)"
```

### 2.2 HTTP Probing & Tech Detection
```bash
# Probe all subs: status code, title, tech, redirect chain
cat sessions/{DATE}/all-subs-{TARGET}.txt | httpx \
  -sc -title -tech-detect -location -server \
  -fr -mc 200,301,302,401,403,404,500 \
  -o sessions/{DATE}/alive-{TARGET}.txt \
  -threads 50

# Extract just the live URLs
cat sessions/{DATE}/alive-{TARGET}.txt | grep -v "404\|400" | awk '{print $1}' > sessions/{DATE}/live-{TARGET}.txt

# Flag high-value targets
grep -iE "jenkins|gitlab|jira|confluence|admin|dashboard|api|dev|staging|internal|vpn|grafana|kibana|elastic" sessions/{DATE}/alive-{TARGET}.txt
```

### 2.3 Port Scanning
```bash
# Fast port scan on live hosts
nmap -iL sessions/{DATE}/live-{TARGET}.txt \
  -p 21,22,23,25,53,80,443,445,3306,3389,5432,6379,8080,8443,8888,9200,27017 \
  -sV --open -T4 \
  -oA sessions/{DATE}/nmap-{TARGET}

# Note any unexpected open ports — database, Redis, Elasticsearch exposed?
```

### 2.4 Screenshot Recon
```bash
# Visual overview of all live targets
gowitness scan file -f sessions/{DATE}/live-{TARGET}.txt \
  --screenshot-path sessions/{DATE}/screenshots/ \
  --delay 2

# Review screenshots looking for:
# - Admin panels  - Login forms  - Error pages with debug info
# - Internal apps  - Default credentials pages  - Dev/staging environments
```

---

## PHASE 3 — SURFACE MAPPING

### 3.1 Deep Crawling
```bash
# Katana for modern JS-heavy apps
katana -list sessions/{DATE}/live-{TARGET}.txt \
  -d 5 -jc -fx -kf all \
  -o sessions/{DATE}/crawl-{TARGET}.txt \
  -threads 10

# Extract all endpoints
cat sessions/{DATE}/crawl-{TARGET}.txt | grep -oP "https?://[^\"' ]+" | sort -u
```

### 3.2 JS Analysis
```bash
# Download all JS files
cat sessions/{DATE}/crawl-{TARGET}.txt | grep "\.js$" | sort -u > sessions/{DATE}/jsfiles-{TARGET}.txt

# Extract endpoints and secrets from JS
cat sessions/{DATE}/jsfiles-{TARGET}.txt | while read url; do
  curl -sk "$url" | python3 scripts/js-extractor.py
done > sessions/{DATE}/js-endpoints-{TARGET}.txt

# Look for hardcoded API keys, secrets
trufflehog filesystem sessions/{DATE}/js/ --only-verified
```

### 3.3 Parameter Discovery
```bash
# Arjun finds hidden parameters
arjun -i sessions/{DATE}/live-{TARGET}.txt \
  -m GET,POST \
  -o sessions/{DATE}/params-arjun-{TARGET}.json \
  -t 20

# ffuf for wordlist-based parameter fuzzing
ffuf -u "https://{TARGET}/api/endpoint?FUZZ=test" \
  -w wordlists/parameters.txt \
  -mc 200,302 -fw 0 \
  -o sessions/{DATE}/ffuf-params-{TARGET}.json
```

---

## RECON OUTPUT CHECKLIST

Before moving to vuln-hunt, confirm you have:
- [ ] Full subdomain list with live/dead status
- [ ] Tech stack mapped per subdomain  
- [ ] All endpoints catalogued
- [ ] JS files downloaded and analyzed
- [ ] Historical URLs reviewed for interesting patterns
- [ ] Interesting parameters identified
- [ ] Any obvious misconfigs flagged (open admin, exposed DB, public S3)
- [ ] SESSION.md updated with attack surface map

**Highest value targets to prioritize:**
1. API subdomains with auth endpoints
2. Admin/internal panels (even 403 — might bypass)
3. Staging/dev environments (often less hardened)
4. GraphQL endpoints
5. File upload functionality
6. Password reset flows
