# Subdomain Takeover — Complete Attack Reference
> Source: EdOverflow can-i-take-over-xyz, 0xpatrik blog, HackTricks | RAG Knowledge Base | Full detail preserved

---

## What Is Subdomain Takeover?

When a DNS record (CNAME, A, NS) points to an external service that has been **deleted or is unclaimed**, an attacker can register that service and serve arbitrary content from the legitimate subdomain.

The DNS record continues to exist and resolve, but the destination is under attacker control.

---

## The DNS CNAME Dangling Pointer Mechanism

**Normal State:**
```
dev.example.com.    CNAME    example.github.io.
example.github.io.  A        185.199.108.153
```
→ `dev.example.com` serves content from `example.github.io` (controlled by example.com owner)

**Vulnerable State (GitHub Pages site deleted):**
```
dev.example.com.    CNAME    example.github.io.    ← Still in DNS
example.github.io.  (no record — project deleted)  ← Unclaimed!
```
→ DNS record dangles with no valid destination

**Takeover:**
1. Attacker creates GitHub repository `example` (or org `example`)
2. Enables GitHub Pages
3. Adds CNAME file containing `dev.example.com`
4. `dev.example.com` now serves attacker-controlled content

---

## NS Record Takeover (Higher Risk Than CNAME)

```
# NS record pointing to expired nameserver
example.com.  NS  ns1.expired-hosting.com.
```

If the nameserver domain expires and an attacker registers it:
- Attacker controls **ALL DNS** for `example.com`
- Can set any records: A, CNAME, MX, TXT (SPF, DKIM bypass), NS
- High TTL values (e.g., 1 week = 604800 seconds) cause mass caching across all public DNS resolvers
- **Real case:** Matthew Bryant registered `ns-a1.io` which was a nameserver for the `.io` ccTLD

---

## Identifying Vulnerable Subdomains

### Step 1: Enumerate Subdomains

```bash
# Multiple tools for broad coverage
subfinder -d example.com -o subdomains.txt
amass enum -passive -d example.com >> subdomains.txt
assetfinder example.com >> subdomains.txt
findomain -t example.com >> subdomains.txt
sort -u subdomains.txt > all_subs.txt

# Active certificate transparency logs
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
  jq -r '.[].name_value' | sort -u >> all_subs.txt
```

### Step 2: Find Dangling CNAME Records

```bash
# Check all subdomains for CNAME records
while read sub; do
  cname=$(dig +short CNAME $sub)
  if [ ! -z "$cname" ]; then
    echo "$sub -> $cname"
  fi
done < all_subs.txt

# Bonus: check for NXDOMAIN (CNAME target doesn't resolve)
while read sub; do
  if dig +short CNAME $sub | grep -q '.'; then
    target=$(dig +short CNAME $sub)
    if ! host $target &>/dev/null; then
      echo "POTENTIAL TAKEOVER: $sub -> $target (NXDOMAIN)"
    fi
  fi
done < all_subs.txt
```

### Step 3: Check HTTP Response Fingerprints

```bash
# Get HTTP responses for all live subdomains
httpx -l all_subs.txt -status-code -title -mc 200,404 -o live.txt

# Check for service-specific error messages
while read sub; do
  response=$(curl -s -L --max-time 10 https://$sub 2>/dev/null)
  echo "$sub: $(echo $response | head -c 200)"
done < all_subs.txt
```

### Step 4: Automated Tools

```bash
# nuclei takeover templates
nuclei -l all_subs.txt -t nuclei-templates/takeovers/ -o takeover_results.txt

# subjack
subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt -ssl

# tko-subs
tko-subs -domains all_subs.txt -data providers-data.yml -workers 100

# dnsx + httpx pipeline
dnsx -l all_subs.txt -cname -resp -o cname_records.txt
httpx -l cname_records.txt -title -status-code
```

---

## Service Fingerprints — Complete Takeover Table

| Service | CNAME Pattern | HTTP Fingerprint (Vulnerable State) | Exploitable? |
|---|---|---|---|
| **AWS S3** | `.s3.amazonaws.com`, `.s3-website-REGION.amazonaws.com` | `The specified bucket does not exist` | Yes |
| **AWS Elastic Beanstalk** | `.elasticbeanstalk.com` | NXDOMAIN | Yes |
| **Azure App Service** | `.azurewebsites.net` | NXDOMAIN | Yes |
| **Azure CDN** | `.cloudapp.azure.com`, `.cloudapp.net` | NXDOMAIN | Yes |
| **GitHub Pages** | `.github.io` | `There isn't a GitHub Pages site here.` | Edge Case |
| **Heroku** | `.herokudns.com`, `.herokuapp.com` | `No such app` | Edge Case |
| **Fastly** | `.fastly.net` | `Fastly error: unknown domain` | Not Vulnerable |
| **Bitbucket** | `.bitbucket.io` | `Repository not found` | Yes |
| **Shopify** | `.myshopify.com` | `Sorry, this shop is currently unavailable.` | Edge Case |
| **Ghost** | `.ghost.io` | `Site unavailable` | Yes |
| **Help Scout** | `.helpscoutdocs.com` | `No settings were found for this company:` | Yes |
| **Help Juice** | `.helpjuice.com` | `We could not find what you're looking for.` | Yes |
| **Surge.sh** | `.na-west1.surge.sh`, `.surge.sh` | `project not found` | Yes |
| **Wordpress.com** | `.wordpress.com` | `Do you want to register .*.wordpress.com?` | Yes |
| **Tumblr** | `.tumblr.com` | `Whatever you were looking for doesn't live here.` | Edge Case |
| **Readme.io** | `.readme.io` | `The creators of this project are still working` | Yes |
| **Discourse** | `.trydiscourse.com` | NXDOMAIN | Yes |
| **Digital Ocean** | DO nameservers | `Domain uses DO name servers with no records` | Yes |
| **Netlify** | `.netlify.app` | `DEPLOYMENT_NOT_FOUND` | Edge Case |
| **Vercel** | `.vercel.app` | `DEPLOYMENT_NOT_FOUND` | Edge Case |
| **Ngrok** | `.ngrok.io` | `Tunnel .*.ngrok.io not found` | Yes |
| **Pantheon** | — | `404 error unknown site` | Yes |
| **Strikingly** | `.s.strikinglydns.com` | `PAGE NOT FOUND` | Yes |
| **SurveySparrow** | `.surveysparrow.com` | `Account not found` | Yes |
| **Read the Docs** | — | `The link you have followed does not exist` | Yes |
| **Short.io** | — | `Link does not exist` | Yes |
| **Uberflip** | `.read.uberflip.com` | `The URL you've accessed does not provide hub` | Yes |
| **JetBrains (YouTrack)** | `.youtrack.cloud` | `is not a registered InCloud YouTrack` | Yes |
| **HatenaBlog** | `.hatenablog.com` | `404 Blog is not found` | Yes |
| **Zendesk** | — | `Help Center Closed` | Not Vulnerable |
| **HubSpot** | — | `This page isn't available` | Not Vulnerable |
| **Firebase** | — | — | Not Vulnerable |
| **Google Cloud Storage** | — | `NoSuchBucket` | Not Vulnerable |
| **CloudFront** | — | `ViewerCertificateException` | Not Vulnerable |
| **Agile CRM** | `.agilecrm.com` | `Sorry, this page is no longer available.` | Yes |
| **Airee.ru** | `.airee.ru` | `Ошибка 402. Сервис Айри.рф не оплачен` | Yes |
| **Anima** | `.animaapp.io` | `The page you were looking for does not exist` | Yes |
| **Gemfury** | `.furyns.com` | `404: This page could not be found.` | Yes |
| **Fly.io** | `.fly.dev` | `404 Not Found` | Edge Case |
| **Render** | `.onrender.com` | `Service is not available` | Edge Case |
| **Statuspage.io** | `.statuspage.io` | `Status Page Not Found` | Edge Case |
| **Pingdom** | `.pingdom.com` | `This public report page has not been activated` | Yes |
| **UserVoice** | `.uservoice.com` | `This UserVoice subdomain is currently available` | Yes |
| **Intercom** | `.custom.intercom.help` | `This page is reserved for future use` | Yes |
| **Campaign Monitor** | `.createsend.com` | `Double-check the URL` | Yes |
| **HackerOne** | `.hackerone.com` | `404 page not found` | Not Vulnerable |

---

## Exploitation Walkthroughs

### GitHub Pages Takeover

**Prerequisites:** CNAME points to `TARGET.github.io` and that Pages site is deleted/unclaimed.

```
1. Confirm: dig CNAME dev.example.com → TARGET.github.io
2. curl -s https://dev.example.com → "There isn't a GitHub Pages site here."
3. Check if GitHub user/org "TARGET" exists: https://github.com/TARGET
4. If user/org exists but no Pages site: create repo TARGET.github.io with gh-pages branch
5. If user/org doesn't exist: create account named "TARGET"
6. Create repo TARGET.github.io (or TARGET for org pages)
7. Add CNAME file to gh-pages branch containing: dev.example.com
8. Push any index.html — site goes live within ~5 minutes
9. dev.example.com now serves attacker content with valid HTTPS
```

**Proof of Concept Page:**
```html
<!DOCTYPE html>
<html>
<head><title>Subdomain Takeover PoC</title></head>
<body>
<h1>Subdomain Takeover PoC — dev.example.com</h1>
<p>This subdomain is vulnerable to takeover.</p>
<p>Discovered by: [your handle]</p>
<p>Timestamp: <script>document.write(new Date())</script></p>
</body>
</html>
```

### AWS S3 Takeover

**Prerequisites:** CNAME points to bucket URL that no longer exists.

```
1. Confirm: dig CNAME sub.example.com → sub.example.com.s3.amazonaws.com
   OR: dig CNAME → sub.example.com.s3-website-us-east-1.amazonaws.com
2. curl sub.example.com → "The specified bucket does not exist"
3. Determine region from CNAME (s3-website-us-east-1 = us-east-1)
4. Create S3 bucket named EXACTLY: sub.example.com (same region)
5. Enable static website hosting on the bucket
6. Upload index.html and error.html
7. Bucket now accessible via sub.example.com (DNS already points here)
```

**Note:** Bucket name must exactly match the CNAME target prefix.

### Heroku Takeover

```
1. Confirm: dig CNAME dev.example.com → SOMETHING.herokudns.com
2. curl dev.example.com → "No such app"
3. Create Heroku account + new app (any name)
4. In Heroku Dashboard: Settings → Domains → Add domain: dev.example.com
5. Deploy any app to Heroku
6. dev.example.com resolves to your Heroku app
```

### Azure Takeover

```
1. Confirm: CNAME → SOMETHING.azurewebsites.net
2. curl → NXDOMAIN or Azure error page
3. Check if SOMETHING is available in Azure
4. Create Azure Web App named SOMETHING in any subscription
5. Add custom domain dev.example.com to the web app
```

---

## Impact — What You Can Do With a Taken-Over Subdomain

### 1. Phishing and Social Engineering

Content served at `dev.example.com` appears under legitimate domain authority in:
- Browser address bar
- Search engine results (Google trusts the domain)
- Email links
- Social media previews

Create convincing login page at `login.example.com` (taken over) → harvest credentials.

### 2. Cookie Theft

If main application sets cookies with `Domain=.example.com`:
```http
Set-Cookie: session=SECRET; Domain=example.com; Secure
```

Attacker controlling `dev.example.com` can:
1. Host JavaScript that reads cookies: `document.cookie` (if HttpOnly not set)
2. Receive cookies automatically via CORS-credentialed requests
3. Set new cookies at parent domain scope from subdomain (if certain conditions met)

### 3. OAuth Redirect Token Theft

If `redirect_uri=https://dev.example.com/callback` is whitelisted in OAuth config:
```
https://accounts.google.com/oauth/authorize?
  client_id=VICTIM_APP_CLIENT_ID&
  redirect_uri=https://dev.example.com/callback&
  response_type=code&
  scope=email+profile
```

Victim authorizes → authorization code delivered to attacker's server → exchanged for victim's access token.

### 4. SSL Certificate Issuance

Let's Encrypt ACME HTTP-01 challenge served from attacker-controlled subdomain:
- Request cert for `dev.example.com`
- ACME challenge file served from attacker's server
- Valid SSL cert for `https://dev.example.com` issued within minutes
- Victim sees green padlock and valid certificate for legitimate domain

### 5. Content Security Policy (CSP) Bypass

If target's CSP includes:
```
Content-Security-Policy: script-src 'self' https://dev.example.com
```

Attacker serves malicious JS at `https://dev.example.com/script.js` → CSP bypassed → XSS possible on main domain.

### 6. Email Interception

Set MX records for taken-over subdomain:
- All email to `@dev.example.com` received by attacker
- Useful for intercepting password resets, confirmation emails
- Enables account takeover chains via email-delivered codes

### 7. CORS Bypass

If target has: `Access-Control-Allow-Origin: https://dev.example.com`

Attacker can make credentialed cross-origin requests from `dev.example.com` to the main application API and receive responses.

---

## Proof of Concept Best Practices

1. **Don't serve actual phishing pages** — create a simple HTML page that identifies the finding
2. **Include your handle and timestamp** in the PoC page
3. **Document the DNS resolution chain** (dig output)
4. **Screenshot** the response from the subdomain
5. **Take down your PoC** after report submission (or leave it for triage to verify)
6. **Don't steal actual cookies/tokens** — just demonstrate the attack is possible

**Minimal PoC Page:**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Subdomain Takeover - Security Research</title>
</head>
<body>
    <h1>Subdomain Takeover Proof of Concept</h1>
    <p><strong>Subdomain:</strong> dev.example.com</p>
    <p><strong>DNS CNAME:</strong> dev.example.com → old-target.github.io</p>
    <p><strong>Service:</strong> GitHub Pages</p>
    <p><strong>Researcher:</strong> [your handle]</p>
    <p><strong>Date:</strong> 2026-06-10</p>
    <p>This page demonstrates that the above subdomain is vulnerable to takeover.
       No malicious activity has been performed.</p>
</body>
</html>
```

---

## Reporting Template

```markdown
## Subdomain Takeover — dev.example.com

**Severity:** High
**CVSS:** 8.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

### Summary
The subdomain `dev.example.com` has a dangling CNAME record pointing to 
`old-project.github.io` which is no longer registered. An attacker can create 
a GitHub repository to take over this subdomain and serve arbitrary content.

### DNS Evidence
```
$ dig CNAME dev.example.com
dev.example.com.  300  IN  CNAME  old-project.github.io.

$ curl -I https://dev.example.com
HTTP/1.1 404 Not Found
[GitHub Pages "There isn't a GitHub Pages site here." response]
```

### Impact
- Phishing attacks appearing to originate from example.com
- Theft of session cookies set with Domain=.example.com
- OAuth redirect_uri abuse if dev.example.com is whitelisted
- Valid SSL certificate issuance for dev.example.com
- Content Security Policy bypass

### PoC
[Attach screenshot of PoC page served from the subdomain]

### Remediation
Remove the DNS CNAME record for `dev.example.com` pointing to `old-project.github.io`.
```

---

## Bug Bounty Severity Context

| Takeover Type | Impact | Typical Severity |
|---|---|---|
| Cookie domain `.example.com` session cookies stealable | ATO possible | Critical |
| OAuth redirect_uri whitelisted | Token theft → ATO | Critical |
| Just content serving (no auth flow) | Phishing, reputation | High |
| Static asset subdomain (cdn.example.com) | Limited phishing | Medium |
| Dev/staging subdomain with no auth flows | Phishing only | Medium |
| Expired third-party service, limited scope | Informational–Low | Low |
