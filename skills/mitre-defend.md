# MITRE D3FEND — Defensive Countermeasures Reference
> Source: https://d3fend.mitre.org/ | RAG Knowledge Base | Full detail preserved
> Bug Bounty Perspective: "What does the ABSENCE of this defense look like as a finding?"

---

## D3FEND Tactic Overview (7 Top-Level Tactics)

### 1. MODEL
Understand and map what you have before you defend it. Asset inventory, network mapping, dependency graphing, risk assessment. Foundation for all other tactics.

### 2. HARDEN
Strengthen systems so attacks fail or are harder to execute:
- **Application Hardening (D3-AH)** — ASLR, stack canaries, CFI, code integrity
- **Credential Hardening (D3-CH)** — cert pinning, MFA, OTP, token binding, strong password policy
- **Message Hardening (D3-MH)** — message authentication, encryption, transfer agent auth
- **Platform Hardening (D3-PH)** — patching, disk encryption, TPM boot integrity, driver integrity
- **Source Code Hardening (D3-SCH)** — pointer validation, integer range validation, null checks, variable typing, credential scrubbing
- **Authentication Methods** — MFA (D3-MFA), certificate-based auth (D3-CBAN), token-based auth (D3-TBA), biometric auth (D3-BAN)

### 3. DETECT
Identify malicious activity through monitoring and analysis:
- **File Analysis (D3-FA)** — dynamic analysis, file hashing, content rules
- **Identifier Analysis (D3-ID)** — IP/domain/URL reputation, homoglyph detection
- **Network Traffic Analysis (D3-NTA)** — protocol anomaly detection, DNS analysis, connection attempt analysis
- **Platform Monitoring (D3-PM)** — FIM, application performance monitoring, application exception monitoring
- **Process Analysis (D3-PA)** — syscall analysis, process lineage, DB query string analysis, script execution analysis
- **User Behavior Analysis (D3-UBA)** — authentication event thresholding (D3-ANET), geolocation logon analysis, web session activity analysis, session duration analysis (D3-SDA)

### 4. ISOLATE
Limit adversary reach through segmentation, filtering, and mediation:
- **Access Mediation (D3-AMED)** — web session access mediation, credential transmission scoping, proxy/endpoint web server mediation
- **Content Filtering (D3-CF)** — file format verification, content rebuild, content quarantine, content validation (D3-CV)
- **Network Isolation (D3-NI)** — inbound/outbound traffic filtering, DNS allow/denylisting, email filtering, encrypted tunnels
- **Execution Isolation (D3-EI)** — executable allowlisting/denylisting, hardware/kernel process isolation
- **Access Policy Administration (D3-APA)** — file permissions, user account permissions, domain trust policy

### 5. DECEIVE
Deploy deceptive assets to detect and mislead attackers:
- **Decoy Environment (D3-DE)** — connected/integrated/standalone honeynets
- **Decoy Object (D3-DO)** — decoy files, decoy network resources, decoy session tokens, decoy user credentials, decoy personas

### 6. EVICT
Remove adversaries and their artifacts:
- **Credential Eviction (D3-CE)** — credential revocation, account locking, auth cache invalidation
- **Object Eviction (D3-OE)** — file eviction, disk erasure, registry key deletion
- **Process Eviction (D3-PE)** — process/session termination, host reboot
- **DNS Cache Eviction (D3-DNSCE)**, **Domain Registration Takedown (D3-DRT)**

### 7. RESTORE
Recover from compromise: credential reissuance, data recovery, system restoration.

---

## Application Hardening (D3-AH)

**ID:** D3-AH | **Tactic:** Harden | **Source:** https://d3fend.mitre.org/technique/d3f:ApplicationHardening/

**Description:** Makes executables more resilient against code injection and execution exploits by dynamically randomizing memory layout, validating memory contents, and monitoring for unusual instruction sequences.

**Key Sub-Techniques:**
- D3-SAOR — Segment Address Offset Randomization (ASLR)
- D3-SFCV — Stack Frame Canary Validation
- D3-CFI — Control Flow Integrity
- D3-ACH — Application Configuration Hardening
- D3-PSEP — Process Segment Execution Prevention (NX/DEP)
- D3-DCE — Dead Code Elimination
- D3-DRA — Disable Remote Access

**ATT&CK Techniques Countered:** Process Injection, Process Hollowing, Credential API Hooking, privilege escalation via memory corruption

**Bug bounty findings when this defense is absent:**

| Missing Sub-Technique | What It Looks Like | Finding Class |
|---|---|---|
| D3-ACH (App Config Hardening) | Server headers revealing framework versions (`X-Powered-By: PHP/7.2`, `Server: Apache/2.4.6`), debug endpoints in production (`/debug`, `/_profiler`, `/actuator`), stack traces in error responses | Information Disclosure / Verbose Error Handling |
| D3-DRA (Disable Remote Access) | Admin interfaces (phpMyAdmin, Kubernetes dashboard, internal API) exposed on public IPs without authentication | Exposed Admin Interface / Missing Authentication |
| Missing security headers | No `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options` | Missing Security Headers (Low–Medium) |
| D3-IRV (Integer Range Validation) | Integer overflow in pricing/quantity parameters | Type Confusion / Business Logic |
| D3-VTV (Variable Type Validation) | Type juggling / mass assignment vulnerabilities | Mass Assignment / Type Confusion |

---

## Authentication Event Thresholding (D3-ANET)

**ID:** D3-ANET | **Tactic:** Detect → User Behavior Analysis | **Source:** https://d3fend.mitre.org/technique/d3f:AuthenticationEventThresholding/

**Description:** Establishes a baseline of normal authentication behavior per user (device, geo, timing patterns), then evaluates new authentication events against configured thresholds to detect anomalous logins. Can trigger account locking or alerting.

**ATT&CK Techniques Countered:** Brute force (T1110), credential stuffing, valid account abuse (T1078), password spraying

**Known Limitation:** If malicious behavior statistically mirrors legitimate activity, detection thresholds won't trigger — slow, low-and-slow credential attacks can evade this entirely.

**Bug bounty findings when this defense is absent:**

| Missing Capability | What It Looks Like | Finding Class |
|---|---|---|
| No rate limiting on login endpoint | Send 100+ authentication attempts without triggering lockout or CAPTCHA | Broken Authentication / Credential Brute Force (OWASP A07) |
| No account lockout policy | Submit fixed valid username with wrong passwords rapidly — account never locks | Missing Account Lockout |
| No IP-based anomaly detection | Log in from US IP, immediately authenticate from different country with no step-up challenge | Missing Re-authentication / Insufficient Session Controls |
| No thresholding on password reset | `/forgot-password` or OTP endpoints have no rate limiting | Auth Bypass — Secondary Auth Flow |
| No authorization event thresholding (D3-AZET) | Rapid RBAC probe requests not rate-limited | Authorization Testing Gap |

---

## Web Application Firewall (D3FEND Artifact)

**D3FEND ID:** d3f:WebApplicationFirewall (artifact, not a technique node)
**Tactic:** Isolate (via Content Filtering D3-CF / Network Isolation)
**Source:** https://d3fend.mitre.org/dao/artifact/d3f:WebApplicationFirewall/

**Description:** Filters, monitors, and blocks HTTP traffic at the application layer (L7). Prevents SQLi, XSS, file inclusion, and security misconfigurations. In D3FEND, WAF is an *artifact* that implements the Content Filtering (D3-CF) and Network Isolation technique families.

**Bug bounty findings when this defense is absent or misconfigured:**

| Scenario | What It Looks Like | Finding Class |
|---|---|---|
| No WAF at all | Classic payload strings (`' OR 1=1--`, `<script>alert(1)`, `../../../etc/passwd`) reach the application unblocked | Direct Injection Vulnerability |
| WAF bypass via encoding | WAF present but bypassable — URL double-encoding, Unicode normalization, case variation, JSON payload embedding | WAF Bypass |
| WAF not covering all endpoints | `api.target.com` unprotected while `www.target.com` has a WAF | Security Control Gap |
| Content-Type confusion bypass | WAF tuned for `application/x-www-form-urlencoded` but API accepts `application/json` | WAF Bypass via Content-Type |
| Missing Content Validation at upload endpoints | File upload accepts `.php` disguised as `.jpg` (magic byte mismatch), polyglot files | Unrestricted File Upload / RCE |

---

## Content Validation / Input Validation (D3-CV)

**ID:** D3-CV | **Tactic:** Isolate | **Source:** https://d3fend.mitre.org/technique/d3f:ContentValidation/

**Description:** Verifies that input/file content complies with policy — analyzing file sections, enforcing format rules, and rejecting or sanitizing non-compliant content.

**Sub-Techniques:**
- D3-FFV — File Format Verification
- D3-FMVV — File Metadata Value Verification
- D3-FMCV — File Metadata Consistency Validation
- D3-FCDC — File Content Decompression Checking
- D3-FISV — File Internal Structure Verification
- D3-FMBV — File Magic Byte Verification

**Bug bounty findings when this defense is absent:**

| Missing Sub-Technique | What It Looks Like | Finding Class |
|---|---|---|
| D3-FFV / D3-FMBV | Upload `.php` renamed to `image.jpg` — server executes as PHP; upload `script.svg` — XSS fires | Unrestricted File Upload → RCE or Stored XSS |
| D3-FCDC | Upload a ZIP/gzip bomb (few KB compressed, GB decompressed) — server allocates memory | DoS via File Upload |
| Missing schema/type validation on API | Send string where integer expected → SQL fragment; send array where scalar expected → 500 error revealing stack trace | Mass Assignment, Type Confusion, Information Disclosure |
| D3-CV at GraphQL layer | No depth/complexity limits + no input sanitization on GraphQL queries | GraphQL Abuse, Injection, DoS |
| SSRF via unvalidated URL input | Application accepts URL parameter and fetches it without validating content or scheme | SSRF |
| XXE via unvalidated XML input | XML parser accepts external entity declarations without D3-CV for document structure | XXE → SSRF/LFI |

---

## Credential Hardening (D3-CH)

**ID:** D3-CH | **Tactic:** Harden | **Source:** https://d3fend.mitre.org/technique/d3f:CredentialHardening/

**Description:** Modifies system or network properties to protect credentials across their lifecycle: creation policy, transmission security, rotation, and binding credentials to specific connections/sessions.

**Sub-Techniques:**
- D3-CP — Certificate Pinning
- D3-CERO — Certificate Rotation
- D3-TB — Token Binding (binds session tokens to the TLS connection)
- D3-PR — Password Rotation
- D3-CDP — Change Default Credentials
- D3-SPP — Strong Password Policy
- D3-CRO — Credential Rotation
- D3-OTP — One-time Password

**ATT&CK Techniques Countered:** Brute force (T1110), credential dumping (T1003), Kerberos ticket theft (T1558), token/cookie theft (T1539), account manipulation (T1098)

**Bug bounty findings when this defense is absent:**

| Missing Sub-Technique | What It Looks Like | Finding Class |
|---|---|---|
| D3-CDP (default credentials not changed) | Try admin/admin, admin/password, root/root on web consoles, Jenkins, Grafana, Kibana | Default Credentials → Full Compromise |
| D3-SPP (no password complexity enforcement) | Registration endpoint accepts single-character passwords; no minimum length | Weak Password Policy |
| D3-OTP / MFA absent | Sensitive account actions require no second factor | Missing MFA on Sensitive Operations |
| Insecure token transmission | Session tokens sent over HTTP; `Secure` flag absent on auth cookies | Sensitive Data Exposure / Cookie Security Flags |
| D3-CP (no certificate pinning on mobile) | Mobile app performs SSL/TLS without pinning — Burp proxy intercepts trivially | Enables interception of all mobile traffic |
| D3-CRO (credential rotation absent) | Long-lived API keys or tokens that never expire; static secrets in source code | Hardcoded Credentials / Non-expiring Tokens |
| JWT without expiry / weak signing key | `alg:none` accepted, HS256 with guessable secret, `exp` claim not enforced | Broken Authentication via JWT Misconfiguration |

---

## Session Duration Analysis (D3-SDA)

**ID:** D3-SDA | **Tactic:** Detect → User Behavior Analysis | **Source:** https://d3fend.mitre.org/technique/d3f:SessionDurationAnalysis/

**Description:** Analyzes user session durations against historical behavior baselines to detect anomalies — unexpectedly long sessions indicating persistent unauthorized access or session hijacking.

**ATT&CK Techniques Countered:** Credential-based persistence, valid account abuse (T1078), web session cookie theft (T1539)

**Bug bounty findings when this defense is absent:**

| Missing Capability | What It Looks Like | Finding Class |
|---|---|---|
| No session timeout | Authenticate once, capture token, wait 24-48 hours — token still valid | Insufficient Session Expiration (CWE-613) |
| No session invalidation on logout | Click logout, capture pre-logout token, replay it — server still responds as authenticated | Broken Authentication — Session Not Invalidated |
| No session invalidation on password change | Change password, replay old session token — still valid | Session Fixation / Privilege Persistence |
| Absolute vs. idle timeout absent | JWT with `exp` set 1 year in future; cookie with `Max-Age` of years | Long-lived Session Tokens |
| Missing D3-ST on privilege escalation | Becoming admin does not issue new session token — old token persists with elevated privileges | Session Fixation Post-Privilege-Change |

---

## D3FEND Bug Bounty Quick Reference

| Absent D3FEND Defense | Technique ID | Bug Bounty Finding Class | Severity |
|---|---|---|---|
| No brute force threshold on login | D3-ANET | Credential Brute Force / No Rate Limit | Medium |
| No account lockout | D3-ANET | Broken Authentication | Medium |
| Default credentials not changed | D3-CDP | Default Creds → Full Compromise | Critical |
| No MFA on sensitive actions | D3-OTP / D3-MFA | Missing MFA | Medium–High |
| Non-expiring tokens / no rotation | D3-CRO | Hardcoded/Long-lived Credentials | High |
| Session not invalidated on logout | D3-ST | Broken Session Management | High |
| No session timeout | D3-SDA | Insufficient Session Expiration | Medium |
| File upload type not validated | D3-FFV / D3-FMBV | Unrestricted File Upload → RCE | Critical |
| XML input accepts external entities | D3-CV | XXE | High–Critical |
| URL input not validated (SSRF) | D3-CV | SSRF | High–Critical |
| API accepts untyped/unschema'd input | D3-CV | Mass Assignment / Type Confusion | Medium–High |
| WAF absent or bypassable | D3-CF | SQLi/XSS payload reaches app | High–Critical |
| Admin interfaces exposed publicly | D3-DRA | Exposed Admin Panel | High |
| Verbose error messages / stack traces | D3-ACH | Information Disclosure | Low–Medium |
| Missing security headers | D3-ACH | Security Misconfiguration | Low–Medium |
| No certificate pinning (mobile) | D3-CP | Enables interception | Informational |
