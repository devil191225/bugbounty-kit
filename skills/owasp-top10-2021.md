# OWASP Top 10 2021 — Complete Vulnerability Index
> Source: https://owasp.org/Top10/2021/ | RAG Knowledge Base | Full detail preserved

---

## A01:2021 — Broken Access Control
**CWEs:** CWE-22, CWE-23, CWE-35, CWE-59, CWE-200, CWE-201, CWE-219, CWE-264, CWE-275, CWE-276, CWE-284, CWE-285, CWE-352, CWE-359, CWE-377, CWE-402, CWE-425, CWE-441, CWE-497, CWE-538, CWE-540, CWE-548, CWE-552, CWE-566, CWE-601, CWE-639, CWE-651, CWE-668, CWE-706, CWE-862, CWE-863, CWE-913, CWE-922, CWE-1275 (34 total)

**Description:** Access control enforces policy such that users cannot act outside of their intended permissions. Failures allow attackers to access unauthorized functionality or data — such as viewing other users' accounts, modifying other users' data, or acting with elevated privilege. This is the most prevalent category in the 2021 dataset, found in 94% of tested applications with over 318,000 occurrences.

**Vulnerability types covered:** IDOR (insecure direct object reference), privilege escalation, force browsing to restricted pages, path traversal, parameter tampering, missing access controls on API methods (POST/PUT/DELETE), JWT/metadata manipulation, CORS misconfiguration enabling unauthorized API access, mass assignment

**Skill files:** portswigger-injection.md (Access Control section), auth-bypass.md, api-testing.md, portswigger-advanced.md (CORS section)

---

## A02:2021 — Cryptographic Failures
**CWEs:** CWE-259, CWE-261, CWE-296, CWE-310, CWE-319, CWE-321, CWE-322, CWE-323, CWE-324, CWE-325, CWE-326, CWE-327, CWE-328, CWE-329, CWE-330, CWE-331, CWE-335, CWE-336, CWE-337, CWE-338, CWE-340, CWE-347, CWE-523, CWE-720, CWE-757, CWE-759, CWE-760, CWE-780, CWE-818, CWE-916 (29 total)

**Description:** Previously called "Sensitive Data Exposure," renamed to focus on root causes. Covers failures in cryptography — or complete absence of it — that result in exposure of sensitive data such as passwords, credit card numbers, health records, and business secrets both in transit and at rest.

**Vulnerability types covered:** Unencrypted data transmission (cleartext HTTP/SMTP/FTP), weak or deprecated cipher algorithms (RC4, DES, 3DES), insecure key storage and hardcoded keys, missing certificate validation / improper TLS configuration, weak password hashing (MD5, SHA1, unsalted hashes), insecure padding (ECB mode, PKCS#1 v1.5), insufficient entropy / weak PRNG, JWT algorithm confusion (none/HS256 downgrade), rainbow table attacks against unsalted hashes

**Skill files:** portswigger-advanced.md (JWT section), portswigger-advanced.md (OAuth section)

---

## A03:2021 — Injection
**CWEs:** CWE-20, CWE-74, CWE-75, CWE-77, CWE-78, CWE-79, CWE-80, CWE-83, CWE-87, CWE-88, CWE-89, CWE-90, CWE-91, CWE-93, CWE-94, CWE-95, CWE-96, CWE-97, CWE-98, CWE-99, CWE-113, CWE-116, CWE-138, CWE-184, CWE-470, CWE-471, CWE-564, CWE-610, CWE-643, CWE-644, CWE-652, CWE-917 (33 total)

**Description:** Injection occurs when hostile data is sent to an interpreter as part of a command or query. An attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization. This includes XSS (now merged into this category from 2017), and covers 94% of applications with an average incidence rate of 3% across 274,228 instances.

**Vulnerability types covered:** SQL injection (classic, blind, time-based, UNION-based), NoSQL injection, OS command injection, LDAP injection, XSS (reflected, stored, DOM-based), ORM injection, Server-Side Template Injection (SSTI), Expression Language / OGNL injection, HTTP header injection, XML injection, file path injection

**Skill files:** portswigger-injection.md, api-testing.md

---

## A04:2021 — Insecure Design
**CWEs:** CWE-73, CWE-183, CWE-209, CWE-213, CWE-235, CWE-256, CWE-257, CWE-266, CWE-269, CWE-280, CWE-311, CWE-312, CWE-313, CWE-316, CWE-419, CWE-430, CWE-434, CWE-444, CWE-451, CWE-472, CWE-501, CWE-522, CWE-525, CWE-539, CWE-579, CWE-598, CWE-602, CWE-642, CWE-646, CWE-650, CWE-653, CWE-656, CWE-657, CWE-799, CWE-807, CWE-840, CWE-841, CWE-927, CWE-1021, CWE-1173 (40 total)

**Description:** New category in 2021 that distinguishes architectural and design flaws from implementation bugs. Represents missing or ineffective security controls that were never present in the design — failures that cannot be fixed by a perfect implementation of a flawed design. Requires secure design patterns, threat modeling, and reference architectures.

**Vulnerability types covered:** Business logic flaws (rate limit bypass, workflow abuse, inventory exhaustion), insecure credential recovery flows (security questions), missing anti-automation controls, trust boundary violations, client-side enforcement of server-side logic, insecure file upload design, missing rate limiting on sensitive operations, exposure of sensitive data in URL parameters (CWE-598), insufficient anti-bot protections

**Skill files:** logic-bugs.md, portswigger-injection.md (file upload), api-testing.md

---

## A05:2021 — Security Misconfiguration
**CWEs:** CWE-2, CWE-11, CWE-13, CWE-15, CWE-16, CWE-260, CWE-315, CWE-520, CWE-526, CWE-537, CWE-541, CWE-547, CWE-611, CWE-614, CWE-756, CWE-776, CWE-942, CWE-1004, CWE-1032, CWE-1174 (20 total)

**Description:** Security misconfiguration is the most commonly seen issue and results from insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages exposing sensitive information. All application layers are in scope: network, platform, web server, application server, database, framework, and custom code.

**Vulnerability types covered:** Default credentials left unchanged, unnecessary features/ports/services enabled, missing security headers (CSP, HSTS, X-Frame-Options), verbose error messages / stack traces leaking internals, directory listing enabled, XXE via misconfigured XML parser (CWE-611), insecure cloud storage permissions (public S3 buckets), missing HttpOnly/Secure cookie flags (CWE-614), XXE billion laughs (CWE-776), CORS wildcard misconfiguration (CWE-942), exposed admin interfaces

**Skill files:** portswigger-injection.md (XXE section), recon.md, cloud-enum.md, portswigger-advanced.md (CORS section)

---

## A06:2021 — Vulnerable and Outdated Components
**CWEs:** CWE-937, CWE-1035, CWE-1104

**Description:** Components such as libraries, frameworks, and other software modules run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Organizations that don't track component versions, monitor for vulnerabilities (CVE/NVD), or patch in a timely manner are exposed to this risk across their entire software supply chain.

**Vulnerability types covered:** Known CVE exploitation in unpatched third-party libraries (e.g., CVE-2017-5638 Struts2 RCE), outdated OS/web server/database versions with public exploits, Heartbleed-style protocol-level CVEs in embedded components, unmaintained dependencies with no upstream security fixes, transitive dependency vulnerabilities (nested packages), outdated CMS plugins and themes

**Skill files:** recon.md

---

## A07:2021 — Identification and Authentication Failures
**CWEs:** CWE-255, CWE-259, CWE-287, CWE-288, CWE-290, CWE-294, CWE-295, CWE-297, CWE-300, CWE-302, CWE-304, CWE-306, CWE-307, CWE-346, CWE-384, CWE-521, CWE-613, CWE-620, CWE-640, CWE-798, CWE-940, CWE-1216 (22 total)

**Description:** Previously "Broken Authentication," covers failures in confirming user identity, authentication, and session management. Weaknesses allow attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users' identities temporarily or permanently.

**Vulnerability types covered:** Credential stuffing and password spraying (automated brute force), default or weak passwords, broken password reset flows (predictable tokens, no expiry), missing or bypassable multi-factor authentication (2FA bypass), plaintext or weakly hashed password storage, session token exposed in URL, session fixation, missing session invalidation on logout or timeout, hardcoded credentials (CWE-798), authentication bypass via direct object reference (CWE-306)

**Skill files:** portswigger-injection.md (Authentication section), auth-bypass.md, portswigger-advanced.md (OAuth/JWT sections), api-testing.md

---

## A08:2021 — Software and Data Integrity Failures
**CWEs:** CWE-345, CWE-353, CWE-426, CWE-494, CWE-502, CWE-565, CWE-784, CWE-829, CWE-830, CWE-915 (10 total)

**Description:** New 2021 category covering failures to protect against integrity violations in software update pipelines, critical data, and CI/CD workflows. Encompasses scenarios where applications rely on plugins, libraries, or modules from untrusted sources without verifying their authenticity. Insecure deserialization (previously a standalone 2017 category) is included here as a primary sub-class.

**Vulnerability types covered:** Insecure deserialization (Java serialization RCE, pickle deserialization), supply chain compromise via poisoned build pipelines or dependencies (SolarWinds-style), unsigned/unverified firmware or software auto-updates, prototype pollution (CWE-915), untrusted CDN inclusion (CWE-829/830), insecure CI/CD pipeline access allowing code injection, cookie tampering without integrity checks (CWE-565/784), dependency confusion attacks

**Skill files:** portswigger-advanced.md (Prototype Pollution section), api-testing.md

---

## A09:2021 — Security Logging and Monitoring Failures
**CWEs:** CWE-117, CWE-223, CWE-532, CWE-778 (4 total)

**Description:** Insufficient logging and monitoring, coupled with missing or ineffective incident response, allows attackers to further attack systems, maintain persistence, and pivot to more systems. Most breach studies show the time to detect a breach is over 200 days. Covers the inability to detect, escalate, and respond to active attacks.

**Vulnerability types covered:** Missing audit logs for logins, failed logins, and high-value transactions (CWE-223/778), sensitive data written to log files (CWE-532), log injection / log forging (CWE-117), no real-time alerting on suspicious activity, logs stored only locally with no centralized SIEM, missing integrity controls on audit trails, absence of monitoring for anomalous account behavior

**Skill files:** web-vulns.md, recon.md

---

## A10:2021 — Server-Side Request Forgery (SSRF)
**CWEs:** CWE-918

**Description:** SSRF flaws occur when a web application fetches a remote resource based on a user-supplied URL without adequate validation. An attacker can coerce the application to send a crafted request to an unexpected destination — even when protected by a firewall or VPN. The frequency and severity of SSRF are increasing as modern architectures rely heavily on URL-fetching functionality and cloud services expose metadata endpoints.

**Vulnerability types covered:** Basic SSRF to internal services (localhost/127.0.0.1), cloud metadata endpoint exfiltration (AWS IMDSv1 at 169.254.169.254, GCP/Azure equivalents), SSRF for internal port scanning and network mapping, blind SSRF (out-of-band via DNS/HTTP callbacks), SSRF filter bypass (DNS rebinding, IPv6, URL encoding, alternate IP notation), SSRF to RCE via internal service exploitation, SSRF chained with CSRF or open redirect, file:// scheme abuse for local file read

**Skill files:** portswigger-injection.md (SSRF section), api-testing.md, chain-builder.md

---

## Quick Reference Matrix

| Code | Category | Primary Skill Files |
|------|----------|-------------------|
| A01 | Broken Access Control | portswigger-injection.md, auth-bypass.md, api-testing.md |
| A02 | Cryptographic Failures | portswigger-advanced.md (JWT/OAuth) |
| A03 | Injection | portswigger-injection.md, api-testing.md |
| A04 | Insecure Design | logic-bugs.md, portswigger-injection.md (file upload) |
| A05 | Security Misconfiguration | recon.md, cloud-enum.md, portswigger-advanced.md (CORS) |
| A06 | Vulnerable and Outdated Components | recon.md |
| A07 | Identification and Authentication Failures | auth-bypass.md, portswigger-advanced.md (OAuth/JWT) |
| A08 | Software and Data Integrity Failures | portswigger-advanced.md (Prototype Pollution) |
| A09 | Security Logging and Monitoring Failures | web-vulns.md, recon.md |
| A10 | Server-Side Request Forgery (SSRF) | portswigger-injection.md, api-testing.md, chain-builder.md |

---

## Key Notes (2021 vs 2017 Changes)
- **A03 Injection** now absorbs XSS, which was a standalone A07 in 2017
- **A04 Insecure Design** and **A08 Software and Data Integrity Failures** are new in 2021
- **A08** absorbs the 2017 standalone "A08 Insecure Deserialization" and expands it to supply chain
- **A10 SSRF** is new to 2021, mapping to a single CWE (CWE-918), reflecting its rapid rise with cloud-native architectures
