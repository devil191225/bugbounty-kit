# MITRE ATT&CK Enterprise — Web & Application Security Reference
> Source: https://attack.mitre.org/ | RAG Knowledge Base | Full detail preserved

---

## Enterprise Tactics — Full List (15 Tactics)

| ID | Tactic | One-Line Description |
|---|---|---|
| TA0043 | Reconnaissance | Adversary gathers information to plan future operations |
| TA0042 | Resource Development | Adversary establishes infrastructure and resources to support operations |
| TA0001 | Initial Access | Adversary tries to get into your network or systems |
| TA0002 | Execution | Adversary tries to run malicious code |
| TA0003 | Persistence | Adversary tries to maintain their foothold across reboots and resets |
| TA0004 | Privilege Escalation | Adversary tries to gain higher-level permissions |
| TA0005 | Stealth | Adversary hides and conceals actions to appear as normal behavior |
| TA0112 | Defense Impairment | Adversary breaks security mechanisms so defenders can't see or trust what's happening |
| TA0006 | Credential Access | Adversary tries to steal account names and passwords |
| TA0007 | Discovery | Adversary tries to figure out your environment |
| TA0008 | Lateral Movement | Adversary tries to move through your environment |
| TA0009 | Collection | Adversary tries to gather data of interest to their goal |
| TA0011 | Command and Control | Adversary communicates with compromised systems to control them |
| TA0010 | Exfiltration | Adversary tries to steal data |
| TA0040 | Impact | Adversary manipulates, interrupts, or destroys systems and data |

**Bug bounty relevance by tactic:** Initial Access and Credential Access are primary hunting zones. Discovery and Execution map to post-exploitation impact chains used to demonstrate severity. Stealth and Defense Impairment map to WAF/filter bypass primitives.

---

## T1190 — Exploit Public-Facing Application
**Tactic:** Initial Access (TA0001)
**Platforms:** Web servers, databases, network devices, cloud-hosted apps, containers

**Description:** Adversaries exploit vulnerabilities in internet-facing systems to gain initial access. Attack surfaces include web apps, APIs, standard services (SSH, SMB), network device management interfaces, and cloud/container ingress points. Misconfigurations, unpatched CVEs, and logic flaws are all valid entry paths.

**Detection Signals:**
- Abnormal HTTP/S request patterns to public endpoints followed by elevated error codes and unexpected process spawning
- Suspicious access log entries preceding server crashes or shell execution
- Container processes spawning interactive shells via ingress exploitation
- Cloud load balancer logs showing exploit patterns followed by metadata API (IMDS) access

**Mitigations:**
- Application isolation and sandboxing
- Web Application Firewall (WAF) deployment
- Network traffic filtering and segmentation
- Privileged account management
- Regular patching and vulnerability scanning

**Bug Bounty Angle:** Primary technique when testing any SaaS or web target. Every SSRF, SQLi, RCE, deserialization, and path traversal finding maps here. Demonstrating impact via metadata API access (IMDS) upgrades severity significantly on cloud-hosted targets. Showing shell-spawn potential is the clearest path to Critical.

---

## T1133 — External Remote Services
**Tactics:** Initial Access (TA0001), Persistence (TA0003)
**Platforms:** VPN, RDP, Citrix, SSH, VNC, Docker/Kubernetes APIs

**Description:** Adversaries abuse externally exposed remote services to gain initial access or maintain persistence using valid or stolen credentials. In cloud/container environments, unauthenticated Docker or Kubernetes API exposure is a direct exploitation path without requiring credentials. Legitimate-looking access makes this hard to distinguish from normal user behavior.

**Detection Signals:**
- Unusual external remote access attempts with failed logins followed by success from atypical geolocations or outside business hours
- SSH/VPN/RDP authentication attempts from external IPs followed by successful logon and remote shell activity
- Connections to exposed container API surfaces from unauthorized external IPs, followed by anomalous container creation

**Mitigations:**
- Disable unnecessary remote services (M1042)
- Centralize remote access through VPN concentrators (M1035)
- Require MFA for all remote accounts (M1032)
- Use network proxies/gateways to block direct remote access (M1030)

**Bug Bounty Angle:** Finding an unauthenticated Kubernetes API, an RDP port with no MFA, or an admin panel exposed to the internet is a direct T1133 finding. On GitLab targets, exposed container registries and API endpoints without auth are prime candidates. Severity is typically High–Critical.

---

## T1078 — Valid Accounts
**Tactics:** Initial Access (TA0001), Persistence (TA0003), Privilege Escalation (TA0004), Stealth (TA0005)
**Sub-techniques:** Default Accounts (T1078.001), Domain Accounts (T1078.002), Local Accounts (T1078.003), Cloud Accounts (T1078.004)

**Description:** Adversaries obtain and abuse legitimate credentials to bypass access controls, blending in with normal user activity. This spans default credentials, credentials obtained via phishing or credential dumps, and cloud IAM accounts. Because the access pattern is indistinguishable from normal user behavior, this technique is highly effective for both initial access and long-term persistence.

**Detection Signals:**
- Anomalous logon patterns and abnormal logon types (e.g., service account used interactively)
- IdP log anomalies: impossible travel, geographic inconsistencies, multiple MFA failures
- Cloud account usage from unexpected nodes or IP addresses

**Mitigations:**
- Multi-factor authentication across all account types (M1032)
- Conditional access policies blocking non-compliant devices or out-of-range IPs (M1036)
- Routine permission audits; disable unauthorized default accounts (M1026)
- Strong password policies; no default credential reuse (M1027)

**Bug Bounty Angle:** Default credentials on admin panels, API keys committed to public repos, and OAuth token leakage all fall under T1078.004 (Cloud Accounts). Finding a working default admin credential is typically Critical. Any account takeover chain ultimately results in Valid Accounts access — this technique is your impact statement for ATO reports.

---

## T1552 — Unsecured Credentials
**Tactic:** Credential Access (TA0006)
**Platforms:** Containers, IaaS, Linux, Windows, macOS, SaaS, Network Devices, Identity Providers

**Description:** Adversaries search compromised or misconfigured systems for credentials stored without adequate protection — plaintext config files, shell history, private keys, browser-saved passwords, environment variables, and cloud instance metadata. In bug bounty it manifests as exposed secrets in public repositories, debug endpoints, or misconfigured cloud storage.

**Detection Signals:**
- Unusual access to `.bash_history`, registry paths, or private key files by scripting tools or unauthorized users
- Reading of `/etc/shadow`, `~/.ssh/id_rsa`, or keychain files by non-privileged processes
- Unauthorized API calls to retrieve secrets or modify SSO configuration
- Access to container image layers or mounted Kubernetes secrets by non-orchestration processes

**Mitigations:**
- Store cryptographic keys on separate hardware (HSM/TPM), not locally
- Restrict Instance Metadata API (IMDS) access; deploy WAF protections
- Prohibit credential storage in registry or plaintext config files

**Bug Bounty Angle:** One of the highest-yield techniques in bug bounty. Exposed `.env` files, hardcoded API keys in JS bundles, secrets in Docker image layers, IMDS access via SSRF, and leaked tokens in error responses all map here. On GitLab/Shopify targets, look for CI/CD variable leakage, exposed runner tokens, and secrets in commit history.

---

## T1110 — Brute Force
**Tactic:** Credential Access (TA0006)
**Sub-techniques:** Password Guessing, Password Cracking, Password Spraying, Credential Stuffing

**Description:** Adversaries systematically attempt to guess or crack credentials through repetitive login attempts, either against live services or offline against obtained hashes. Password spraying (one common password against many accounts) and credential stuffing (breach-list reuse) are the modern variants most relevant to web applications.

**Detection Signals:**
- High-volume failed logon attempts followed by successful authentication from a suspicious user or IP
- Password spraying patterns — many accounts, few attempts each, compressed timeframe
- Spike in failed SaaS logins preceding successful access

**Mitigations:**
- Account lockout policies after failed login thresholds (M1036)
- MFA on all externally facing services (M1032)
- Password requirements aligned with NIST 800-63B (M1027)

**Bug Bounty Angle:** Most programs explicitly exclude automated brute force from scope — check the policy first. However, *reporting* the absence of brute force protections (no rate limiting, no lockout, no CAPTCHA on login) is valid and reportable as a misconfiguration.

---

## T1059 — Command and Scripting Interpreter
**Tactic:** Execution (TA0002)
**Sub-techniques:** PowerShell, Windows Command Shell, Unix Shell, Python, JavaScript, Network Device CLI, Cloud API, AppleScript

**Description:** Adversaries abuse built-in command and scripting interpreters to execute malicious code. These are standard system components, making execution blend with normal administrative activity. Malicious payloads are typically delivered via initial access vectors and executed through these interpreters, often with encoding or obfuscation to evade detection.

**Detection Signals:**
- Scripting interpreters (powershell.exe, cmd.exe) executing outside normal hours or with encoded/obfuscated arguments
- Shell interpreters (bash, sh, python, perl) launched by unexpected parent processes, especially chaining netcat or curl

**Mitigations:**
- AV/EDR with automatic quarantine (M1049)
- Application control and PowerShell Constrained Language Mode (M1038)
- Code signing enforcement where feasible (M1045)

**Bug Bounty Angle:** T1059 is your impact demonstration technique. When you find an RCE, the execution is T1059. Showing `id`, `whoami`, `curl attacker.com` in your PoC demonstrates T1059. For SSTI, command injection, or deserialization bugs, explicitly calling out what interpreter is being invoked upgrades your report's technical credibility and CVSS score.

---

## T1566 — Phishing
**Tactic:** Initial Access (TA0001)
**Sub-techniques:** Spearphishing Attachment, Spearphishing Link, Spearphishing via Service, Spearphishing Voice

**Description:** Adversaries use electronically delivered social engineering to gain system access. This ranges from mass phishing campaigns to targeted spearphishing with high-fidelity impersonation, thread hijacking, and legitimate-looking domains.

**Mitigations:**
- Email authentication: SPF, DKIM, DMARC configuration (M1054)
- Email gateway scanning and malicious attachment removal (M1031)
- User security awareness training (M1017)

**Bug Bounty Angle:** Phishing is typically out of scope for most bug bounty programs. However, infrastructure that *enables* phishing is reportable: subdomain takeovers usable for phishing, missing DMARC/SPF allowing email spoofing, open redirects that can launder phishing links, or OAuth flows enabling consent phishing. Missing DMARC on a primary domain is a Medium–High finding.

---

## T1539 — Steal Web Session Cookie
**Tactic:** Credential Access (TA0006)
**Platforms:** Linux, Windows, macOS, SaaS, Identity Providers

**Description:** Adversaries steal web application session cookies to gain authenticated access without requiring username/password credentials. Cookies can be extracted from browser disk storage, browser process memory, or intercepted over the network. Critically, stolen session cookies bypass MFA entirely because the authentication event has already occurred.

**Detection Signals:**
- Session cookies reused from unusual geolocations or user agents without reauthentication
- Suspicious access to Chrome's Cookies SQLite DB or memory reads of browser processes

**Mitigations:**
- Hardware-based MFA tokens (YubiKey, FIDO2); Conditional Access requiring trusted device binding (M1032)
- Short cookie validity windows; configure automatic cookie deletion (M1054)
- Keep browsers and password managers up to date (M1051)

**Bug Bounty Angle:** XSS findings are the primary cookie theft vector — demonstrating `document.cookie` exfiltration directly demonstrates T1539. Additionally: session cookies without `HttpOnly` (accessible to JavaScript), missing `Secure` flag (transmitted over HTTP), absent `SameSite` attribute (CSRF-enabled cookie theft), and overly long session lifetimes without re-auth are all T1539-adjacent findings. Cookie theft bypassing MFA is a Critical-tier impact narrative.

---

## Bug Bounty Tactic Coverage Map

| ATT&CK Technique | Primary Bug Class | Typical Severity |
|---|---|---|
| T1190 Exploit Public-Facing App | RCE, SSRF, SQLi, Deserialization, Path Traversal | Critical–High |
| T1133 External Remote Services | Exposed admin panels, unauth APIs, missing MFA on remote access | Critical–High |
| T1078 Valid Accounts | Default creds, ATO, OAuth token abuse, cloud IAM misconfig | Critical–High |
| T1552 Unsecured Credentials | Exposed secrets, env files, IMDS via SSRF, leaked tokens | Critical–High |
| T1110 Brute Force | Missing rate limiting, no lockout (reportable misconfig) | Low–Medium |
| T1059 Command Interpreter | RCE impact demonstration, command injection | Critical (impact chain) |
| T1566 Phishing | Missing DMARC/SPF, open redirect, subdomain takeover | Medium–High |
| T1539 Steal Web Session Cookie | XSS cookie theft, missing HttpOnly/Secure/SameSite | High–Critical |
| T1552.004 | Private key exposure, SSH key leakage in repos | Critical |

---

## Using ATT&CK in Bug Bounty Reports

When writing a report, map your finding to ATT&CK to show triage teams the real-world kill chain:

```
Initial Access: T1190 (Exploit Public-Facing Application) — SQLi on /api/search
  ↓
Credential Access: T1552.001 (Credentials in Files) — /etc/passwd readable via SQLi
  ↓
Privilege Escalation: T1078.003 (Local Accounts) — root credential hash cracked
  ↓
Impact: T1565 (Data Manipulation) / T1486 (Data Encrypted for Impact)
```

This technique chain:
1. Shows you understand the full attack scenario
2. Justifies Critical CVSS scores
3. Demonstrates business impact beyond just the technical bug
