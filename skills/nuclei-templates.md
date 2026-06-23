# Nuclei Custom Template Guide
> Source: ProjectDiscovery Nuclei docs, community templates | RAG Knowledge Base | Full detail preserved
> Related: `recon.md`, `tools/vuln_scanner.sh`, `nuclei/custom/`

---

## Overview

When you find a bug pattern on one target, write a Nuclei template to re-run on other programs automatically. Turns one finding into a hunting capability.

---

## Template Structure

```yaml
id: custom-idor-user-api

info:
  name: User API IDOR - Sequential ID
  author: your-handle
  severity: high
  description: Detects IDOR on /api/users/{id} endpoint
  tags: idor,api,auth
  reference:
    - https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
  classification:
    cwe-id: CWE-639
    owasp-api: API1:2023

http:
  - raw:
      - |
        GET /api/users/{{user_id}} HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{token}}

    payloads:
      user_id:
        - "1"
        - "2"
        - "100"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - '"email"'
          - '"phone"'
        condition: and
      - type: dsl
        dsl:
          - 'len(body) > 100'
```

---

## When to Write a Template

| Situation | Template type |
|---|---|
| Found IDOR pattern | HTTP raw with ID payloads |
| Specific header misconfig | Header matcher |
| Exposed admin panel path | Path + status matcher |
| GraphQL introspection open | Body contains __schema |
| Subdomain takeover fingerprint | DNS + HTTP body hash |
| CVE for target's exact version | Public CVE template customized |
| OAuth misconfig pattern | Multi-step (advanced) |

---

## Key Sections

### info block
```yaml
info:
  name: Human readable name
  author: handle
  severity: info|low|medium|high|critical|unknown
  tags: tag1,tag2
  metadata:
    max-request: 10
```

### HTTP requests
```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/api/v1/admin/users"

    headers:
      User-Agent: Mozilla/5.0

    matchers:
      - type: word
        words:
          - "admin panel"
          - "Dashboard"
        condition: or
```

### DNS templates
```yaml
dns:
  - name: "{{FQDN}}"
    type: CNAME
    matchers:
      - type: word
        words:
          - "github.io"
          - "herokuapp.com"
```

### Workflow templates (multi-step)
```yaml
workflows:
  - template: technologies/spring-detect.yaml
    subtemplates:
      - template: vulnerabilities/spring-actuator.yaml
```

---

## Matchers Reference

```yaml
# Status code
- type: status
  status: [200, 403]

# Body contains
- type: word
  part: body
  words: ["admin", "dashboard"]

# Regex
- type: regex
  part: body
  regex: ["user_id.*[0-9]+"]

# JSON field
- type: json
  json:
    - '.data.email'

# DSL expressions
- type: dsl
  dsl:
    - 'status_code == 200'
    - 'contains(body, "email")'

# Binary hash
- type: dsl
  dsl:
    - 'status_code == 200 && contains(body, "swagger")'
```

---

## Extractors (For Chaining)

```yaml
extractors:
  - type: regex
    name: user-email
    part: body
    group: 1
    regex:
      - '"email":"([^"]+)"'
```

Use extracted values in subsequent requests with `{{user-email}}`.

---

## Variables & Payloads

```yaml
variables:
  token: "YOUR_TEST_TOKEN"

payloads:
  paths:
    - admin
    - administrator
    - api/admin

attack: batteringram  # pitchfork, clusterbomb
```

For authorized testing only — don't hardcode production stolen tokens in shared templates.

---

## File Organization in Kit

```
nuclei/custom/
├── graphql-introspection.yaml
├── open-redirect-param.yaml
├── exposed-git-config.yaml
└── README.md
```

Run:
```bash
nuclei -t nuclei/custom/ -l live-hosts.txt -o findings.txt
```

---

## Example Templates

### GraphQL Introspection
```yaml
id: graphql-introspection

info:
  name: GraphQL Introspection Enabled
  severity: medium
  tags: graphql,api

http:
  - raw:
      - |
        POST /graphql HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"query":"{__schema{types{name}}}"}

    matchers:
      - type: word
        words:
          - "__schema"
          - "types"
        condition: and
```

### Spring Actuator Exposure
```yaml
id: spring-actuator-env

info:
  name: Spring Boot Actuator /env Exposed
  severity: high
  tags: spring,exposure,misconfig

http:
  - method: GET
    path:
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/env"

    matchers:
      - type: word
        words:
          - "propertySources"
          - "systemProperties"
        condition: and
      - type: status
        status: [200]
```

### SAML Metadata Exposure
```yaml
id: saml-metadata-exposed

info:
  name: SAML Metadata Publicly Accessible
  severity: info
  tags: saml,sso

http:
  - method: GET
    path:
      - "{{BaseURL}}/saml/metadata"
      - "{{BaseURL}}/FederationMetadata/2007-06/FederationMetadata.xml"

    matchers:
      - type: word
        words:
          - "EntityDescriptor"
          - "SingleSignOnService"
        condition: and
```

---

## Best Practices

```
[ ] Unique id field (no collision with public templates)
[ ] Accurate severity — avoid crying wolf on info findings
[ ] Low false-positive rate — test on 10+ hosts before deploying
[ ] Include CWE/OWASP tags for filtering
[ ] rate-limit aware — don't DoS targets
[ ] Never include exploit payloads that cause damage in scan mode
[ ] Document auth requirements in description
[ ] Version pin nuclei for reproducibility
```

---

## Validation Workflow

```
1. Write template
2. Test against known-vulnerable lab (PortSwigger, DVWA, custom)
3. Test against original target (confirm detection)
4. Test against 5 unrelated hosts (measure false positive rate)
5. Add to `nuclei/custom/`
6. Run in /recon pipeline on new targets
```

---

## Integration with Kit

```bash
# In recon pipeline after httpx
nuclei -t nuclei/custom/ -l sessions/DATE/live.txt \
  -severity high,critical -o sessions/DATE/nuclei-custom.txt

# CVE sweep (existing)
/scan-cves <host>
```

---

## Related Files

- `recon.md` — nuclei in recon pipeline
- `nuclei/custom/` — starter custom templates
- `tools/vuln_scanner.sh` — scan wrapper
- `tools/hunt.py` — orchestrated hunt pipeline
- `subdomain-takeover.md` — takeover fingerprints for templates
- `owasp-api-top10-2023.md` — API vulnerability classes to template
