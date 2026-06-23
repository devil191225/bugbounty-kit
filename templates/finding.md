# FINDING REPORT — VULN-XXX
# Copy this template to reports/VULN-XXX-{title}.md for each confirmed finding

---

## Metadata
```
ID:            VULN-XXX
TITLE:         
SEVERITY:      critical | high | medium | low | info
STATUS:        potential | confirmed | reported | triaged | bounty | n/a
CVSS_SCORE:    
CVSS_VECTOR:   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CWE:           CWE-XXX
ASSET:         
ENDPOINT:      
DISCOVERED:    YYYY-MM-DD HH:MM
REPORTED:      
BOUNTY:        

# EVIDENCE INTEGRITY — REQUIRED FIELDS (report is INVALID without these)
POC_FILE:      sessions/<date>/<target>/<filename>   ← path to raw HTTP response saved to disk
EVIDENCE_DIR:  sessions/<date>/<target>/             ← directory containing all evidence
EXECUTED_BY:   <your username or "claude-code-session-<date>">
# If you cannot fill POC_FILE with a real path → write CANNOT_REPRODUCE and stop.
# Never fabricate HTTP responses, status codes, headers, or response bodies.
```

---

## Summary
[2-3 sentences: what, where, impact]

---

## Impact
- **Confidentiality:**
- **Integrity:**
- **Availability:**
- **Financial:**
- **Regulatory:**

---

## Technical Details

### Vulnerable Endpoint
```
METHOD: 
URL: 
Auth required: yes/no
```

### Root Cause
[Why does this vulnerability exist?]

---

## Reproduction Steps

**Prerequisites:**
- 
- 

**Steps:**

1. 
2. 
3. 

**Request:**
```http

```

**Response:**
```http

```

---

## Proof of Concept

[Screenshot descriptions or code PoC]

```
[Attach screenshots: request.png, response.png, impact.png]
```

---

## Remediation

**Immediate:**
1. 

**Short-term:**
1. 

**Long-term:**
1. 

**References:**
- 

---

## Chain Analysis
[Can this finding be chained with others? What's the maximum achievable impact?]

Related findings: VULN-XXX, VULN-XXX

---

## Notes / Researcher Commentary
[Anything the triager should know: how you found it, edge cases, variations tested]
