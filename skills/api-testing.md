# SKILL: API Security Testing
**REST, GraphQL, gRPC — modern APIs are where the money is.**

---

## API DISCOVERY FIRST

```bash
# Find all API endpoints from crawl data
grep -iE "api|v1|v2|v3|graphql|grpc|swagger|openapi" sessions/{DATE}/crawl-{TARGET}.txt | sort -u

# Check for API docs (often left exposed)
ffuf -u "https://{TARGET}/FUZZ" -w wordlists/api-docs.txt -mc 200,301
# Wordlist includes: swagger.json, openapi.json, api-docs, swagger-ui.html, docs, redoc

# Download and parse OpenAPI/Swagger spec if found
curl -sk https://{TARGET}/swagger.json | python3 scripts/swagger-parser.py
```

---

## REST API TESTING

### Authentication
```bash
# Test endpoints without auth header (remove Authorization entirely)
# Test with invalid/expired token
# Test with another user's token (horizontal)
# Test with low-privilege token on high-privilege endpoint (vertical)

# Check for API key in non-standard locations:
# X-API-Key header
# api_key query param
# apikey query param
```

### HTTP Method Abuse
```bash
# Test all HTTP methods on every endpoint
# Some endpoints only protect GET but not POST/PUT/DELETE
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo "--- $method ---"
  curl -sk -X $method "https://{TARGET}/api/v1/users/123" \
    -H "Authorization: Bearer {LOW_PRIV_TOKEN}" \
    -w "\nStatus: %{http_code}\n"
done
```

### Mass Assignment via API
```bash
# GET /api/users/me to see all user fields
# PUT /api/users/me with additional fields: role, verified, plan, admin
# Does the server accept and apply unexpected fields?
```

### API Versioning
```bash
# Old API versions often have less security
# If current is /api/v3/, test /api/v2/ and /api/v1/
# Also test: /api/, /v1/, /v2/, /api/beta/, /api/internal/
ffuf -u "https://{TARGET}/FUZZ/users" -w wordlists/api-versions.txt -mc 200,401,403
```

---

## GRAPHQL TESTING

### Introspection (Information Disclosure)
```bash
# Check if introspection is enabled (should be disabled in production)
curl -sk -X POST "https://{TARGET}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{__schema{types{name,fields{name}}}}"}'

# If it works: full schema dump
python3 scripts/graphql-introspect.py https://{TARGET}/graphql > sessions/{DATE}/graphql-schema-{TARGET}.json
```

### Query Depth Attack
```bash
# Test for query depth limits (DoS potential)
curl -sk -X POST "https://{TARGET}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{user{friends{friends{friends{friends{friends{id}}}}}}}"}'
```

### Batch Query Abuse
```bash
# Test if batching is enabled (can be used for rate limit bypass)
curl -sk -X POST "https://{TARGET}/graphql" \
  -H "Content-Type: application/json" \
  -d '[{"query":"mutation{login(email:\"test1@test.com\",password:\"pass1\"){token}}"},{"query":"mutation{login(email:\"test2@test.com\",password:\"pass2\"){token}}"}]'
```

### IDOR via GraphQL
```bash
# Try accessing other users' data by changing IDs in queries
# query { user(id: "victim-uuid") { email, phone, address } }
```

### GraphQL Injection
```bash
# Test field injection in arguments
# { user(id: "1 UNION SELECT * FROM users") { email } }
# { search(query: "test') OR ('1'='1") { results } }
```

---

## API RATE LIMITING

```bash
# Test authentication rate limiting (critical for account security)
# Send 100 rapid requests to login endpoint
for i in {1..100}; do
  curl -sk -o /dev/null -w "%{http_code}\n" \
    -X POST "https://{TARGET}/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@example.com","password":"wrong"}' &
done | sort | uniq -c

# Check if X-Forwarded-For rotation bypasses rate limit
for i in {1..20}; do
  curl -sk -o /dev/null -w "%{http_code}\n" \
    -X POST "https://{TARGET}/api/auth/login" \
    -H "X-Forwarded-For: 1.2.3.$i" \
    -d '{"email":"victim@example.com","password":"wrong"}'
done
```

---

## BROKEN OBJECT LEVEL AUTH (BOLA/IDOR) — API FOCUS

```bash
# BOLA is the #1 API vulnerability (OWASP API Security Top 10)
# Methodology:
# 1. Identify all object IDs in API responses
# 2. For each ID type, test access with another user's session
# 3. Test: numeric IDs, UUIDs, hashes, usernames, emails as identifiers

# Script to test IDOR across endpoint list:
python3 scripts/idor-tester.py \
  --endpoints sessions/{DATE}/api-endpoints-{TARGET}.txt \
  --token-a "{TOKEN_USER_A}" \
  --token-b "{TOKEN_USER_B}" \
  --output sessions/{DATE}/idor-results-{TARGET}.txt
```

---

## COMMON HIGH-VALUE API FINDINGS

| Finding | Where to Look | Typical Severity |
|---------|--------------|-----------------|
| BOLA/IDOR | Every ID parameter | High |
| Broken Function Level Auth | Admin endpoints with user token | High-Critical |
| Mass Assignment | PUT/PATCH profile/settings | Medium-High |
| Excessive Data Exposure | User objects leaking PII | Medium-High |
| Lack of Rate Limiting | Auth, OTP, reset endpoints | Medium |
| GraphQL Introspection | /graphql | Low-Medium |
| JWT Alg None | Authorization header | Critical |
| API Key in URL | Logs leak keys | High |
