# gRPC & Protobuf API Testing
> Source: OWASP API Security, grpc-security-python, HackTricks | RAG Knowledge Base | Full detail preserved
> Related: `api-testing.md`, `graphql-advanced.md`

---

## Overview

Modern backends increasingly expose gRPC alongside REST/GraphQL. gRPC uses HTTP/2 + Protocol Buffers. Often less tested — reflection enabled in prod, weak auth, injection in protobuf fields.

---

## Discovery

```
Common ports: 50051, 9090, 443 (gRPC over TLS)
Content-Type: application/grpc
Paths: /package.Service/Method
Tools detect: httpx -h2, grpcurl
```

### Identify gRPC
```bash
# HTTP/2 prior knowledge
curl -k --http2-prior-knowledge https://target:443

# grpcurl list services
grpcurl -plaintext target:50051 list
grpcurl target:443 list  # with TLS
```

---

## gRPC Server Reflection

Equivalent to GraphQL introspection — lists all services, methods, message types.

```bash
grpcurl -plaintext target:50051 describe
grpcurl target:443 list mypackage.MyService
grpcurl target:443 describe mypackage.MyService.MethodName
```

**If reflection enabled in production → full API map without proto files.**

Disable reflection in prod — report as info + test all discovered methods.

---

## Obtaining Proto Files

1. Server reflection (above)
2. GitHub leak: `.proto` files in repos
3. Mobile app decompile: protobuf descriptors
4. Burp gRPC plugin captures binary → decode with known proto
5. Black-box: protobuf field fuzzing (field numbers 1-100)

---

## Testing Methodology

```
Phase 1: Discovery
  [ ] Port scan 50051, 443 HTTP/2
  [ ] grpcurl list / describe
  [ ] Burp gRPC interception enabled

Phase 2: Auth
  [ ] Test methods without metadata (auth token)
  [ ] Test User A metadata → User B resource IDs
  [ ] JWT in metadata: authorization: Bearer ...

Phase 3: Input validation
  [ ] String fields: SQLi, SSTI, path traversal payloads
  [ ] Integer fields: -1, 0, MAX_INT, IDOR enumeration
  [ ] Repeated fields: oversized arrays (DoS if in scope)
  [ ] Nested messages: unexpected sub-message types

Phase 4: Logic
  [ ] Method enumeration for hidden admin RPCs
  [ ] Race conditions on streaming RPCs
  [ ] Client/server streaming abuse
```

---

## Authentication Metadata

gRPC auth typically in metadata headers:
```
authorization: Bearer eyJ...
x-api-key: KEY
client-id: ID
```

Test:
- Missing metadata on protected methods
- Expired/revoked token acceptance
- Algorithm confusion on JWT metadata
- Metadata injection: `authorization: Bearer token\r\nInjected: header`

---

## IDOR in gRPC

```protobuf
message GetUserRequest {
  int64 user_id = 1;
}
```

```bash
grpcurl -d '{"user_id": 1}' target:443 mypackage.UserService/GetUser
grpcurl -d '{"user_id": 2}' target:443 mypackage.UserService/GetUser
```

Same IDOR patterns as REST — test every ID field with cross-user tokens.

---

## Injection via Protobuf Fields

### String fields processed unsafely
```
name: "test' OR 1=1--"
url: "http://169.254.169.254/latest/meta-data/"
path: "../../../etc/passwd"
template: "{{7*7}}"
```

### Binary fields
Upload protobuf with embedded XML for XXE if server parses nested formats.

---

## Streaming RPC Abuse

### Server streaming
Server sends unbounded stream — resource exhaustion.

### Client streaming
Upload massive stream — DoS, buffer overflow in poorly written handlers.

### Bidirectional streaming
Auth checked only on initial message — send auth as User A, subsequent messages as User B operations.

---

## HTTP/2 Specific Attacks

gRPC requires HTTP/2:
- Request smuggling via H2 downgrade (see `portswigger-advanced.md`)
- HPACK header compression attacks (advanced)
- Concurrent stream abuse

---

## grpc-web

Browsers use grpc-web proxy — often separate auth:
```
POST /mypackage.MyService/GetUser HTTP/1.1
Content-Type: application/grpc-web+proto
```

Test grpc-web endpoint separately — may have weaker auth than native gRPC.

---

## Tools

| Tool | Use |
|---|---|
| grpcurl | CLI testing, reflection |
| grpcui | Web UI for gRPC |
| BloomRPC / Kreya | GUI client |
| Burp gRPC | Intercept/decode in Burp Suite |
| protoc | Compile/decompile proto |
| protobuf-inspector | Decode unknown protobuf |
| ffuf | gRPC method fuzzing |

### grpcurl Examples
```bash
# List services
grpcurl target.com:443 list

# Call method
grpcurl -H "authorization: Bearer TOKEN" \
  -d '{"id": "123"}' \
  target.com:443 \
  package.Service/Method

# With proto file (no reflection)
grpcurl -proto service.proto -import-path ./protos ...
```

---

## Burp Suite gRPC

1. Enable HTTP/2 in Burp
2. Install gRPC plugin
3. Import .proto or use server reflection
4. Intercept binary frames → editable decoded view
5. Repeat/intruder on decoded fields

---

## Severity Guide

| Finding | Severity |
|---|---|
| Reflection + unauth admin RPC | Critical |
| IDOR on sensitive RPC | High |
| SSRF via URL field in RPC | High-Critical |
| Missing auth on state-changing RPC | High |
| Reflection only (no data access) | Low-Medium |

---

## Bug Bounty Report Template

```markdown
## Summary
gRPC server at api.target.com:443 exposes server reflection revealing
admin RPC AdminService/DeleteUser callable without authentication.

## Steps
1. grpcurl api.target.com:443 list → AdminService found
2. grpcurl -d '{"user_id":"victim-id"}' api.target.com:443 AdminService/DeleteUser
3. User deleted without auth token

## Impact
Full account deletion of any user without authentication.

## Remediation
Disable gRPC reflection in production.
Implement per-RPC authorization middleware.
```

---

## Related Files

- `api-testing.md` — general API testing
- `graphql-advanced.md` — similar API paradigm attacks
- `portswigger-advanced.md` — HTTP/2 smuggling
- `owasp-api-top10-2023.md` — BOLA, broken auth
