# Payload Library — Curated Core + Upstream Sync



> **Tier key:** `SOTA` = matches/exceeds top external refs | `Synced` = PAT/SecLists/Escape mirror | `Curated` = hand-built entry points | `Doc` = methodology reference (not Intruder list)

>

> Sources: PayloadsAllTheThings, PortSwigger (2024–2026), SecLists, Escape GraphQL wordlist, BlackFan PP gadgets

>

> **Authorized testing only.** Lines starting with `#` are comments.



## Sync from upstream



```powershell

python tools/sync_payloads.py              # PAT Intruder + XXE + deserialization docs

python tools/sync_payloads.py --external   # + Escape GraphQL 10k wordlists

python tools/rag_chunk.py --build          # Re-index for RAG after updates

```



**Windows note:** Defender may quarantine `cmdi/generic.txt` or `rag/chunks.jsonl` (false positive on attack strings). Add a sandbox folder exclusion if sync/RAG skips those files.



## Directory map



| Path | Tier | Contents |

|---|---|---|

| **sqli/** | | |

| `union-select.txt` | Synced | UNION payloads (PAT) ~37k |

| `error-based.txt` | Synced | Error-based SQLi (PAT) ~2.9k |

| `time-based.txt` | Synced | Time-based blind (PAT) ~2.5k |

| `auth-bypass.txt` | Synced | Login bypass (PAT) ~1.2k |

| `auth-bypass2.txt` | Synced | Extended auth bypass (PAT) ~1.8k |

| `polyglots.txt` | Synced | SQLi polyglots (PAT) |

| `oracle-fuzzdb.txt` | Synced | Oracle FuzzDB (PAT) ~7k |

| `mysql-blind-where.txt` | Synced | MySQL WHERE blind (PAT) |

| `mssql-blind-where.txt` | Synced | MSSQL WHERE blind (PAT) |

| `postgres-enum.txt` | Synced | Postgres enum (PAT) |

| `generic-fuzz.txt` | Synced | Generic fuzz seeds (PAT) |

| `mysql.txt` | Curated | MySQL entry payloads + PortSwigger patterns |

| `postgres.txt` | Curated | PostgreSQL entry payloads |

| `mssql.txt` | Curated | MSSQL entry payloads |

| `blind-time.txt` | Curated | Cross-DB time blind |

| **xss/** | | |

| `event-handlers-no-interaction.txt` | SOTA | 152 PortSwigger 2026 events |

| `polyglots.txt` | SOTA | Multi-context polyglots (PAT + PortSwigger) |

| `waf-bypass.txt` | SOTA | Cloudflare, Akamai, Incapsula, Fortiweb |

| `attribute-context.txt` | Curated | HTML attribute breakout |

| `js-context.txt` | Curated | JS string breakout |

| **ssrf/** | | |

| `url-validation-bypass.txt` | SOTA | PortSwigger 2024 URL validation bypass |

| `cloud-metadata.txt` | SOTA | AWS/GCP/Azure/DO/Oracle/Alibaba/K8s/Docker |

| `internal-hosts.txt` | SOTA | Internal services, ports, k8s DNS |

| `bypasses.txt` | Curated | Legacy loopback/whitelist bypass |

| **ssti/** | | |

| `detection.txt` | SOTA | Universal polyglot + boolean pairs |

| `ssti-fuzz.txt` | Synced | Engine fuzz (PAT) 100+ payloads |

| `jinja2-rce.txt` | Curated | Python/Jinja2 gadgets |

| `freemarker-rce.txt` | Curated | Java Freemarker |

| `twig-rce.txt` | Curated | PHP Twig/Symfony |

| `velocity-rce.txt` | Curated | Java Velocity |

| **ssti/engines/** | | |

| `ruby-erb.txt` | Curated | Ruby ERB detection + file read + RCE |

| `pebble.txt` | Curated | Pebble/Java detection + reflection RCE |

| `smarty.txt` | Curated | Smarty version leak + legacy/modern RCE |

| See `ssti/engines/README.md` | Doc | Engine map + workflow |

| **lfi/** | | |

| `directory-traversal.txt` | Synced | Standard traversal (PAT) ~8k |

| `deep-traversal.txt` | Synced | Deep traversal (PAT) ~68k |

| `exotic-encoding.txt` | Synced | Encoded traversal (PAT) ~69k |

| **nosql/** | | |

| `mongodb.txt` | Synced | Mongo operator injection (PAT) |

| `nosql-generic.txt` | Synced | Generic NoSQL (PAT) |

| **ldap/** | | |

| `ldap-fuzz.txt` | Synced | LDAP injection (PAT) |

| `ldap-small.txt` | Synced | Quick LDAP (PAT) |

| **open-redirect/** | | |

| `payloads.txt` | Synced | Open redirect payloads (PAT) ~8k |

| `wordlist.txt` | Synced | Redirect wordlist (PAT) |

| **cmdi/** | | |

| `generic.txt` | Synced | Extended command injection (PAT) ~20k — may be quarantined by Windows Defender |

| `unix.txt` | Synced | Unix command injection (PAT) |

| `windows-powershell.txt` | Curated | Windows/PowerShell bypass (PAT README + PortSwigger) |

| `bypass-polyglot.txt` | Curated | Filter bypass + polyglot — Windows-safe alternative to generic.txt |

| **xxe/** | | |

| `xxe-fuzz.txt` | Synced | XXE fuzz list (PAT Intruders) |

| `xml-attacks.txt` | Synced | XML attack payloads (PAT Intruders) |

| `file-read.txt` | Curated | Classic/blind/XInclude/SVG entry payloads |

| **file-upload/** | | |

| `extensions-bypass.txt` | SOTA | Extension/double-ext/null-byte (PAT + PortSwigger) |

| `filename-tricks.txt` | SOTA | Path/null/UTF-8/ADS filename tricks |

| `mime-bypass.txt` | SOTA | Content-Type bypass list |

| `polyglot-shells.txt` | SOTA | Magic-byte + PHP/ASP polyglot bodies |

| **auth/** | | |

| `jwt.txt` | Curated | alg:none, kid/jku/x5u, claim tampering |

| **graphql/** | | |

| `wordlist-query-fields-10k.txt` | Synced | Escape Technologies query fields |

| `wordlist-mutations-10k.txt` | Synced | Escape mutation fields |

| `wordlist-types-10k.txt` | Synced | Escape type names |

| `wordlist-arguments-10k.txt` | Synced | Escape argument names |

| `wordlist-fields.txt` | Synced | SecLists graphql fields |

| `introspection-queries.txt` | SOTA | Introspection + suggestion triggers |

| `batching-idor.txt` | SOTA | JSON batching, alias IDOR, 2FA bypass |

| `dos-depth-fragments.txt` | SOTA | Deep nesting, circular fragments |

| `injection-sqli-nosql.txt` | SOTA | SQL/NoSQL via GraphQL args |

| `mutations-idor.txt` | SOTA | Privilege escalation mutations |

| `endpoints-discovery.txt` | SOTA | GraphQL path discovery |

| `field-suggestion-seeds.txt` | Curated | High-value field brute seeds |

| **prototype-pollution/** | | |

| `url-query-hash.txt` | SOTA | CSPP query/hash (BlackFan gadgets) |

| `client-side-gadgets.txt` | SOTA | jQuery/Vue/DOMPurify/sanitize-html |

| `detection-canary.txt` | SOTA | PortSwigger black-box SSPP oracles |

| `constructor-alternatives.txt` | SOTA | __proto__ filter bypass paths |

| `json-body-payloads.txt` | Curated | JSON __proto__/constructor sinks |

| `server-side-nodejs.txt` | Curated | Express/Node detection + gadgets |

| `rce-gadgets.txt` | Curated | EJS/Kibana/NODE_OPTIONS chains |

| **csrf/** | | |

| `poc-templates.txt` | Curated | GET/POST/XHR/Referer bypass PoCs (PAT + PortSwigger) |

| **deserialization/** | | |

| `gadgets-curated.txt` | Curated | Java/PHP/Python/.NET/Node gadget seeds |

| `java.txt` | Doc | PAT Java deserialization reference |

| `php.txt` | Doc | PAT PHP object injection reference |

| `python.txt` | Doc | PAT Python pickle/YAML reference |

| `node.txt` | Doc | PAT Node.js reference |

| `dotnet.txt` | Doc | PAT .NET reference |

| `ruby.txt` | Doc | PAT Ruby reference |

| **crlf/** | | |

| `payloads.txt` | Curated | Header injection / response splitting |

| `injection.txt` | Doc | PAT CRLF methodology (README) |

| **xxe/** | (see above) | |

| **smuggling/** | | |

| `cl-te-te-cl.txt` | Curated | CL.TE / TE.CL / TE obfuscation seeds (PortSwigger) |

| **cache-poison/** | | |

| `unkeyed-headers.txt` | Curated | Unkeyed header cache poisoning seeds |

| **oauth/** | | |

| `redirect-uri-bypass.txt` | Curated | redirect_uri / PKCE / scope fuzz seeds |

| **saml/** | | |

| `xsw-seeds.txt` | Curated | XSW / NameID injection / ACS path seeds |

| **websocket/** | | |

| `handshake-paths.txt` | Curated | WS endpoint discovery paths |

| `cswsh-origins.txt` | Curated | Origin header CSWSH bypass seeds |

| `message-injection.txt` | Curated | JSON frame XSS/SQLi/IDOR seeds |

| **grpc/** | | |

| `reflection-paths.txt` | Curated | gRPC/grpc-web path + port seeds |

| `method-fuzz.txt` | Curated | Common service/method name fuzz |

| `metadata-keys.txt` | Curated | Auth metadata header fuzz |

| **mobile/** | | |

| `deeplink-paths.txt` | Curated | Deeplink / universal link fuzz |

| `api-headers.txt` | Curated | Mobile-only API trust headers |

| `intent-schemes.txt` | Curated | Android intent / exported component seeds |

| **api/** | | |

| `mass-assignment-fields.txt` | SOTA | Role/plan/verification field seeds + nested JSON |



## Usage



```bash

# Burp Intruder: load file as payload list

# ffuf: ffuf -u 'https://target/FUZZ' -w payloads/lfi/directory-traversal.txt

python tools/rag_chunk.py --query "Cloudflare XSS bypass"

```



## Sources



- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — MIT

- [Escape-Technologies/graphql-wordlist](https://github.com/Escape-Technologies/graphql-wordlist)

- [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution)

- [SecLists](https://github.com/danielmiessler/SecLists)

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)



## Related skills



- `skills/graphql-advanced.md` — GraphQL batching, aliases, federation

- `skills/portswigger-advanced.md` — prototype pollution theory

- `skills/portswigger-injection.md` — methodology

- `skills/bug-chains.md` — CHAIN-014 GraphQL, CHAIN-020 PP

- `skills/skills-index.md` — vuln class → skill mapping



## Known gaps (next tier)

- BruteLogic-scale XSS corpus (beyond curated polyglots)
- HTTP/2 smuggling binary templates (research-only; use Burp Request Smuggler)
- gRPC protobuf binary fuzz (requires proto or black-box field numbers)


