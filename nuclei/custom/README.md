# nuclei/custom — Bug Bounty Kit Templates

Curated Nuclei templates for patterns that recur across programs.  
**Not** a replacement for [ProjectDiscovery nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) — use both.

## Run

```bash
# Against a single URL
nuclei -t nuclei/custom/ -u https://target.com

# Against recon output
nuclei -t nuclei/custom/ -l recon/example.com/live/urls.txt

# With hunt pipeline
python tools/hunt.py --target example.com
# nuclei is invoked by vuln_scanner.sh / hunt.py when recon completes
```

## Templates

| File | Severity | Notes |
|---|---|---|
| `graphql-introspection.yaml` | info | Chain required for report |
| `open-redirect-param.yaml` | low | Chain with OAuth/token theft |
| `exposed-git-config.yaml` | medium | Verify not intentional public repo |
| `grpc-server-reflection.yaml` | info | Follow with grpcurl + auth/IDOR on methods |
| `websocket-upgrade-detect.yaml` | info | CSWSH + message injection in Burp |
| `swagger-openapi-exposure.yaml` | low | Map API → BOLA/mass assignment |

## After finding a pattern

1. Copy nearest template → rename `id`
2. Customize matchers for target-specific behavior
3. Store in this directory
4. Reference in report as reusable detection

See `skills/nuclei-templates.md` for authoring guide.
