# SSTI Engine Payloads — Curated per Engine

> Tier: **Curated** | Sources: `skills/portswigger-injection2.md` (SSTI section), PAT `ssti-fuzz.txt`, `detection.txt`  
> Authorized testing only.

## Engine map

| File | Engine | Stack | Detection oracle |
|---|---|---|---|
| `ruby-erb.txt` | ERB | Ruby/Rails | `<%= 7*7 %>` → `49` |
| `pebble.txt` | Pebble | Java | `${{7*7}}` / `${7*7}` |
| `smarty.txt` | Smarty | PHP | `{$smarty.version}` or `{php}` (legacy) |

Existing engine files in parent `ssti/`:

- `jinja2-rce.txt`, `freemarker-rce.txt`, `twig-rce.txt`, `velocity-rce.txt`
- `detection.txt` — universal polyglot + fingerprint errors
- `ssti-fuzz.txt` — synced PAT bulk list

## Workflow

1. Fuzz with `../detection.txt` polyglot
2. Identify engine via decision tree in `skills/portswigger-injection2.md`
3. Load the matching `engines/*.txt` file
4. Confirm RCE/file-read in lab before live target

```bash
python tools/os_query.py "SSTI ERB detection" --top 3
```
