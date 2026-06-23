# Private Operator Policy

> **ADR-011:** This OS remains **private by default**. Do not publish without a redaction review.

## Never leave this machine (or encrypt backups)

| Path | Why |
|---|---|
| `SCOPE.md` | Live program scope, assets, campaign notes |
| `SESSION.md` | Active hunt state |
| `reports/` | Finding drafts and submissions |
| `sessions/` | Raw HTTP evidence, PoCs |
| `hunt-memory/*.jsonl` | Learned techniques, outcomes, your edge |
| `.env` | API keys |
| `recon/` | Target-specific recon output |

## Safe to share internally (if ever needed)

- `tools/` (framework scripts)
- Generic `skills/` methodology (no engagement notes)
- `payloads/` synced from public upstream (with attribution)
- `PROJECT-NOTES.md`, ADRs, architecture docs

## Before any git push

```bash
python tools/health_check.py --quick
python tools/audit_references.py
git status   # verify SCOPE.md, reports/, hunt-memory/ are NOT staged
```

Copy `SCOPE.md.example` → `SCOPE.md` for new engagements. Never commit the real `SCOPE.md`.

## Open source stance

**Current decision:** Keep the full OS private. The framework is dual-use; operator memory and engagement data are the competitive moat.

Revisit only with explicit redaction review (see `PROJECT-NOTES.md` §20).
