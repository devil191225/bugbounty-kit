"""
Pattern database — successful techniques indexed by vuln class + tech stack.

Patterns are stored in a JSONL file, one entry per line.
Matching supports partial tech stack overlap for cross-target learning.
"""

try:
    import fcntl as _fcntl_mod

    class _FcntlShim:
        LOCK_EX = _fcntl_mod.LOCK_EX
        LOCK_UN = _fcntl_mod.LOCK_UN
        flock = staticmethod(_fcntl_mod.flock)

    fcntl = _FcntlShim()
except ImportError:
    # Windows — file locking not available; use no-op shim
    class fcntl:  # type: ignore[no-redef]
        LOCK_EX = 0
        LOCK_UN = 0

        @staticmethod
        def flock(fd, op):  # noqa: ARG004
            pass

import json
import os
import sys
from pathlib import Path

from memory.rotation import DEFAULT_KEEP, DEFAULT_MAX_BYTES, rotate_if_needed
from memory.schemas import validate_pattern_entry, SchemaError, CTF_ONLY_TECHNIQUES


class PatternDB:
    """Read/write/match successful hunt patterns."""

    def __init__(
        self,
        path: str | Path,
        max_bytes: int = DEFAULT_MAX_BYTES,
        keep_backups: int = DEFAULT_KEEP,
    ):
        """
        Args:
            path: Path to the patterns.jsonl file. Parent dirs are created if needed.
            max_bytes: Rotate the file when it exceeds this size.
            keep_backups: Number of rotated backups to retain.
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.keep_backups = keep_backups
        # Dedup index of (target, vuln_class, technique) keys. Populated lazily
        # on first save() so re-opening an existing DB stays correct without
        # paying the read cost up-front. Cross-process dedup is best-effort:
        # two processes with independent instances can each pass the dedup
        # check before either writes. The cost is one wasted JSONL row.
        self._dedup_keys: set[tuple[str, str, str]] | None = None

    @staticmethod
    def _dedup_key(entry: dict) -> tuple[str, str, str]:
        # Prefer the stable UUID id when present (new entries always have it).
        # Fall back to (target, vuln_class, technique) for legacy entries without an id.
        if entry.get("id"):
            return (entry["id"], "", "")
        return (entry.get("target", ""), entry.get("vuln_class", ""), entry.get("technique", ""))

    def _load_dedup_keys(self) -> set[tuple[str, str, str]]:
        """Build the dedup key set by streaming the file once.

        Skips corrupted lines silently — they cannot collide with a valid
        save, and ``read_all`` already warns about them.
        """
        keys: set[tuple[str, str, str]] = set()
        if not self.path.exists():
            return keys
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                keys.add(self._dedup_key(entry))
        return keys

    def save(self, entry: dict) -> bool:
        """Validate and save a pattern entry. Returns True if saved, False if duplicate.

        A duplicate is defined as same target + vuln_class + technique.
        """
        validated = validate_pattern_entry(entry)

        if self._dedup_keys is None:
            self._dedup_keys = self._load_dedup_keys()

        key = self._dedup_key(validated)
        if key in self._dedup_keys:
            return False

        line = json.dumps(validated, separators=(",", ":")) + "\n"
        encoded = line.encode("utf-8")

        rotate_if_needed(self.path, max_bytes=self.max_bytes, keep=self.keep_backups)

        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                written = os.write(fd, encoded)
                if written != len(encoded):
                    raise OSError(f"Partial write: {written}/{len(encoded)} bytes")
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

        self._dedup_keys.add(key)
        return True

    def read_all(self, *, validate: bool = True) -> list[dict]:
        """Read all pattern entries. Corrupted lines are skipped with a warning."""
        if not self.path.exists():
            return []

        entries = []
        with open(self.path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    print(
                        f"WARNING: patterns line {lineno} is corrupted (skipping): {e}",
                        file=sys.stderr,
                    )
                    continue

                if validate:
                    try:
                        validate_pattern_entry(entry)
                    except SchemaError as e:
                        print(
                            f"WARNING: patterns line {lineno} failed validation (skipping): {e}",
                            file=sys.stderr,
                        )
                        continue

                entries.append(entry)

        return entries

    def match(self, *, vuln_class: str | None = None,
              tech_stack: list[str] | None = None,
              environment: str | None = None,
              target_type: str | None = None) -> list[dict]:
        """Find patterns matching vuln class and/or overlapping tech stack.

        Args:
            vuln_class: Exact match on vuln_class field.
            tech_stack: Partial overlap match — returns patterns where ANY tech in
                        the query overlaps with the pattern's tech_stack.
            environment: Filter by 'ctf' or 'live'. If None, returns all.
            target_type: Exact match on target_type field.

        Returns:
            Matching patterns sorted by payout (highest first), then recency.
        """
        patterns = self.read_all()

        if vuln_class is not None:
            patterns = [p for p in patterns if p.get("vuln_class") == vuln_class]

        if tech_stack is not None:
            query_set = {t.lower() for t in tech_stack}
            patterns = [
                p for p in patterns
                if query_set & {t.lower() for t in p.get("tech_stack", [])}
            ]

        if environment is not None:
            patterns = [p for p in patterns if p.get("environment") == environment]

        if target_type is not None:
            patterns = [p for p in patterns if p.get("target_type") == target_type]

        # Sort: highest payout first, then most recent
        patterns.sort(
            key=lambda p: (p.get("payout", 0), p.get("ts", "")),
            reverse=True,
        )

        return patterns

    def get_live_strategies(self, *, vuln_class: str | None = None,
                            target_type: str | None = None) -> list[dict]:
        """Return strategies safe to run on live programs.

        Includes live-tagged patterns and CTF patterns whose technique is not
        in CTF_ONLY_TECHNIQUES (brute_force, flood, data_manipulation, etc.).

        Sorted by outcome weight: high_impact > valid > duplicate > informational > no_effect.
        """
        OUTCOME_WEIGHT = {
            "high_impact": 5,
            "valid": 4,
            "duplicate": 2,
            "informational": 1,
            "no_effect": 0,
        }

        patterns = self.read_all()

        # Filter: live env OR (ctf env AND technique not in blocked list)
        def _safe_for_live(p: dict) -> bool:
            env = p.get("environment")
            technique = p.get("technique", "")
            if env == "live":
                return True
            if env == "ctf":
                technique_tags = set(technique.lower().replace(",", " ").split())
                return not (technique_tags & CTF_ONLY_TECHNIQUES)
            # No environment tag — treat as live (backwards compat)
            return True

        patterns = [p for p in patterns if _safe_for_live(p)]

        if vuln_class is not None:
            patterns = [p for p in patterns if p.get("vuln_class") == vuln_class]

        if target_type is not None:
            patterns = [p for p in patterns if p.get("target_type") == target_type]

        patterns.sort(
            key=lambda p: (
                OUTCOME_WEIGHT.get(p.get("outcome", ""), 0),
                p.get("payout", 0),
                p.get("ts", ""),
            ),
            reverse=True,
        )

        return patterns

    def get_strategy_weights(self, target_type: str) -> dict[str, dict]:
        """Return per-vuln_class success rates for a given target type.

        Returns:
            {vuln_class: {"valid": N, "duplicate": N, "no_effect": N, "rate": float}}
        """
        patterns = self.match(target_type=target_type)
        weights: dict[str, dict] = {}

        for p in patterns:
            vc = p.get("vuln_class", "unknown")
            outcome = p.get("outcome", "no_effect")
            if vc not in weights:
                weights[vc] = {"valid": 0, "high_impact": 0, "duplicate": 0,
                               "informational": 0, "no_effect": 0, "total": 0}
            weights[vc][outcome] = weights[vc].get(outcome, 0) + 1
            weights[vc]["total"] += 1

        for vc, stats in weights.items():
            total = stats["total"]
            hits = stats.get("valid", 0) + stats.get("high_impact", 0)
            stats["rate"] = round(hits / total, 2) if total else 0.0

        return weights

    def get_ctf_patterns(self, *, vuln_class: str | None = None) -> list[dict]:
        """Return all CTF-sourced patterns, optionally filtered by vuln class."""
        return self.match(environment="ctf", vuln_class=vuln_class)
