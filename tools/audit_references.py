#!/usr/bin/env python3
"""
audit_references.py — Scan repo docs for references to paths that do not exist.

Usage:
  python tools/audit_references.py
  python tools/audit_references.py --json
  python tools/audit_references.py --fix-hints
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent

SCAN_DIRS = ["skills", "agents", "rules", "tools", ".cursor/rules"]
SCAN_FILES = ["CLAUDE.md", "README.md", "PROJECT-NOTES.md", "payloads/README.md"]
GHOST_SCAN_SKIP = {
    "PROJECT-NOTES.md",
    "tools/health_check.py",
    "tools/audit_references.py",
}

# Known legacy ghost paths — any hit is a defect
GHOST_PATHS = [
    "skills/bug-bounty/",
    "skills/bb-methodology/",
    "skills/web2-recon/",
    "skills/web2-vuln-classes/",
    "skills/security-arsenal/",
    "skills/triage-validation/",
    "skills/report-writing/",
    "commands/report.md",
]

# Standard external tools — not checked on disk
EXTERNAL_TOOLS = {
    "ffuf", "nuclei", "subfinder", "httpx", "katana", "amass", "gau", "dalfox",
    "sqlmap", "jwt_tool", "burp", "curl", "jq", "arjun", "trufflehog", "gitleaks",
    "semgrep", "codeql",
}

# Repo path patterns to verify
PATH_PATTERNS = [
    re.compile(r"`((?:skills|payloads|tools|scripts|wordlists|agents|hooks|memory|hunt-memory|nuclei|templates|rag)/[^\s`]+)`"),
    re.compile(r"((?:skills|payloads|tools|scripts|wordlists|agents|hooks|memory|hunt-memory|nuclei|templates|rag)/[\w./\-]+)"),
]


def _iter_text_files() -> list[Path]:
    files: list[Path] = []
    for name in SCAN_FILES:
        p = _REPO / name
        if p.is_file():
            files.append(p)
    for d in SCAN_DIRS:
        root = _REPO / d
        if root.is_dir():
            files.extend(root.rglob("*.md"))
            files.extend(root.rglob("*.mdc"))
            if d == "tools":
                files.extend(root.rglob("*.py"))
    return sorted(set(files))


def _normalize_path(raw: str) -> str:
    path = raw.strip().rstrip(".,;:)'\"")
    if path.endswith("/"):
        return path
    # Keep directory refs and file refs
    return path.split("#")[0].split("?")[0]


def _path_exists(rel: str) -> bool:
    p = _REPO / rel.replace("/", os.sep)
    return p.exists()


def audit() -> dict:
    ghost_hits: list[dict] = []
    missing_hits: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for file_path in _iter_text_files():
        rel_file = file_path.relative_to(_REPO).as_posix()
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            missing_hits.append({"file": rel_file, "path": rel_file, "reason": f"unreadable: {exc}"})
            continue

        for ghost in GHOST_PATHS:
            if rel_file in GHOST_SCAN_SKIP:
                continue
            if ghost in text:
                ghost_hits.append({"file": rel_file, "ghost": ghost})

        for pattern in PATH_PATTERNS:
            for match in pattern.finditer(text):
                raw = _normalize_path(match.group(1))
                if not raw or raw in EXTERNAL_TOOLS:
                    continue
                if any(raw.startswith(f"{t}/") for t in EXTERNAL_TOOLS):
                    continue
                key = (rel_file, raw)
                if key in seen:
                    continue
                seen.add(key)

                if "{" in raw or "*" in raw or "..." in raw:
                    continue
                if "<" in raw or ">" in raw or "/foo" in raw or raw.endswith("foo.py"):
                    continue
                if rel_file in GHOST_SCAN_SKIP:
                    continue
                # Skip external / placeholder paths
                if raw.startswith(("http://", "https://", "~/", "/usr/", "/etc/")):
                    continue
                if raw.startswith("recon/") or raw.startswith("hunt-memory/targets"):
                    continue
                if raw == "hunt-memory/audit.jsonl":
                    continue  # runtime append-only log (memory/audit_log.py)
                if "{baseDir}" in raw or "baseDir" in raw:
                    continue
                if "SecLists/" in raw or raw.startswith("Discovery/"):
                    continue
                if raw.endswith("/") and raw.count("/") <= 2:
                    # Top-level dir refs like payloads/ — directory must exist
                    if _path_exists(raw.rstrip("/")):
                        continue
                if raw.endswith(".md") and "SKILL.md" not in raw and "/" not in raw.replace("skills/", ""):
                    pass

                if _path_exists(raw):
                    continue
                if _path_exists(raw.rstrip("/")):
                    continue

                missing_hits.append({
                    "file": rel_file,
                    "path": raw,
                    "reason": "not found on disk",
                })

    return {
        "repo": str(_REPO),
        "files_scanned": len(_iter_text_files()),
        "ghost_hits": ghost_hits,
        "missing_hits": missing_hits,
        "passed": not ghost_hits and not missing_hits,
    }


def _print_report(report: dict) -> None:
    green = "\033[92m"
    red = "\033[91m"
    yellow = "\033[93m"
    reset = "\033[0m"

    print(f"\nReference audit — {report['repo']}")
    print(f"Files scanned: {report['files_scanned']}\n")

    if report["ghost_hits"]:
        print(f"{red}Ghost paths ({len(report['ghost_hits'])}):{reset}")
        for hit in report["ghost_hits"]:
            print(f"  {hit['file']} -> {hit['ghost']}")
        print()

    if report["missing_hits"]:
        print(f"{red}Missing paths ({len(report['missing_hits'])}):{reset}")
        for hit in report["missing_hits"][:40]:
            print(f"  {hit['file']} -> {hit['path']} ({hit['reason']})")
        if len(report["missing_hits"]) > 40:
            print(f"  ... and {len(report['missing_hits']) - 40} more")
        print()

    if report["passed"]:
        print(f"{green}PASS{reset} — no ghost or missing repo path references found.\n")
    else:
        print(f"{red}FAIL{reset} — fix references or create missing assets.\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit docs for ghost/missing path references")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    report = audit()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report)

    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
