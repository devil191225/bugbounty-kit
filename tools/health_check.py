#!/usr/bin/env python3
"""
health_check.py — Verify bug bounty OS integrity before a hunt session.

Usage:
  python tools/health_check.py
  python tools/health_check.py --quick
  python tools/health_check.py --json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent

# Legacy shuvonsec paths that must not appear in agent brain files.
GHOST_SKILL_PATHS = [
    "skills/bug-bounty/",
    "skills/bb-methodology/",
    "skills/web2-recon/",
    "skills/web2-vuln-classes/",
    "skills/security-arsenal/",
    "skills/triage-validation/",
    "skills/report-writing/",
    "commands/report.md",
]

BRAIN_FILES = [
    "CLAUDE.md",
    "README.md",
    "tools/validate.py",
]

CORE_PATHS = [
    "SCOPE.md",
    "SESSION.md",
    "skills/skills-index.md",
    "payloads/README.md",
    "rules/hunting.md",
    "rules/reporting.md",
    "agents/validator.md",
    "templates/finding.md",
    "rag/index_meta.json",
]

PAYLOAD_DIRS = [
    "payloads/graphql",
    "payloads/prototype-pollution",
    "payloads/sqli",
    "payloads/xss",
    "payloads/smuggling",
    "payloads/cache-poison",
    "payloads/oauth",
    "payloads/saml",
    "payloads/websocket",
    "payloads/grpc",
    "payloads/mobile",
    "payloads/api",
]

KEY_TOOLS = [
    "tools/hunt.py",
    "tools/validate.py",
    "tools/rag_chunk.py",
    "tools/os_query.py",
    "tools/prioritize.py",
    "tools/gate_check.py",
    "tools/dup_check.py",
    "tools/scope_checker.py",
    "tools/ctf_learn.py",
    "tools/sync_payloads.py",
    "tools/sync_seclists.py",
    "tools/audit_references.py",
    "tools/gate_check.py",
    "tools/health_check.py",
]


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""
    hint: str = ""


@dataclass
class HealthReport:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.ok for c in self.checks)

    def add(self, name: str, ok: bool, detail: str = "", hint: str = "") -> None:
        self.checks.append(CheckResult(name=name, ok=ok, detail=detail, hint=hint))


def _exists(rel: str) -> bool:
    return (_REPO / rel).exists()


def check_core_paths(report: HealthReport) -> None:
    missing = [p for p in CORE_PATHS if not _exists(p)]
    report.add(
        "core_paths",
        not missing,
        f"{len(CORE_PATHS) - len(missing)}/{len(CORE_PATHS)} present",
        f"Missing: {', '.join(missing)}" if missing else "",
    )


def check_payload_dirs(report: HealthReport) -> None:
    missing = [p for p in PAYLOAD_DIRS if not _exists(p)]
    report.add(
        "payload_dirs",
        not missing,
        f"{len(PAYLOAD_DIRS) - len(missing)}/{len(PAYLOAD_DIRS)} categories",
        f"Missing: {', '.join(missing)}" if missing else "",
    )


def check_key_tools(report: HealthReport) -> None:
    missing = [p for p in KEY_TOOLS if not _exists(p)]
    report.add(
        "key_tools",
        not missing,
        f"{len(KEY_TOOLS) - len(missing)}/{len(KEY_TOOLS)} scripts",
        f"Missing: {', '.join(missing)}" if missing else "",
    )


def check_ghost_paths(report: HealthReport) -> None:
    hits: list[str] = []
    for rel in BRAIN_FILES:
        path = _REPO / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            hits.append(f"{rel} (unreadable: {exc})")
            continue
        for ghost in GHOST_SKILL_PATHS:
            if ghost in text:
                hits.append(f"{rel} -> {ghost}")

    report.add(
        "ghost_paths",
        not hits,
        "clean" if not hits else f"{len(hits)} reference(s)",
        "; ".join(hits) if hits else "",
    )


def check_rag_index(report: HealthReport, quick: bool) -> None:
    chunks = _REPO / "rag" / "chunks.jsonl"
    meta = _REPO / "rag" / "index_meta.json"

    if not meta.is_file():
        report.add(
            "rag_meta",
            False,
            "index_meta.json missing",
            "Run: python tools/rag_chunk.py --build",
        )
        return

    report.add("rag_meta", True, "index_meta.json readable")

    if not chunks.is_file():
        report.add(
            "rag_chunks",
            False,
            "chunks.jsonl missing",
            "Run: python tools/rag_chunk.py --build",
        )
        return

    try:
        size = chunks.stat().st_size
        with chunks.open(encoding="utf-8") as fh:
            first = fh.readline()
        json.loads(first)
        report.add("rag_chunks", True, f"readable ({size:,} bytes)")
    except OSError as exc:
        report.add(
            "rag_chunks",
            False,
            f"read failed: {exc}",
            "Windows Defender may quarantine chunks.jsonl — add a folder exclusion "
            f"for {_REPO} then rebuild RAG.",
        )
        return
    except json.JSONDecodeError as exc:
        report.add("rag_chunks", False, f"invalid JSONL: {exc}")
        return

    if quick:
        return

    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(
            [sys.executable, str(_REPO / "tools" / "rag_chunk.py"), "--query", "SSRF metadata", "--top", "1"],
            cwd=str(_REPO),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=env,
            encoding="utf-8",
            errors="replace",
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        ok = proc.returncode == 0 and bool(combined.strip())
        report.add(
            "rag_query",
            ok,
            "query ok" if ok else f"exit {proc.returncode}",
            combined.strip() if not ok and combined.strip() else "",
        )
    except subprocess.TimeoutExpired:
        report.add("rag_query", False, "timed out")


def check_scope_filled(report: HealthReport) -> None:
    scope = _REPO / "SCOPE.md"
    if not scope.is_file():
        report.add("scope_content", False, "SCOPE.md missing")
        return
    text = scope.read_text(encoding="utf-8", errors="replace").lower()
    placeholder_markers = ["example.com", "your-target", "todo", "fill in", "edit this"]
    looks_empty = len(text.strip()) < 80 or any(m in text for m in placeholder_markers)
    report.add(
        "scope_content",
        not looks_empty,
        "configured" if not looks_empty else "still placeholder content",
        "Edit SCOPE.md with in-scope/out-of-scope assets before hunting." if looks_empty else "",
    )


def run_checks(quick: bool) -> HealthReport:
    report = HealthReport()
    check_core_paths(report)
    check_payload_dirs(report)
    check_key_tools(report)
    check_ghost_paths(report)
    check_rag_index(report, quick=quick)
    if not quick:
        check_scope_filled(report)
    return report


def _print_report(report: HealthReport) -> None:
    green = "\033[92m"
    red = "\033[91m"
    yellow = "\033[93m"
    reset = "\033[0m"

    print(f"\nBug Bounty OS Health Check — {_REPO}\n")
    for check in report.checks:
        mark = f"{green}PASS{reset}" if check.ok else f"{red}FAIL{reset}"
        line = f"  [{mark}] {check.name}: {check.detail}"
        print(line)
        if not check.ok and check.hint:
            print(f"         {yellow}hint:{reset} {check.hint}")

    status = f"{green}READY{reset}" if report.passed else f"{red}NOT READY{reset}"
    print(f"\nOverall: {status} ({sum(c.ok for c in report.checks)}/{len(report.checks)} checks)\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify bug bounty OS integrity")
    parser.add_argument("--quick", action="store_true", help="Skip RAG query test and scope content check")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable output")
    args = parser.parse_args()

    report = run_checks(quick=args.quick)

    if args.json:
        payload = {
            "repo": str(_REPO),
            "passed": report.passed,
            "checks": [
                {"name": c.name, "ok": c.ok, "detail": c.detail, "hint": c.hint}
                for c in report.checks
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        _print_report(report)

    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
