#!/usr/bin/env python3
"""
dup_check.py — Pre-submit duplicate check assistant.

Runs automated checks from CLAUDE.md DUPLICATE CHECK PROTOCOL:
  1. Local reports/ overlap
  2. HackerOne disclosed hacktivity (GraphQL)
  3. Search URL pack for GitLab / web / writeups (manual follow-up)
  4. OSS competition flag

Usage:
  python tools/dup_check.py --program shopify --artifact "validate_no_privilege_escalation!"
  python tools/dup_check.py --program shopify --artifact "GraphQL batching" --endpoint "/graphql" --title "IDOR via batching"
  python tools/dup_check.py --program gitlab --artifact "merge_train" --oss --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tools.validate import check_h1_dups  # noqa: E402

REPORTS_DIR = _REPO / "reports"


def _tokenize(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9_./\-]+", text.lower()) if len(t) >= 4}


def check_local_reports(artifact: str, endpoint: str = "", title: str = "") -> list[dict]:
    """Scan reports/ for overlapping artifacts, endpoints, or titles."""
    if not REPORTS_DIR.is_dir():
        return []

    needles = [artifact, endpoint, title]
    artifact_tokens = _tokenize(artifact)
    hits: list[dict] = []

    for path in sorted(REPORTS_DIR.rglob("*.md")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = path.relative_to(_REPO).as_posix()
        lower = text.lower()

        for needle in needles:
            if needle and len(needle) >= 4 and needle.lower() in lower:
                hits.append({
                    "file": rel,
                    "match_type": "exact_substring",
                    "needle": needle,
                })
                break
        else:
            if artifact_tokens:
                file_tokens = _tokenize(text)
                overlap = artifact_tokens & file_tokens
                if len(overlap) >= 2:
                    hits.append({
                        "file": rel,
                        "match_type": "token_overlap",
                        "tokens": sorted(overlap),
                    })

    return hits


def build_search_urls(program: str, artifact: str) -> dict[str, str]:
    """Generate manual search URLs — no fabricated results."""
    enc = urllib.parse.quote(artifact)
    prog = urllib.parse.quote(program)
    return {
        "gitlab_issues": (
            f"https://gitlab.com/gitlab-org/gitlab/-/issues?search={enc}&scope=all&state=all"
            if program.lower() == "gitlab"
            else f"https://gitlab.com/search?search={enc}&scope=issues"
        ),
        "hackerone_hacktivity": f"https://hackerone.com/{program}/hacktivity?query={enc}",
        "hackerone_reports_site": f"https://www.google.com/search?q=site:hackerone.com/reports+{prog}+{enc}",
        "disclosed_writeups": (
            f"https://www.google.com/search?q={prog}+bug+bounty+{enc}+disclosed"
        ),
        "github_code": f"https://github.com/search?q={enc}+type=code",
        "top_program_md": (
            f"https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_program/"
            f"TOP{program.upper()}.md"
        ),
    }


def assess_verdict(
    local_hits: list[dict],
    h1_hits: list[dict],
    oss: bool,
    artifact: str,
) -> tuple[str, list[str]]:
    reasons: list[str] = []

    if local_hits:
        exact = [h for h in local_hits if h.get("match_type") == "exact_substring"]
        if exact:
            reasons.append(f"Local reports/ contains exact match for artifact ({len(exact)} file(s))")
            return "KILL", reasons
        reasons.append(f"Partial overlap in reports/ ({len(local_hits)} file(s)) — review before submitting")

    if len(h1_hits) >= 3:
        reasons.append(f"HackerOne hacktivity: {len(h1_hits)} similar disclosed reports")
        return "KILL", reasons
    if h1_hits:
        reasons.append(f"HackerOne hacktivity: {len(h1_hits)} possibly similar disclosed report(s)")

    if oss:
        reasons.append("OSS target — assume high competition if findable via source code alone")

    if not reasons:
        return "GO", ["No automated duplicate signals — still run manual GitLab/search URLs"]

    if any("KILL" in r for r in reasons):
        return "KILL", reasons

    if reasons:
        return "CAUTION", reasons
    return "GO", reasons


def run_dup_check(
    program: str,
    artifact: str,
    endpoint: str = "",
    title: str = "",
    oss: bool = False,
) -> dict:
    local_hits = check_local_reports(artifact, endpoint=endpoint, title=title)
    h1_keyword = artifact or title or endpoint or program
    h1_hits = check_h1_dups(program, h1_keyword) if program else []
    search_urls = build_search_urls(program, artifact) if program and artifact else {}
    verdict, reasons = assess_verdict(local_hits, h1_hits, oss, artifact)

    return {
        "verdict": verdict,
        "program": program,
        "artifact": artifact,
        "endpoint": endpoint,
        "title": title,
        "oss": oss,
        "local_reports": local_hits,
        "hackerone_disclosed": [
            {
                "title": r.get("title"),
                "severity": r.get("severity_rating"),
                "disclosed_at": (r.get("disclosed_at") or "")[:10],
                "url": r.get("url"),
            }
            for r in h1_hits
        ],
        "search_urls": search_urls,
        "reasons": reasons,
        "next_steps": _next_steps(verdict),
    }


def _next_steps(verdict: str) -> list[str]:
    if verdict == "GO":
        return [
            "Open search_urls and confirm no same code-path disclosure",
            "Proceed to gate_check.py then full report",
        ]
    if verdict == "CAUTION":
        return [
            "Read each H1/local hit — confirm your angle is meaningfully different",
            "If uncertain, submit low-severity stub same day or pivot endpoint",
        ]
    return [
        "Do not write full report — pivot technique or endpoint",
        "Log finding as KILLED in SESSION.md with dup reason",
    ]


def _print_human(result: dict) -> None:
    green = "\033[92m"
    yellow = "\033[93m"
    red = "\033[91m"
    reset = "\033[0m"
    dim = "\033[2m"

    v = result["verdict"]
    color = green if v == "GO" else yellow if v == "CAUTION" else red

    print(f"\n{color}DUP CHECK: {v}{reset}")
    print(f"Program: {result['program']} | Artifact: {result['artifact']}")
    if result.get("endpoint"):
        print(f"Endpoint: {result['endpoint']}")

    print("\nReasons:")
    for r in result["reasons"]:
        print(f"  - {r}")

    if result["local_reports"]:
        print(f"\n{yellow}Local reports ({len(result['local_reports'])}):{reset}")
        for h in result["local_reports"][:10]:
            print(f"  • {h['file']} ({h['match_type']})")

    if result["hackerone_disclosed"]:
        print(f"\n{yellow}HackerOne disclosed ({len(result['hackerone_disclosed'])}):{reset}")
        for h in result["hackerone_disclosed"][:8]:
            print(f"  • [{h.get('severity','?')}] {h.get('title','')}")
            if h.get("url"):
                print(f"    {dim}{h['url']}{reset}")

    if result["search_urls"]:
        print("\nManual search URLs:")
        for name, url in result["search_urls"].items():
            print(f"  {name}: {url}")

    print("\nNext steps:")
    for step in result["next_steps"]:
        print(f"  → {step}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Pre-submit duplicate check")
    parser.add_argument("--program", required=True, help="HackerOne program handle (e.g. shopify)")
    parser.add_argument("--artifact", required=True, help="Exact method/flag/endpoint artifact to search")
    parser.add_argument("--endpoint", default="", help="Optional endpoint path")
    parser.add_argument("--title", default="", help="Optional finding title")
    parser.add_argument("--oss", action="store_true", help="OSS target — high competition warning")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    result = run_dup_check(
        program=args.program,
        artifact=args.artifact,
        endpoint=args.endpoint,
        title=args.title,
        oss=args.oss,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_human(result)

    return 0 if result["verdict"] == "GO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
