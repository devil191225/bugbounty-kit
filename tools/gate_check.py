#!/usr/bin/env python3
"""
gate_check.py — Non-interactive 7-Question + never-submit gate for autonomous mode.

The agent MUST run this before writing to reports/. Output PASS or KILL with reasons.

Usage:
  python tools/gate_check.py \\
    --title "IDOR on /api/users/{id}" \\
    --vuln-class idor \\
    --endpoint "/api/users/123" \\
    --poc-file "sessions/2026-06-10/target/poc.txt" \\
    --impact "Attacker reads victim PII with attacker token" \\
    --repro "curl -H 'Authorization: Bearer A' https://target/api/users/B"

  python tools/gate_check.py --json-file finding.json
  python tools/gate_check.py --stdin-json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent

# Standalone N/A bug classes (from agents/validator.md + rules/reporting.md)
NEVER_SUBMIT_PATTERNS = [
    (r"missing\s+(csp|hsts|x-frame|security)\s+header", "missing security headers alone"),
    (r"missing\s+(spf|dkim|dmarc)", "missing email DNS records alone"),
    (r"graphql\s+introspection|introspection\s+enabled|introspection\s+open", "graphql introspection alone"),
    (r"banner\s+disclosure|version\s+disclosure", "banner/version without exploit"),
    (r"self[- ]xss", "self-xss"),
    (r"open\s+redirect\s+alone|redirect\s+alone", "open redirect alone"),
    (r"ssrf\s+dns[- ]only|dns\s+callback\s+only", "ssrf dns-only"),
    (r"logout\s+csrf", "logout csrf"),
    (r"missing\s+cookie\s+flag", "missing cookie flags alone"),
    (r"rate\s+limit", "rate limit on non-critical form"),
    (r"clickjacking\s+alone", "clickjacking without sensitive action"),
    (r"cors\s+wildcard\s+alone", "cors wildcard without credentialed exfil"),
]

THEORETICAL_PHRASES = [
    "could potentially",
    "may allow",
    "might be possible",
    "could lead to",
    "theoretically",
    "if chained with",
]


def _load_finding(args: argparse.Namespace) -> dict:
    if args.stdin_json:
        return json.load(sys.stdin)
    if args.json_file:
        return json.loads(Path(args.json_file).read_text(encoding="utf-8"))
    return {
        "title": args.title,
        "vuln_class": args.vuln_class,
        "endpoint": args.endpoint,
        "poc_file": args.poc_file,
        "impact": args.impact,
        "repro": args.repro,
        "in_scope": args.in_scope,
        "program_accepts_impact": args.program_accepts_impact,
        "known_behavior": args.known_behavior,
        "privileged_required": args.privileged_required,
        "identity_verified": args.identity_verified,
    }


def _check_never_submit(text: str) -> str | None:
    lower = text.lower()
    for pattern, label in NEVER_SUBMIT_PATTERNS:
        if re.search(pattern, lower):
            return label
    return None


def run_gate(finding: dict) -> dict:
    failures: list[dict] = []
    warnings: list[str] = []

    title = (finding.get("title") or "").strip()
    vuln_class = (finding.get("vuln_class") or "").strip()
    endpoint = (finding.get("endpoint") or "").strip()
    poc_file = (finding.get("poc_file") or "").strip()
    impact = (finding.get("impact") or "").strip()
    repro = (finding.get("repro") or finding.get("reproduction") or "").strip()

    combined = f"{title} {vuln_class} {impact}".lower()

    # Q1 — reproducible now
    if not repro or len(repro) < 20:
        failures.append({"q": "Q1", "reason": "No exact reproduction steps (curl/request) provided"})
    if any(p in impact.lower() for p in THEORETICAL_PHRASES):
        failures.append({"q": "Q1", "reason": "Impact uses theoretical language — rewrite as concrete attacker action"})

    # Q2 — program accepts impact
    if finding.get("program_accepts_impact") is False:
        failures.append({"q": "Q2", "reason": "Impact type not on program accepted list"})

    # Q3 — in scope
    if finding.get("in_scope") is False:
        failures.append({"q": "Q3", "reason": "Asset marked out of scope"})

    # Q4 — no unrealistic privilege
    if finding.get("privileged_required") is True:
        failures.append({"q": "Q4", "reason": "Requires privileged access attacker cannot get"})

    # Q5 — not known behavior
    if finding.get("known_behavior") is True:
        failures.append({"q": "Q5", "reason": "Documented or accepted behavior"})

    # Q6 — prove impact
    if not impact or len(impact) < 30:
        failures.append({"q": "Q6", "reason": "Impact not proven beyond 'technically possible'"})
    if impact.lower().startswith("could ") or "technically possible" in impact.lower():
        failures.append({"q": "Q6", "reason": "Impact statement is not concrete proof"})

    # Q7 — never submit
    ns = _check_never_submit(combined)
    if ns:
        failures.append({"q": "Q7", "reason": f"On never-submit list: {ns} — chain required or kill"})

    # Q8 — identity (IDOR/auth)
    if vuln_class.lower() in {"idor", "auth_idor", "bola", "auth_bypass", "broken_access_control"}:
        if finding.get("identity_verified") is False:
            failures.append({"q": "Q8", "reason": "Two-account identity check not verified for access-control bug"})

    # Q9 — evidence file
    if not poc_file:
        failures.append({"q": "Q9", "reason": "POC_FILE path missing"})
    elif poc_file.upper() in {"N/A", "CANNOT_REPRODUCE"}:
        failures.append({"q": "Q9", "reason": "Cannot reproduce — do not draft report"})
    else:
        poc_path = Path(poc_file)
        if not poc_path.is_absolute():
            poc_path = _REPO / poc_file
        if not poc_path.is_file():
            failures.append({"q": "Q9", "reason": f"POC_FILE does not exist: {poc_file}"})

    if not title:
        failures.append({"q": "meta", "reason": "Title missing"})
    if not endpoint:
        warnings.append("Endpoint not specified — add for duplicate check")

    verdict = "PASS" if not failures else "KILL"
    return {
        "verdict": verdict,
        "failures": failures,
        "warnings": warnings,
        "finding_summary": {
            "title": title,
            "vuln_class": vuln_class,
            "endpoint": endpoint,
            "poc_file": poc_file,
        },
        "gate_status_line": f"GATE_STATUS: {verdict}",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Non-interactive validation gate")
    parser.add_argument("--title", default="")
    parser.add_argument("--vuln-class", default="")
    parser.add_argument("--endpoint", default="")
    parser.add_argument("--poc-file", default="")
    parser.add_argument("--impact", default="")
    parser.add_argument("--repro", default="", help="Exact curl or HTTP reproduction")
    parser.add_argument("--json-file", default="")
    parser.add_argument("--stdin-json", action="store_true")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--in-scope", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--program-accepts-impact", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--known-behavior", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--privileged-required", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--identity-verified", action=argparse.BooleanOptionalAction, default=None)
    args = parser.parse_args()

    finding = _load_finding(args)
    result = run_gate(finding)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(result["gate_status_line"])
        if result["failures"]:
            print("\nFAILURES:")
            for f in result["failures"]:
                print(f"  [{f['q']}] {f['reason']}")
        if result["warnings"]:
            print("\nWARNINGS:")
            for w in result["warnings"]:
                print(f"  - {w}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
