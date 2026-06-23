#!/usr/bin/env python3
"""
prioritize.py — Hunt prioritization from memory weights + live-safe strategies.

Combines pattern DB success rates with suggested techniques before hunting.

Usage:
  python tools/prioritize.py --target-type fintech
  python tools/prioritize.py --target-type saas --tech oauth,nodejs
  python tools/prioritize.py --target-type ecommerce --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from memory.pattern_db import PatternDB  # noqa: E402

PATTERNS_FILE = _REPO / "hunt-memory" / "patterns.jsonl"

# Default hunt order when memory is empty (from web-vulns.md / CLAUDE.md)
DEFAULT_ORDER = [
    "auth_bypass",
    "oauth_oidc",
    "idor",
    "saml",
    "logic",
    "sqli",
    "ssrf",
    "xss",
    "business_logic",
    "race",
    "graphql",
    "prototype_pollution",
]

QUERY_MAP = {
    "auth_bypass": "authentication bypass MFA session",
    "oauth_oidc": "oauth oidc redirect_uri PKCE",
    "idor": "IDOR BOLA object reference",
    "saml": "SAML XSW signature wrapping",
    "logic": "business logic payment race",
    "sqli": "SQL injection union blind",
    "ssrf": "SSRF cloud metadata",
    "xss": "XSS stored reflected bypass",
    "business_logic": "business logic quota bypass",
    "race": "race condition TOCTOU",
    "graphql": "GraphQL batching IDOR",
    "prototype_pollution": "prototype pollution nodejs",
}


def _db() -> PatternDB:
    PATTERNS_FILE.parent.mkdir(parents=True, exist_ok=True)
    return PatternDB(PATTERNS_FILE)


def _run_weights(target_type: str) -> dict:
    return _db().get_strategy_weights(target_type)


def _run_suggest(target_type: str, vuln_class: str | None = None) -> list[dict]:
    return _db().get_live_strategies(vuln_class=vuln_class, target_type=target_type)


def build_plan(target_type: str, tech: list[str], top_classes: int = 8) -> dict:
    weights = _run_weights(target_type)
    ranked: list[dict] = []

    for vc in DEFAULT_ORDER:
        stats = weights.get(vc, {})
        rate = stats.get("rate", 0.0)
        total = stats.get("total", 0)
        ranked.append({
            "vuln_class": vc,
            "success_rate": rate,
            "samples": total,
            "priority_score": rate if total else 0.1,  # slight prior for untested classes
        })

    ranked.sort(key=lambda x: (x["priority_score"], x["samples"]), reverse=True)
    ranked = ranked[:top_classes]

    for item in ranked:
        vc = item["vuln_class"]
        strategies = _run_suggest(target_type, vuln_class=vc)[:3]
        item["live_strategies"] = [
            {
                "technique": s.get("technique"),
                "outcome": s.get("outcome"),
                "environment": s.get("environment"),
                "safe_for_live": s.get("safe_for_live", True),
            }
            for s in strategies
        ]
        item["os_query"] = QUERY_MAP.get(vc, vc.replace("_", " "))
        if tech:
            item["os_query"] += " " + " ".join(tech)

    return {
        "target_type": target_type,
        "tech_stack": tech,
        "ranked_vuln_classes": ranked,
        "commands": [
            f"python tools/os_query.py \"{r['os_query']}\" --target-type {target_type}"
            for r in ranked[:5]
        ],
    }


def _print_human(plan: dict) -> None:
    print(f"\nHunt plan — target_type={plan['target_type']}")
    if plan["tech_stack"]:
        print(f"Tech: {', '.join(plan['tech_stack'])}\n")
    print(f"{'Rank':<5} {'Class':<22} {'Rate':<6} {'N':<4} Top technique")
    print("-" * 70)
    for i, row in enumerate(plan["ranked_vuln_classes"], 1):
        tech = ""
        if row["live_strategies"]:
            tech = row["live_strategies"][0].get("technique", "")[:40]
        print(f"{i:<5} {row['vuln_class']:<22} {row['success_rate']:<6.2f} {row['samples']:<4} {tech}")
    print("\nSuggested os_query commands:")
    for cmd in plan["commands"]:
        print(f"  {cmd}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Hunt prioritization from hunt memory")
    parser.add_argument("--target-type", required=True, help="Target archetype: saas, fintech, ecommerce, oss, ...")
    parser.add_argument("--tech", default="", help="Comma-separated tech stack hints (oauth,nodejs,...)")
    parser.add_argument("--top", type=int, default=8, help="Max vuln classes to rank")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    tech = [t.strip() for t in args.tech.split(",") if t.strip()]
    plan = build_plan(args.target_type, tech, top_classes=args.top)

    if args.json:
        print(json.dumps(plan, indent=2))
    else:
        _print_human(plan)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
