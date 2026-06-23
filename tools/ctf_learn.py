#!/usr/bin/env python3
"""
ctf_learn.py  Log a CTF challenge outcome and surface transferable live patterns.

After solving (or failing) a CTF challenge, call this tool to store the pattern
in hunt memory tagged environment=ctf. The tool then queries the pattern DB for
similar live-program patterns you should try next.

Usage:
  python3 tools/ctf_learn.py log \
    --challenge "HackTheBox OAuth PKCE" \
    --vuln-class oauth_oidc \
    --technique "PKCE code_challenge bound late — intercepted before binding" \
    --tech-stack "oauth2,oidc,python" \
    --context "Server accepted code_challenge after code was already issued" \
    --signals "no error on late challenge, code exchangeable without verifier" \
    --outcome valid \
    --notes "Check when and where code_challenge is bound in PKCE flows"

  python3 tools/ctf_learn.py suggest --vuln-class oauth_oidc
  python3 tools/ctf_learn.py suggest --target-type saas
  python3 tools/ctf_learn.py weights --target-type saas
  python3 tools/ctf_learn.py list-ctf
  python3 tools/ctf_learn.py flush   # drain the auto-queue from post-tool hook into pattern DB
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from memory.pattern_db import PatternDB
from memory.schemas import (
    make_pattern_entry,
    VALID_ENVIRONMENTS,
    VALID_TARGET_TYPES,
    VALID_OUTCOMES,
    CTF_ONLY_TECHNIQUES,
)
from tools.banner import print_banner  # noqa: E402

# ── Colour codes ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

MEMORY_DIR = Path(_REPO) / "hunt-memory"
PATTERNS_FILE = MEMORY_DIR / "patterns.jsonl"
AUTO_QUEUE = Path(_REPO) / "sessions" / "auto-ctf-learn-queue.jsonl"

# ── Bug classes the notes.txt specifically calls out to grind in CTF ───────────
PRIORITY_BUG_CLASSES = {
    "oauth_oidc": "OAuth / OIDC mistakes (prompt, max_age, PKCE, state, nonce)",
    "ssrf":       "SSRF via profile/webhook/metadata URLs",
    "logic_qr":   "Logic bugs around QR / magic link / SSO flows",
}


def _db() -> PatternDB:
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    return PatternDB(PATTERNS_FILE)


def _print_pattern(p: dict, idx: int) -> None:
    env    = p.get("environment", "?")
    vc     = p.get("vuln_class", "?")
    tech   = p.get("technique", "?")
    stack  = ", ".join(p.get("tech_stack", []))
    outcome = p.get("outcome", "?")
    target_type = p.get("target_type", "?")
    ctx    = p.get("context", "")
    signals = p.get("signals", [])
    notes  = p.get("notes", "")
    ts     = p.get("ts", "")[:10]

    env_colour = GREEN if env == "live" else CYAN
    outcome_colour = GREEN if outcome in ("valid", "high_impact") else (
        RED if outcome == "no_effect" else YELLOW
    )

    print(f"\n  {BOLD}[{idx}]{RESET} {env_colour}[{env.upper()}]{RESET}  "
          f"{BOLD}{vc}{RESET}  {DIM}({ts}){RESET}")
    print(f"       Technique : {tech}")
    print(f"       Stack     : {stack}")
    print(f"       Target type: {target_type}  "
          f"Outcome: {outcome_colour}{outcome}{RESET}")
    if ctx:
        print(f"       Context   : {ctx}")
    if signals:
        print(f"       Signals   : {', '.join(signals)}")
    if notes:
        print(f"       Notes     : {notes}")


def cmd_log(args) -> None:
    """Store a CTF challenge outcome in the pattern DB."""
    signals = [s.strip() for s in args.signals.split(",") if s.strip()] if args.signals else None

    entry = make_pattern_entry(
        target=args.challenge,
        vuln_class=args.vuln_class,
        technique=args.technique,
        tech_stack=[t.strip() for t in args.tech_stack.split(",") if t.strip()],
        environment="ctf",
        target_type="ctf_challenge",
        outcome=args.outcome,
        context=args.context or None,
        signals=signals,
        notes=args.notes or None,
        tags=["ctf"] + (["priority"] if args.vuln_class in PRIORITY_BUG_CLASSES else []),
    )

    db = _db()
    saved = db.save(entry)

    if not saved:
        print(f"{YELLOW}[dup]{RESET} Pattern already stored for this challenge+vuln_class+technique.")
        return

    print(f"{GREEN}[saved]{RESET} CTF pattern logged: {args.challenge} / {args.vuln_class}")
    print()

    # Immediately surface transferable live strategies for the same vuln class
    live = db.get_live_strategies(vuln_class=args.vuln_class)
    ctf_blocked = [p for p in db.get_ctf_patterns(vuln_class=args.vuln_class)
                   if any(t in p.get("technique", "").lower() for t in CTF_ONLY_TECHNIQUES)]

    if live:
        print(f"{BOLD}Transferable live strategies for [{args.vuln_class}]:{RESET}")
        for i, p in enumerate(live[:5], 1):
            _print_pattern(p, i)
    else:
        print(f"{DIM}No live strategies for [{args.vuln_class}] yet — you're building the DB.{RESET}")

    if ctf_blocked:
        print(f"\n{YELLOW}[BLOCKED on live]{RESET} These CTF techniques use brute-force/flood/data-manipulation — do NOT use on live programs:")
        for p in ctf_blocked[:3]:
            print(f"  - {p.get('technique')}")

    print()
    _print_priority_reminder(args.vuln_class)


def cmd_suggest(args) -> None:
    """Show live-safe strategies for a vuln class or target type."""
    db = _db()
    live = db.get_live_strategies(
        vuln_class=args.vuln_class or None,
        target_type=args.target_type or None,
    )

    label = args.vuln_class or args.target_type or "all"
    print(f"{BOLD}Live-safe strategies [{label}]:{RESET}")

    if not live:
        print(f"  {DIM}No patterns yet. Solve some CTF challenges and use `ctf_learn.py log` to build the DB.{RESET}")
        return

    for i, p in enumerate(live[:10], 1):
        _print_pattern(p, i)
    print()


def cmd_weights(args) -> None:
    """Show per-vuln-class success rates for a target type."""
    db = _db()
    weights = db.get_strategy_weights(args.target_type)

    if not weights:
        print(f"{DIM}No patterns with target_type={args.target_type!r} yet.{RESET}")
        return

    print(f"{BOLD}Strategy weights for target_type={args.target_type}:{RESET}\n")
    sorted_vc = sorted(weights.items(), key=lambda kv: kv[1]["rate"], reverse=True)
    for vc, stats in sorted_vc:
        rate = stats["rate"]
        colour = GREEN if rate >= 0.5 else (YELLOW if rate >= 0.2 else RED)
        print(f"  {colour}{rate:.0%}{RESET}  {vc:30s}  "
              f"valid={stats.get('valid', 0)}  "
              f"high={stats.get('high_impact', 0)}  "
              f"dup={stats.get('duplicate', 0)}  "
              f"n={stats['total']}")
    print()


def cmd_list_ctf(args) -> None:
    """List all CTF-sourced patterns."""
    db = _db()
    patterns = db.get_ctf_patterns(vuln_class=args.vuln_class or None)

    if not patterns:
        print(f"{DIM}No CTF patterns stored yet.{RESET}")
        return

    print(f"{BOLD}CTF patterns ({len(patterns)}):{RESET}")
    for i, p in enumerate(patterns, 1):
        _print_pattern(p, i)
    print()


def cmd_flush(args) -> None:
    """Drain sessions/auto-ctf-learn-queue.jsonl into the pattern DB.

    The post-tool hook writes an entry every time a hunt probe is detected.
    This command converts those raw queue entries into proper pattern DB records.
    Called automatically at session start (see CLAUDE.md SESSION STARTUP CHECKLIST).
    """
    if not AUTO_QUEUE.exists():
        print(f"{DIM}No auto-learn queue found — nothing to flush.{RESET}")
        return

    lines = AUTO_QUEUE.read_text(encoding="utf-8").strip().splitlines()
    if not lines:
        print(f"{DIM}Auto-learn queue is empty.{RESET}")
        return

    db = _db()
    saved = 0
    skipped = 0

    for line in lines:
        try:
            q = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue

        # Build a minimal pattern entry from the auto-logged queue entry
        vuln_class = q.get("vuln_class", "unknown")
        technique  = q.get("technique", "auto-detected")
        outcome    = q.get("outcome", "informational")
        env        = q.get("environment", "live")
        cmd        = q.get("command_snippet", "")
        res_snip   = q.get("result_snippet", "")

        # Derive a rough tech_stack from the command
        tech_stack = []
        if re.search(r"oauth|oidc|openid", cmd, re.IGNORECASE):
            tech_stack.append("oauth2")
        if re.search(r"saml", cmd, re.IGNORECASE):
            tech_stack.append("saml")
        if re.search(r"graphql", cmd, re.IGNORECASE):
            tech_stack.append("graphql")
        if not tech_stack:
            tech_stack = ["http"]

        try:
            entry = make_pattern_entry(
                target=f"auto-logged-{q.get('ts', '')[:10]}",
                vuln_class=vuln_class,
                technique=technique,
                tech_stack=tech_stack,
                environment=env,
                target_type="other",
                outcome=outcome,
                context=cmd[:200] if cmd else None,
                signals=[res_snip[:150]] if res_snip else None,
                tags=["auto_logged"],
            )
            if db.save(entry):
                saved += 1
            else:
                skipped += 1
        except Exception as e:
            skipped += 1
            print(f"{YELLOW}[skip]{RESET} Could not convert queue entry: {e}")

    # Archive the queue
    archive = AUTO_QUEUE.with_suffix(f".{datetime.now().strftime('%Y%m%d%H%M%S')}.done")
    AUTO_QUEUE.rename(archive)

    print(f"{GREEN}[flush]{RESET} {saved} entries added to pattern DB, {skipped} skipped.")
    print(f"{DIM}Queue archived to: {archive.name}{RESET}")


def _print_priority_reminder(vuln_class: str | None = None) -> None:
    """Print which priority bug classes to focus CTF grinding on."""
    print(f"{DIM}Priority bug classes to grind in CTF (per notes.txt):{RESET}")
    for vc, desc in PRIORITY_BUG_CLASSES.items():
        marker = f"{GREEN}✓{RESET}" if vc == vuln_class else " "
        print(f"  {marker} {vc:15s} — {desc}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CTF learning loop — log challenge outcomes, surface live-program strategies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── log ──────────────────────────────────────────────────────────────────
    p_log = sub.add_parser("log", help="Log a CTF challenge outcome")
    p_log.add_argument("--challenge",  required=True, help="Challenge name (e.g. 'HTB OAuth PKCE')")
    p_log.add_argument("--vuln-class", required=True, dest="vuln_class",
                       help=f"Bug class: {', '.join(PRIORITY_BUG_CLASSES)}, or any string")
    p_log.add_argument("--technique",  required=True,
                       help="Exact exploit technique — be specific (this is the search key)")
    p_log.add_argument("--tech-stack", required=True, dest="tech_stack",
                       help="Comma-separated techs (e.g. oauth2,oidc,python)")
    p_log.add_argument("--outcome",    required=True, choices=sorted(VALID_OUTCOMES),
                       help="What happened")
    p_log.add_argument("--context",    default="",
                       help="What made the target vulnerable (one sentence)")
    p_log.add_argument("--signals",    default="",
                       help="Comma-separated observable signals that telegraphed the bug")
    p_log.add_argument("--notes",      default="",
                       help="Free-form notes for future transfer to live programs")
    p_log.set_defaults(func=cmd_log)

    # ── suggest ───────────────────────────────────────────────────────────────
    p_sug = sub.add_parser("suggest", help="Show live-safe strategies from pattern DB")
    p_sug.add_argument("--vuln-class",  default="", dest="vuln_class")
    p_sug.add_argument("--target-type", default="", dest="target_type",
                       choices=sorted(VALID_TARGET_TYPES) + [""])
    p_sug.set_defaults(func=cmd_suggest)

    # ── weights ───────────────────────────────────────────────────────────────
    p_wt = sub.add_parser("weights", help="Show per-vuln-class success rates for a target type")
    p_wt.add_argument("--target-type", required=True, dest="target_type",
                      choices=sorted(VALID_TARGET_TYPES))
    p_wt.set_defaults(func=cmd_weights)

    # ── list-ctf ──────────────────────────────────────────────────────────────
    p_list = sub.add_parser("list-ctf", help="List all stored CTF patterns")
    p_list.add_argument("--vuln-class", default="", dest="vuln_class")
    p_list.set_defaults(func=cmd_list_ctf)

    # ── flush ──────────────────────────────────────────────────────────────────
    p_flush = sub.add_parser("flush", help="Drain the auto-hook queue into the pattern DB")
    p_flush.set_defaults(func=cmd_flush)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
