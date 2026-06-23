#!/usr/bin/env python3
"""
hooks/pre-tool-check.py
Claude Code hook: runs before every tool call to enforce scope and safety.
Install: add to hooks.pre_tool_call in CLAUDE.md or .claude/hooks.json
"""

import json
import sys
import re
from pathlib import Path

# Load scope from SCOPE.md
def load_scope():
    scope_file = Path(__file__).parent.parent / "SCOPE.md"
    if not scope_file.exists():
        return [], []
    
    content = scope_file.read_text()
    in_scope = []
    out_scope = []
    
    # Parse in-scope section
    in_match = re.search(r'## IN SCOPE.*?## OUT OF SCOPE', content, re.DOTALL)
    out_match = re.search(r'## OUT OF SCOPE.*?(?:##|\Z)', content, re.DOTALL)
    
    if in_match:
        for line in in_match.group().split('\n'):
            line = line.strip().lstrip('#').strip()
            if line and not line.startswith('#') and not line.startswith('`') and '.' in line:
                in_scope.append(line.strip('`'))
    
    if out_match:
        for line in out_match.group().split('\n'):
            line = line.strip().lstrip('#').strip()
            if line and not line.startswith('#') and not line.startswith('`') and '.' in line:
                out_scope.append(line.strip('`'))
    
    return in_scope, out_scope


def extract_urls_from_command(command: str) -> list:
    """Extract any URLs or hostnames from a shell command."""
    urls = re.findall(r'https?://([^\s/"\']+)', command)
    domains = re.findall(r'-d\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', command)
    hosts = re.findall(r'--host\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', command)
    targets = re.findall(r'(?:^|\s)([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})(?:\s|$)', command)
    return list(set(urls + domains + hosts))


def is_in_scope(target: str, in_scope: list, out_scope: list) -> tuple:
    """Check if target is in scope. Returns (allowed, reason)."""
    
    # Check out-of-scope first (takes priority)
    for oos in out_scope:
        oos_clean = oos.replace('*', '').lstrip('.')
        if oos_clean and oos_clean in target:
            return False, f"OUT OF SCOPE: '{target}' matches '{oos}'"
    
    # Check in-scope
    for ins in in_scope:
        if ins.startswith('*.'):
            # Wildcard: *.example.com matches sub.example.com
            parent = ins[2:]  # Remove '*.'
            if target == parent or target.endswith('.' + parent):
                return True, f"IN SCOPE: matches wildcard '{ins}'"
        elif ins == target or target.endswith('.' + ins):
            return True, f"IN SCOPE: matches '{ins}'"
    
    if in_scope:
        return False, f"NOT IN SCOPE: '{target}' not found in scope list"
    
    return True, "No scope configured (pass-through)"


# ── DANGEROUS COMMAND PATTERNS ──────────────────────────────────────────────
DANGEROUS_PATTERNS = [
    (r'sqlmap.*--dump', "sqlmap --dump requires explicit operator confirmation"),
    (r'sqlmap.*--os-shell', "sqlmap --os-shell requires explicit operator confirmation"),
    (r'sqlmap.*--os-pwn', "sqlmap --os-pwn requires explicit operator confirmation"),
    (r'hydra.*-P.*rockyou', "Large wordlist brute force requires explicit operator confirmation"),
    (r'rm\s+-rf\s+/', "Dangerous filesystem operation blocked"),
    (r'mkfs', "Disk formatting blocked"),
    (r'dd\s+if=.*of=/dev', "Raw disk write blocked"),
    (r':(){ :|:& };:', "Fork bomb pattern detected"),
]

def check_dangerous(command: str) -> tuple:
    """Check for dangerous command patterns. Returns (safe, warning)."""
    for pattern, message in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return False, message
    return True, ""


REPO_ROOT = Path(__file__).parent.parent


def check_report_evidence_integrity(file_path: str, content: str) -> tuple:
    """Block report writes that have no POC_FILE or whose POC_FILE doesn't exist on disk.

    Returns (safe, error_message).
    """
    # Only enforce on files being written inside reports/
    try:
        rel = Path(file_path).relative_to(REPO_ROOT / "reports")
    except ValueError:
        return True, ""  # Not a report file — pass through

    # Must contain POC_FILE field
    poc_match = re.search(r"POC_FILE:\s*(.+)", content)
    if not poc_match:
        return False, (
            "EVIDENCE INTEGRITY VIOLATION\n\n"
            "Report is missing required POC_FILE field.\n"
            "Every report must reference a real HTTP response saved to disk.\n"
            "If you cannot reproduce the finding, write CANNOT_REPRODUCE and stop.\n"
            "NEVER fabricate HTTP responses, status codes, or headers."
        )

    poc_value = poc_match.group(1).strip()

    # Skip template placeholder values
    placeholder_patterns = [
        "sessions/<date>",
        "<filename>",
        "CANNOT_REPRODUCE",
        "N/A",
    ]
    if any(p in poc_value for p in placeholder_patterns):
        # If it's a real report (not the template itself) and has a placeholder → block
        if "VULN-XXX" not in content and "CANNOT_REPRODUCE" not in poc_value:
            return False, (
                "EVIDENCE INTEGRITY VIOLATION\n\n"
                f"POC_FILE contains a placeholder value: '{poc_value}'\n"
                "Replace with the actual path to the saved HTTP response.\n"
                "If you cannot reproduce: write CANNOT_REPRODUCE in POC_FILE and stop drafting."
            )
        return True, ""

    # Resolve path — may be relative to repo root or absolute
    poc_path = Path(poc_value)
    if not poc_path.is_absolute():
        poc_path = REPO_ROOT / poc_value

    if not poc_path.exists():
        return False, (
            "EVIDENCE INTEGRITY VIOLATION\n\n"
            f"POC_FILE does not exist on disk: {poc_value}\n\n"
            "You must save the actual HTTP response to disk BEFORE writing a report.\n"
            "Example:\n"
            "  curl -v 'https://target.com/endpoint' > sessions/2026-06-10/target/poc-response.txt 2>&1\n\n"
            "If you cannot reproduce the finding in this session → write CANNOT_REPRODUCE and stop."
        )

    return True, ""


def main():
    # Read tool call from stdin (Claude Code hook format)
    try:
        hook_input = json.loads(sys.stdin.read())
    except:
        sys.exit(0)  # Pass through if we can't parse

    tool_name = hook_input.get("tool", "")
    tool_input = hook_input.get("input", {})

    # ── Evidence integrity check (Write / Edit tool on report files) ──────────
    if tool_name in ("Write", "Edit", "write", "edit"):
        file_path = tool_input.get("file_path", "")
        content = tool_input.get("content", "") or tool_input.get("new_string", "")
        if file_path and "reports/" in file_path:
            # For Edit we need the full new content — check new_string for the POC_FILE
            # field; if absent it may not be in the edited hunk, so we do a lighter check
            if content:
                safe, msg = check_report_evidence_integrity(file_path, content)
                if not safe:
                    print(json.dumps({"action": "block", "reason": msg}))
                    sys.exit(1)
        sys.exit(0)

    # Only check Bash/shell tools for scope + dangerous patterns
    if tool_name not in ["bash", "Bash", "computer", "shell", "execute", "run_command"]:
        sys.exit(0)

    command = tool_input.get("command", tool_input.get("input", ""))

    if not command:
        sys.exit(0)

    in_scope, out_scope = load_scope()

    # Check for dangerous patterns
    safe, danger_msg = check_dangerous(command)
    if not safe:
        print(json.dumps({
            "action": "block",
            "reason": f"⚠️  SAFETY CHECK FAILED: {danger_msg}\n\nCommand: {command[:200]}\n\nTo proceed, explicitly confirm this action is intentional."
        }))
        sys.exit(1)

    # Extract and check targets (only if scope is configured)
    if in_scope:
        targets = extract_urls_from_command(command)
        for target in targets:
            allowed, reason = is_in_scope(target, in_scope, out_scope)
            if not allowed:
                print(json.dumps({
                    "action": "block",
                    "reason": f"🚫 SCOPE VIOLATION BLOCKED\n\n{reason}\n\nCommand attempted: {command[:200]}\n\nVerify your SCOPE.md and retry."
                }))
                sys.exit(1)

    # All checks passed
    sys.exit(0)


if __name__ == "__main__":
    main()
