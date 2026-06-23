#!/usr/bin/env python3
"""
hooks/post-tool-logger.py
Claude Code hook: runs after every tool call to:
  1. Log commands + results to SESSION.md
  2. Auto-detect hunt attempts and queue CTF-learn entries for autonomous pattern learning
"""

import json
import os
import sys
import re
import subprocess
from datetime import datetime
from pathlib import Path


def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def truncate(text: str, max_len: int = 500) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"... [{len(text)-max_len} chars truncated]"


def update_session_log(command: str, result: str, tool: str):
    session_file = Path(__file__).parent.parent / "SESSION.md"
    if not session_file.exists():
        return
    
    content = session_file.read_text()
    
    # Format log entry
    ts = get_timestamp()
    cmd_short = command[:120].replace('\n', ' ')
    result_short = truncate(result.strip(), 200).replace('\n', ' | ')
    
    log_entry = f"\n[{ts}] [{tool}] {cmd_short}\n  → {result_short}"
    
    # Update LAST_UPDATED
    content = re.sub(r'LAST_UPDATED=.*', f'LAST_UPDATED={ts}', content)
    
    # Append to session log section
    if '## Session Log' in content:
        content = content.replace('## Session Log\n```', f'## Session Log\n```{log_entry}')
    
    session_file.write_text(content)


REPO_ROOT = Path(__file__).parent.parent

# ── Vuln-class inference from command patterns ────────────────────────────────
# Maps (regex_on_command, regex_on_output) → (vuln_class, technique_hint)
# Used to autonomously populate the CTF-learn queue without a manual /ctf-learn call.
HUNT_SIGNAL_MAP = [
    # OAuth / OIDC
    (r"prompt=none",             r"",               "oauth_oidc",   "prompt=none test"),
    (r"max_age=",                r"",               "oauth_oidc",   "max_age parameter test"),
    (r"code_challenge",          r"",               "oauth_oidc",   "PKCE code_challenge test"),
    (r"response_type=token",     r"",               "oauth_oidc",   "implicit flow test"),
    (r"redirect_uri=",           r"http[^&\s]+",    "oauth_oidc",   "redirect_uri manipulation"),
    # SSRF
    (r"burpcollaborator|interact\.sh|oast\.", r"", "ssrf",         "OOB callback probe"),
    (r"169\.254\.169\.254",      r"",               "ssrf",         "cloud metadata endpoint probe"),
    (r"ssrf|server.side.request",r"",               "ssrf",         "SSRF probe"),
    # QR / magic link / SSO logic
    (r"qr.code|magic.link|one.time.token", r"",   "logic_qr",     "QR/magic-link session test"),
    (r"saml|SAMLResponse",       r"",               "saml",         "SAML assertion test"),
    # IDOR
    (r"/api/.*\d+",              r"200",            "idor",         "direct object reference probe"),
    # Injection
    (r"'\s*or\s*'|--\s|union\s+select", r"",       "sqli",         "SQL injection probe"),
    (r"<script|javascript:|onerror=", r"",          "xss",          "XSS probe"),
]


def infer_vuln_class(command: str, result: str) -> tuple[str, str] | None:
    """Return (vuln_class, technique) if the command matches a known hunt signal, else None."""
    for cmd_pat, out_pat, vc, technique in HUNT_SIGNAL_MAP:
        if re.search(cmd_pat, command, re.IGNORECASE):
            if not out_pat or re.search(out_pat, result, re.IGNORECASE):
                return vc, technique
    return None


def infer_outcome(result: str) -> str:
    """Infer a rough outcome from HTTP response output."""
    # Look for HTTP status in curl -v / httpx output
    status_match = re.search(r"< HTTP/[\d.]+ (\d{3})|HTTP/[\d.]+ (\d{3})", result)
    if status_match:
        code = int(status_match.group(1) or status_match.group(2))
        if code == 200:
            # 200 alone isn't confirmed — flag as partial for human review
            return "informational"
        if code in (401, 403, 404):
            return "no_effect"
        if code in (301, 302):
            # Redirect could be interesting — informational
            return "informational"
    # OOB callback received = high signal
    if re.search(r"dns.*lookup|http.*request|callback.*received|oast\.", result, re.IGNORECASE):
        return "valid"
    return "informational"


def auto_queue_ctf_learn(command: str, result: str) -> None:
    """If the command looks like a hunt attempt, append to the auto-learn queue.

    The queue (sessions/auto-ctf-learn-queue.jsonl) is processed by ctf_learn.py
    or consumed directly by the pattern DB on the next session start.
    """
    inferred = infer_vuln_class(command, result)
    if not inferred:
        return

    vuln_class, technique = inferred
    outcome = infer_outcome(result)

    queue_file = REPO_ROOT / "sessions" / "auto-ctf-learn-queue.jsonl"
    queue_file.parent.mkdir(exist_ok=True)

    entry = {
        "ts": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "vuln_class": vuln_class,
        "technique": technique,
        "outcome": outcome,
        "command_snippet": command[:200],
        "result_snippet": result[:300],
        "environment": "live",   # post-tool hook only fires on real commands
        "auto_logged": True,
    }

    with open(queue_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def detect_findings(result: str) -> list:
    """Look for patterns that suggest a finding was discovered."""
    finding_patterns = [
        (r'200 OK.*?(IDOR|injection|XSS|SQLi|traversal|SSRF|RCE)', 'Potential vulnerability in response'),
        (r'private|secret|password|api.?key|token', 'Sensitive data exposure'),
        (r'AWS_SECRET|AKIA[A-Z0-9]{16}', 'Potential AWS key exposure'),
        (r'\[HIGH\]|\[CRITICAL\]', 'High/Critical nuclei finding'),
        (r'NoSuchBucket|AccessDenied', 'S3 bucket enumeration result'),
    ]

    findings = []
    for pattern, description in finding_patterns:
        if re.search(pattern, result, re.IGNORECASE):
            findings.append(description)

    return findings


def main():
    try:
        hook_input = json.loads(sys.stdin.read())
    except:
        sys.exit(0)

    tool_name = hook_input.get("tool", "")
    tool_input = hook_input.get("input", {})
    tool_output = hook_input.get("output", "")

    command = tool_input.get("command", tool_input.get("input", str(tool_input)))
    result = str(tool_output)

    # Log to SESSION.md
    update_session_log(command, result, tool_name)

    # Auto-queue CTF-learn entry if this looks like a hunt probe
    try:
        auto_queue_ctf_learn(command, result)
    except Exception:
        pass  # Never let the learning queue break the main hook

    # Check for potential findings and flag them
    findings = detect_findings(result)
    if findings:
        findings_file = REPO_ROOT / "sessions" / "potential-findings.txt"
        findings_file.parent.mkdir(exist_ok=True)
        with open(findings_file, 'a') as f:
            f.write(f"\n[{get_timestamp()}] POTENTIAL FINDING\n")
            f.write(f"Command: {command[:200]}\n")
            f.write(f"Triggers: {', '.join(findings)}\n")
            f.write(f"Output snippet: {result[:300]}\n")
            f.write("---\n")

    sys.exit(0)


if __name__ == "__main__":
    main()
