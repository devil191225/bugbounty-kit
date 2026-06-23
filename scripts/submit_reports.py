#!/usr/bin/env python3
"""Submit finalized bug bounty reports to HackerOne via API."""

import base64
import json
import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

KIT_ROOT = Path(__file__).parent.parent
load_dotenv(KIT_ROOT / ".env")

H1_BASE  = "https://api.hackerone.com/v1"
H1_USER  = os.getenv("H1_USERNAME", "")
H1_TOKEN = os.getenv("H1_API_TOKEN", "")

def auth_headers():
    creds = base64.b64encode(f"{H1_USER}:{H1_TOKEN}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

def submit(program_handle, title, severity, body, impact, cvss=None):
    payload = {
        "data": {
            "type": "report",
            "attributes": {
                "title": title,
                "vulnerability_information": body,
                "impact": impact,
                "severity_rating": severity,
            },
            "relationships": {
                "program": {"data": {"type": "program", "id": program_handle}}
            },
        }
    }
    if cvss:
        payload["data"]["attributes"]["cvss_vector_string"] = cvss

    r = httpx.post(f"{H1_BASE}/reports", headers=auth_headers(), json=payload, timeout=30)
    return r.status_code, r.json()


def read_report(path):
    return Path(path).read_text(encoding="utf-8")


REPORTS_DIR = KIT_ROOT / "reports"

# ── Report 001 ────────────────────────────────────────────────────────────────
r001_body = read_report(REPORTS_DIR / "report-001-delete-protection-bypass.md")
r001_impact = (
    "Projects on gitlab.com that configure package or container registry delete "
    "protection rules receive no actual protection. A malicious or compromised "
    "maintainer can delete packages and container repositories that should require "
    "owner/admin access to delete. This re-opens the exact supply-chain risk "
    "GitLab designed the feature to prevent, while giving admins and owners a "
    "false sense of security — the UI and API accept their protection settings "
    "but silently ignore them at enforcement time."
)

# ── Report 003a ───────────────────────────────────────────────────────────────
r003a_body = read_report(REPORTS_DIR / "report-003a-pat-create-500.md")
r003a_impact = (
    "Any authenticated user on gitlab.com can crash the personalAccessTokenCreate "
    "GraphQL mutation with an unhandled HTTP 500 by supplying documented, "
    "schema-valid input (PERSONAL_PROJECTS, INSTANCE, or ALL_MEMBERSHIPS access "
    "types). Three of four documented granular scope modes are entirely non-functional. "
    "Users cannot create granular PATs for their intended access modes, potentially "
    "forcing them to fall back to broader, less-secure token scopes."
)

# ── Report 003b ───────────────────────────────────────────────────────────────
r003b_body = read_report(REPORTS_DIR / "report-003b-pat-escalation-check-skip.md")
r003b_impact = (
    "A regular PAT can create granular PATs without any scope-boundary verification "
    "against the calling token. The validate_no_privilege_escalation! guard — "
    "which exists and is correctly designed — is unconditionally skipped when the "
    "caller is a non-granular PAT. Current user-level permission checks constrain "
    "practical exploitation today, but as the granular token framework is expanded "
    "(INSTANCE, ALL_MEMBERSHIPS access types are already in the schema), this "
    "structural gap becomes a direct privilege escalation path."
)

reports = [
    {
        "label": "001 — Delete protection bypass",
        "program": "gitlab",
        "title": "Package and Container Registry delete protection rules are unenforced on gitlab.com — security controls silently bypassed by maintainers",
        "severity": "high",
        "body": r001_body,
        "impact": r001_impact,
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
    },
    {
        "label": "003a — personalAccessTokenCreate 500 errors",
        "program": "gitlab",
        "title": "personalAccessTokenCreate GraphQL mutation: PERSONAL_PROJECTS, INSTANCE, and ALL_MEMBERSHIPS access types cause unhandled 500 errors",
        "severity": "low",
        "body": r003a_body,
        "impact": r003a_impact,
        "cvss": None,
    },
    {
        "label": "003b — PAT escalation check skip",
        "program": "gitlab",
        "title": "personalAccessTokenCreate GraphQL mutation: privilege-escalation check is skipped when calling token is a regular (non-granular) PAT",
        "severity": "low",
        "body": r003b_body,
        "impact": r003b_impact,
        "cvss": None,
    },
]

results = []
for r in reports:
    print(f"\nSubmitting: {r['label']} ...", flush=True)
    status, data = submit(
        program_handle=r["program"],
        title=r["title"],
        severity=r["severity"],
        body=r["body"],
        impact=r["impact"],
        cvss=r.get("cvss"),
    )
    if status in (200, 201):
        report_id = data.get("data", {}).get("id", "?")
        print(f"  SUCCESS  -> Report ID: {report_id}  |  https://hackerone.com/reports/{report_id}")
        results.append({"label": r["label"], "status": "submitted", "id": report_id})
    else:
        errors = data.get("errors") or data
        print(f"  FAILED   -> HTTP {status}: {json.dumps(errors, indent=2)}")
        results.append({"label": r["label"], "status": "failed", "http": status, "error": errors})

print("\n-- SUMMARY --")
for r in results:
    if r["status"] == "submitted":
        print(f"  SUBMITTED  {r['label']}  ID {r['id']}")
    else:
        print(f"  FAILED     {r['label']}  {r['error']}")
