#!/usr/bin/env python3
"""
HackerOne MCP Server for bugbounty-kit
======================================
Gives Claude Code direct HackerOne API access:
  - Browse and search programs
  - Pull structured scope → auto-populate SCOPE.md
  - List your existing reports (duplicate prevention)
  - Draft and submit vulnerability reports

Auth: Set H1_USERNAME and H1_API_TOKEN in .env (project root)
Deps: pip install mcp httpx python-dotenv
Run:  python scripts/hackerone_mcp.py   (stdio transport)
"""

import asyncio
import base64
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

# ── ENV / CONFIG ─────────────────────────────────────────────────────────────

KIT_ROOT = Path(__file__).parent.parent
load_dotenv(KIT_ROOT / ".env")

H1_BASE    = "https://api.hackerone.com/v1"
H1_USER    = os.getenv("H1_USERNAME", "")
H1_TOKEN   = os.getenv("H1_API_TOKEN", "")

def _auth_headers() -> dict:
    """Basic auth headers for H1 API."""
    if not H1_USER or not H1_TOKEN:
        raise RuntimeError(
            "H1_USERNAME and H1_API_TOKEN must be set in .env. "
            "Get your API token at: https://hackerone.com/settings/api_token/edit"
        )
    creds = base64.b64encode(f"{H1_USER}:{H1_TOKEN}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "bugbounty-kit/1.0 (claude-code-mcp)",
    }


# ── HTTP HELPERS ──────────────────────────────────────────────────────────────

async def h1_get(endpoint: str, params: dict | None = None) -> dict:
    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"{H1_BASE}{endpoint}",
            headers=_auth_headers(),
            params=params or {},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()


async def h1_post(endpoint: str, payload: dict) -> dict:
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{H1_BASE}{endpoint}",
            headers=_auth_headers(),
            json=payload,
            timeout=30,
        )
        r.raise_for_status()
        return r.json()


# ── MCP SERVER ────────────────────────────────────────────────────────────────

server = Server("hackerone")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="h1_whoami",
            description=(
                "Verify the HackerOne API connection and return current researcher profile: "
                "username, reputation, signal, and impact."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        types.Tool(
            name="h1_list_programs",
            description=(
                "List public HackerOne bug bounty programs. "
                "Search by keyword, filter by bounty eligibility, and paginate results. "
                "Use this to discover programs to target."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "search":         {"type": "string",  "description": "Keyword to filter by program name or handle"},
                    "offers_bounties":{"type": "boolean", "description": "Only show programs that offer monetary bounties"},
                    "page":           {"type": "integer", "description": "Page number (default: 1)"},
                    "page_size":      {"type": "integer", "description": "Results per page (default: 25, max: 100)"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="h1_get_program",
            description=(
                "Get full details of a HackerOne program: policy, bounty table, response times, "
                "and researcher statistics. Read this before starting any engagement."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle": {"type": "string", "description": "Program handle (e.g. 'hackerone', 'shopify', 'gitlab')"},
                },
                "required": ["handle"],
            },
        ),
        types.Tool(
            name="h1_get_scope",
            description=(
                "Get structured in-scope and out-of-scope assets for a HackerOne program. "
                "Returns asset type (URL, CIDR, iOS/Android app, etc.), identifier, "
                "bounty eligibility, and any per-asset instructions."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle": {"type": "string", "description": "Program handle"},
                },
                "required": ["handle"],
            },
        ),
        types.Tool(
            name="h1_sync_scope",
            description=(
                "Sync a HackerOne program's scope directly into SCOPE.md and update SESSION.md "
                "to mark the new engagement as active. Run this once at the start of every new "
                "engagement to load the exact scope before any testing begins."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle": {"type": "string", "description": "Program handle to sync"},
                },
                "required": ["handle"],
            },
        ),
        types.Tool(
            name="h1_list_my_reports",
            description=(
                "List all vulnerability reports you have submitted to HackerOne. "
                "Use this for duplicate checking before drafting a new report. "
                "Filter by program to see only relevant reports."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "program_handle": {"type": "string", "description": "Filter by program handle (optional)"},
                    "state": {
                        "type": "string",
                        "enum": ["new", "triaged", "needs-more-info", "resolved", "not-applicable",
                                 "informative", "duplicate", "spam"],
                        "description": "Filter by report state (optional)",
                    },
                    "page": {"type": "integer", "description": "Page number (default: 1)"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="h1_get_report",
            description="Get the full details of one of your submitted HackerOne reports by ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "report_id": {"type": "integer", "description": "Numeric report ID"},
                },
                "required": ["report_id"],
            },
        ),
        types.Tool(
            name="h1_submit_report",
            description=(
                "Submit a validated vulnerability report to HackerOne. "
                "IMPORTANT: Always draft the report first and show it to the operator. "
                "The 'confirmed' field MUST be explicitly set to true by the operator before calling this. "
                "Never auto-submit without human review."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "program_handle":    {"type": "string",  "description": "Target program handle"},
                    "title":             {"type": "string",  "description": "Report title — concise and specific"},
                    "severity_rating":   {
                        "type": "string",
                        "enum": ["none", "low", "medium", "high", "critical"],
                        "description": "Severity rating",
                    },
                    "body": {
                        "type": "string",
                        "description": (
                            "Full report in Markdown. Must include: "
                            "## Summary, ## Steps to Reproduce (numbered), "
                            "## Impact, ## Remediation, ## References"
                        ),
                    },
                    "impact":            {"type": "string",  "description": "One-paragraph impact description"},
                    "cvss_vector_string":{"type": "string",  "description": "CVSS v3.1 vector string (optional, e.g. CVSS:3.1/AV:N/AC:L/...)"},
                    "weakness_id":       {"type": "integer", "description": "HackerOne weakness/CWE ID (optional)"},
                    "confirmed": {
                        "type": "boolean",
                        "description": "Must be true — operator has reviewed and approved this report for submission",
                    },
                },
                "required": ["program_handle", "title", "severity_rating", "body", "impact", "confirmed"],
            },
        ),
    ]


# ── TOOL DISPATCHER ───────────────────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    try:
        result = await _dispatch(name, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
    except httpx.HTTPStatusError as e:
        error = {
            "error": f"HackerOne API returned {e.response.status_code}",
            "detail": e.response.text[:800],
            "hint": _h1_error_hint(e.response.status_code),
        }
        return [types.TextContent(type="text", text=json.dumps(error, indent=2))]
    except RuntimeError as e:
        return [types.TextContent(type="text", text=json.dumps({"error": str(e)}))]
    except Exception as e:
        return [types.TextContent(type="text", text=json.dumps({"error": type(e).__name__, "detail": str(e)}))]


def _h1_error_hint(status: int) -> str:
    return {
        401: "Check H1_USERNAME and H1_API_TOKEN in your .env file",
        403: "Your API token may not have the required permissions",
        404: "Program handle not found — check spelling at hackerone.com",
        422: "Request validation failed — check required fields",
        429: "Rate limited — wait before retrying",
    }.get(status, "See https://api.hackerone.com/docs/v1")


async def _dispatch(name: str, args: dict) -> Any:

    # ── h1_whoami ──────────────────────────────────────────────────────────────
    if name == "h1_whoami":
        data = await h1_get("/me")
        u = data.get("data", {}).get("attributes", {})
        return {
            "connected": True,
            "username":   u.get("username"),
            "name":       u.get("name"),
            "reputation": u.get("reputation"),
            "signal":     u.get("signal"),
            "impact":     u.get("impact"),
            "profile_url": f"https://hackerone.com/{u.get('username')}",
        }

    # ── h1_list_programs ───────────────────────────────────────────────────────
    elif name == "h1_list_programs":
        page      = args.get("page", 1)
        page_size = min(args.get("page_size", 25), 100)
        params: dict = {
            "page[number]":    page,
            "page[size]":      page_size,
            "sort[direction]": "desc",
            "sort[field]":     "launched_at",
        }
        if args.get("search"):
            params["filter[keyword]"] = args["search"]
        if args.get("offers_bounties"):
            params["filter[offers_bounties]"] = "true"

        data     = await h1_get("/programs", params)
        programs = data.get("data", [])
        return {
            "total_returned": len(programs),
            "page": page,
            "programs": [
                {
                    "handle":          p["attributes"]["handle"],
                    "name":            p["attributes"]["name"],
                    "state":           p["attributes"]["state"],
                    "offers_bounties": p["attributes"].get("offers_bounties", False),
                    "min_bounty":      p["attributes"].get("min_bounty_table_value"),
                    "max_bounty":      p["attributes"].get("max_bounty_table_value"),
                    "launched_at":     p["attributes"].get("launched_at"),
                    "url":             f"https://hackerone.com/{p['attributes']['handle']}",
                }
                for p in programs
            ],
        }

    # ── h1_get_program ─────────────────────────────────────────────────────────
    elif name == "h1_get_program":
        handle = args["handle"]
        data   = await h1_get(f"/programs/{handle}")
        a      = data.get("data", {}).get("attributes", {})
        return {
            "handle":                          handle,
            "name":                            a.get("name"),
            "state":                           a.get("state"),
            "offers_bounties":                 a.get("offers_bounties"),
            "bounty_table":                    a.get("bounty_table"),
            "policy":                          (a.get("policy") or "")[:3000],
            "response_efficiency_percentage":  a.get("response_efficiency_percentage"),
            "avg_time_to_first_response_days": a.get("average_time_to_first_response"),
            "avg_time_to_bounty_days":         a.get("average_time_to_bounty"),
            "resolved_report_count":           a.get("resolved_report_count"),
            "url":                             f"https://hackerone.com/{handle}",
        }

    # ── h1_get_scope ───────────────────────────────────────────────────────────
    elif name == "h1_get_scope":
        handle = args["handle"]
        data   = await h1_get(f"/programs/{handle}/structured_scopes")
        scopes = data.get("data", [])

        in_scope, out_scope = [], []
        for s in scopes:
            a = s.get("attributes", {})
            asset = {
                "type":                   a.get("asset_type"),
                "identifier":             a.get("asset_identifier"),
                "eligible_for_bounty":    a.get("eligible_for_bounty"),
                "eligible_for_submission":a.get("eligible_for_submission"),
                "instruction":            (a.get("instruction") or "")[:500],
            }
            if a.get("eligible_for_submission", True):
                in_scope.append(asset)
            else:
                out_scope.append(asset)

        return {
            "program":        handle,
            "total_assets":   len(scopes),
            "in_scope_count": len(in_scope),
            "out_scope_count":len(out_scope),
            "in_scope":       in_scope,
            "out_scope":      out_scope,
        }

    # ── h1_sync_scope ──────────────────────────────────────────────────────────
    elif name == "h1_sync_scope":
        handle = args["handle"]

        prog_data  = await h1_get(f"/programs/{handle}")
        pa         = prog_data.get("data", {}).get("attributes", {})
        scope_data = await h1_get(f"/programs/{handle}/structured_scopes")
        scopes     = scope_data.get("data", [])

        in_scope_assets, out_scope_assets = [], []
        for s in scopes:
            a = s.get("attributes", {})
            entry = {
                "type":       a.get("asset_type", "URL"),
                "identifier": a.get("asset_identifier", ""),
                "bounty":     a.get("eligible_for_bounty", False),
                "note":       (a.get("instruction") or "").strip()[:200],
            }
            if a.get("eligible_for_submission", True):
                in_scope_assets.append(entry)
            else:
                out_scope_assets.append(entry)

        today       = datetime.now().strftime("%Y-%m-%d")
        bounty_info = str(pa.get("bounty_table") or "See program policy").strip()[:300]
        program_url = f"https://hackerone.com/{handle}"

        # ── Build SCOPE.md ──────────────────────────────────────────────────
        lines = [
            f"# SCOPE.md — {pa.get('name', handle)}",
            f"# Auto-synced from HackerOne on {today}",
            f"# EDIT manually to add any IP ranges or mobile apps from the policy page.",
            "",
            "## Program Info",
            f"PROGRAM_NAME={pa.get('name', handle)}",
            "PLATFORM=hackerone",
            f"PROGRAM_URL={program_url}",
            f"STARTED={today}",
            "MAX_SEVERITY=critical",
            f"BOUNTY_TABLE={bounty_info}",
            "",
            "---",
            "",
            "## IN SCOPE",
            "",
            "### Domains / Subdomains (wildcard supported)",
            "```",
        ]

        url_assets   = [a for a in in_scope_assets if a["type"] in ("URL", "WILDCARD")]
        cidr_assets  = [a for a in in_scope_assets if a["type"] in ("CIDR", "IP_ADDRESS")]
        app_assets   = [a for a in in_scope_assets if a["type"] in ("GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "OTHER_APK")]
        other_assets = [a for a in in_scope_assets if a not in url_assets + cidr_assets + app_assets]

        for a in url_assets:
            tag = " [bounty-eligible]" if a["bounty"] else " [vrt-only]"
            if a["note"]:
                lines.append(f"# {a['note']}")
            lines.append(f"{a['identifier']}{tag}")

        lines += ["```", "", "### IP Ranges", "```"]
        for a in cidr_assets:
            tag = " [bounty-eligible]" if a["bounty"] else " [vrt-only]"
            lines.append(f"{a['identifier']}{tag}")
        if not cidr_assets:
            lines.append("# (none specified — check program policy)")
        lines += ["```", "", "### Mobile Apps", "```"]
        for a in app_assets:
            tag = " [bounty-eligible]" if a["bounty"] else " [vrt-only]"
            lines.append(f"# {a['type']}")
            lines.append(f"{a['identifier']}{tag}")
        if not app_assets:
            lines.append("# (none specified — check program policy)")
        lines += [
            "```",
            "",
            "---",
            "",
            "## OUT OF SCOPE",
            "",
            "### Domains / Endpoints (NEVER TEST THESE)",
            "```",
        ]
        for a in out_scope_assets:
            lines.append(f"# {a['type']}")
            lines.append(a["identifier"])
        lines += [
            "```",
            "",
            "### Vulnerability Classes (excluded by program)",
            "```",
            "# Rate limiting without demonstrated impact",
            "# Missing security headers (informational only)",
            "# Self-XSS",
            "# CSV injection",
            "# Open redirects without security impact",
            "```",
            "",
            "---",
            "",
            "## PROGRAM-SPECIFIC NOTES",
            "```",
            f"# Synced from: {program_url}",
            f"# Bounty table: {bounty_info}",
            "# Review the full policy before testing: check for excluded vuln classes,",
            "# safe harbor language, and any special submission requirements.",
            "```",
            "",
            "---",
            "",
            "## SCOPE VALIDATION FUNCTION",
            "# Claude Code: Before testing any asset, run this check mentally:",
            "# 1. Is the exact domain/IP listed in IN SCOPE?",
            "# 2. Does it match a wildcard in IN SCOPE?",
            "# 3. Is it explicitly listed in OUT OF SCOPE?",
            "# 4. If uncertain → DO NOT TEST → ask operator",
        ]

        scope_file = KIT_ROOT / "SCOPE.md"
        scope_file.write_text("\n".join(lines), encoding="utf-8")

        # ── Update SESSION.md ────────────────────────────────────────────────
        session_file = KIT_ROOT / "SESSION.md"
        if session_file.exists():
            now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            session = session_file.read_text(encoding="utf-8")
            session = re.sub(r"LAST_UPDATED=.*",  f"LAST_UPDATED={now}",      session)
            session = re.sub(r"CURRENT_TARGET=.*", f"CURRENT_TARGET={handle}", session)
            session = re.sub(r"PHASE=.*",          "PHASE=passive-recon",       session)
            session = re.sub(
                r"SESSION_ID=.*",
                f"SESSION_ID={datetime.now().strftime('%Y-%m-%d')}-001",
                session,
            )
            log_line = (
                f"\n[{now}] [h1_sync_scope] Synced scope for {handle} "
                f"({len(in_scope_assets)} in-scope, {len(out_scope_assets)} out-of-scope)"
            )
            if "## Session Log\n```" in session:
                session = session.replace("## Session Log\n```", f"## Session Log\n```{log_line}")
            session_file.write_text(session, encoding="utf-8")

        return {
            "synced":           True,
            "program":          pa.get("name", handle),
            "handle":           handle,
            "program_url":      program_url,
            "in_scope_count":   len(in_scope_assets),
            "out_scope_count":  len(out_scope_assets),
            "scope_file":       str(scope_file),
            "session_updated":  True,
            "next_step":        (
                f"SCOPE.md is ready. Begin passive recon on {handle}. "
                f"Load skills/recon.md and start with: subfinder, gau, theHarvester."
            ),
        }

    # ── h1_list_my_reports ─────────────────────────────────────────────────────
    elif name == "h1_list_my_reports":
        params: dict = {
            "page[number]": args.get("page", 1),
            "page[size]":   25,
        }
        if args.get("program_handle"):
            params["filter[program][]"] = args["program_handle"]
        if args.get("state"):
            params["filter[state][]"] = args["state"]

        data    = await h1_get("/me/reports", params)
        reports = data.get("data", [])
        return {
            "count":   len(reports),
            "page":    args.get("page", 1),
            "reports": [
                {
                    "id":         r["id"],
                    "title":      r["attributes"].get("title"),
                    "state":      r["attributes"].get("state"),
                    "severity":   r["attributes"].get("severity_rating"),
                    "created_at": r["attributes"].get("created_at"),
                    "triaged_at": r["attributes"].get("triaged_at"),
                    "closed_at":  r["attributes"].get("closed_at"),
                    "url":        f"https://hackerone.com/reports/{r['id']}",
                }
                for r in reports
            ],
        }

    # ── h1_get_report ──────────────────────────────────────────────────────────
    elif name == "h1_get_report":
        report_id = args["report_id"]
        data      = await h1_get(f"/reports/{report_id}")
        a         = data.get("data", {}).get("attributes", {})
        return {
            "id":              report_id,
            "title":           a.get("title"),
            "state":           a.get("state"),
            "severity":        a.get("severity_rating"),
            "body":            (a.get("vulnerability_information") or "")[:4000],
            "impact":          (a.get("impact") or ""),
            "created_at":      a.get("created_at"),
            "triaged_at":      a.get("triaged_at"),
            "closed_at":       a.get("closed_at"),
            "bounty_awarded":  a.get("bounty_awarded_amount"),
            "url":             f"https://hackerone.com/reports/{report_id}",
        }

    # ── h1_submit_report ───────────────────────────────────────────────────────
    elif name == "h1_submit_report":
        if not args.get("confirmed"):
            return {
                "submitted": False,
                "blocked":   True,
                "reason": (
                    "Submission requires operator confirmation. "
                    "Show the complete report draft to the operator, get explicit approval, "
                    "then set confirmed=true and call this tool again."
                ),
            }

        payload: dict = {
            "data": {
                "type": "report",
                "attributes": {
                    "title":                      args["title"],
                    "vulnerability_information":  args["body"],
                    "impact":                     args["impact"],
                    "severity_rating":            args["severity_rating"],
                },
                "relationships": {
                    "program": {
                        "data": {"type": "program", "id": args["program_handle"]}
                    }
                },
            }
        }
        if args.get("cvss_vector_string"):
            payload["data"]["attributes"]["cvss_vector_string"] = args["cvss_vector_string"]
        if args.get("weakness_id"):
            payload["data"]["relationships"]["weakness"] = {
                "data": {"type": "weakness", "id": str(args["weakness_id"])}
            }

        data      = await h1_post("/reports", payload)
        report    = data.get("data", {})
        report_id = report.get("id")

        # Log to SESSION.md
        session_file = KIT_ROOT / "SESSION.md"
        if session_file.exists() and report_id:
            now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            session = session_file.read_text(encoding="utf-8")
            log_line = (
                f"\n[{now}] [SUBMITTED] Report #{report_id} ({args['severity_rating'].upper()}): "
                f"{args['title']} → https://hackerone.com/reports/{report_id}"
            )
            if "## Session Log\n```" in session:
                session = session.replace("## Session Log\n```", f"## Session Log\n```{log_line}")
            session_file.write_text(session, encoding="utf-8")

        return {
            "submitted":   True,
            "report_id":   report_id,
            "title":       args["title"],
            "severity":    args["severity_rating"],
            "program":     args["program_handle"],
            "url":         f"https://hackerone.com/reports/{report_id}" if report_id else None,
            "state":       report.get("attributes", {}).get("state"),
            "next_step":   "Monitor report status at the URL above. Respond promptly to any triage questions.",
        }

    else:
        return {"error": f"Unknown tool: {name}"}


# ── ENTRYPOINT ────────────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
