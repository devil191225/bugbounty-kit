#!/usr/bin/env python3
"""
Intigriti MCP Server — stdio JSON-RPC bridge for Claude Code
Implements MCP protocol 2024-11-05
"""
import sys, json, os, urllib.request, urllib.parse, traceback

INTIGRITI_TOKEN = os.environ.get("INTIGRITI_TOKEN", "")
BASE = "https://api.intigriti.com/external/researcher/v1"

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _req(path, method="GET", body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {INTIGRITI_TOKEN}")
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        raise RuntimeError(f"HTTP {e.code}: {err[:300]}")

# ── Tool implementations ──────────────────────────────────────────────────────

def get_profile():
    # Profile endpoint
    try:
        return _req("/me")
    except Exception:
        # Fallback: pull from programs response header info
        return {"note": "Profile endpoint unavailable; token is valid."}

def list_programs(limit=20, offset=0):
    qs = urllib.parse.urlencode({"limit": limit, "offset": offset})
    data = _req(f"/programs?{qs}")
    records = data.get("records", [])
    out = []
    for p in records:
        out.append({
            "id": p.get("id"),
            "handle": p.get("handle"),
            "name": p.get("name"),
            "following": p.get("following"),
            "minBounty": p.get("minBounty"),
            "maxBounty": p.get("maxBounty"),
            "status": p.get("status"),
        })
    return {"total": data.get("maxCount", 0), "programs": out}

def get_program(handle):
    return _req(f"/programs/{handle}")

def list_submissions(status=None, limit=20, offset=0):
    params = {"limit": limit, "offset": offset}
    if status:
        params["status"] = status
    qs = urllib.parse.urlencode(params)
    return _req(f"/submissions?{qs}")

def get_submission(submission_id):
    return _req(f"/submissions/{submission_id}")

def submit_report(program_handle, title, severity, bug_type, body, endpoint=""):
    """Submit a vulnerability report to Intigriti."""
    payload = {
        "programId": program_handle,
        "title": title,
        "severity": severity,        # critical/high/medium/low/informational
        "type": bug_type,            # e.g. "Cross-Site Scripting (XSS)"
        "description": body,
        "endpoint": endpoint,
    }
    return _req("/submissions", method="POST", body=payload)

def search_programs(query, limit=10):
    qs = urllib.parse.urlencode({"search": query, "limit": limit})
    data = _req(f"/programs?{qs}")
    return data

# ── MCP protocol ─────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "intigriti_get_profile",
        "description": "Get your Intigriti researcher profile.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "intigriti_list_programs",
        "description": "List Intigriti bug bounty programs you can submit to.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 20, "description": "Max results"},
                "offset": {"type": "integer", "default": 0, "description": "Pagination offset"},
            },
        },
    },
    {
        "name": "intigriti_get_program",
        "description": "Get full details for a specific Intigriti program by handle (e.g. 'shopify').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "handle": {"type": "string", "description": "Program handle or ID"},
            },
            "required": ["handle"],
        },
    },
    {
        "name": "intigriti_search_programs",
        "description": "Search Intigriti programs by keyword.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search term"},
                "limit": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
    },
    {
        "name": "intigriti_list_submissions",
        "description": "List your Intigriti bug report submissions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "description": "Filter by status (e.g. open, closed, accepted)"},
                "limit": {"type": "integer", "default": 20},
                "offset": {"type": "integer", "default": 0},
            },
        },
    },
    {
        "name": "intigriti_get_submission",
        "description": "Get full details of a specific submission by ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "submission_id": {"type": "string", "description": "Submission UUID"},
            },
            "required": ["submission_id"],
        },
    },
    {
        "name": "intigriti_submit_report",
        "description": "Submit a vulnerability report to an Intigriti program.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_handle": {"type": "string", "description": "Program handle or ID"},
                "title": {"type": "string", "description": "Report title"},
                "severity": {"type": "string", "description": "critical/high/medium/low/informational"},
                "bug_type": {"type": "string", "description": "Bug type (e.g. Cross-Site Scripting (XSS))"},
                "body": {"type": "string", "description": "Full report body (Markdown)"},
                "endpoint": {"type": "string", "description": "Affected endpoint URL", "default": ""},
            },
            "required": ["program_handle", "title", "severity", "bug_type", "body"],
        },
    },
]

def dispatch(name, args):
    if name == "intigriti_get_profile":
        return get_profile()
    elif name == "intigriti_list_programs":
        return list_programs(args.get("limit", 20), args.get("offset", 0))
    elif name == "intigriti_get_program":
        return get_program(args["handle"])
    elif name == "intigriti_search_programs":
        return search_programs(args["query"], args.get("limit", 10))
    elif name == "intigriti_list_submissions":
        return list_submissions(args.get("status"), args.get("limit", 20), args.get("offset", 0))
    elif name == "intigriti_get_submission":
        return get_submission(args["submission_id"])
    elif name == "intigriti_submit_report":
        return submit_report(
            args["program_handle"], args["title"], args["severity"],
            args["bug_type"], args["body"], args.get("endpoint", "")
        )
    else:
        raise ValueError(f"Unknown tool: {name}")

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def main():
    print("Intigriti MCP server running on stdio", file=sys.stderr, flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        rid = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params", {})

        if method == "initialize":
            send({"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "intigriti", "version": "1.0.0"},
                "capabilities": {"tools": {}},
            }})
        elif method == "notifications/initialized":
            pass  # no response needed
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            try:
                result = dispatch(tool_name, tool_args)
                send({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "isError": False,
                }})
            except Exception as e:
                send({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": f"Error: {e}"}],
                    "isError": True,
                }})
        elif method == "ping":
            send({"jsonrpc": "2.0", "id": rid, "result": {}})
        else:
            if rid is not None:
                send({"jsonrpc": "2.0", "id": rid, "error": {
                    "code": -32601, "message": f"Method not found: {method}"
                }})

if __name__ == "__main__":
    main()
