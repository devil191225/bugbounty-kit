#!/usr/bin/env python3
"""
sync_payloads.py — Pull SOTA payload wordlists from upstream GitHub repos.

Usage:
  python tools/sync_payloads.py
  python tools/sync_payloads.py --dry-run
  python tools/sync_payloads.py --external   # Escape GraphQL wordlists

Sources:
  - swisskyrepo/PayloadsAllTheThings (MIT) — Intruder wordlists
  - Escape-Technologies/graphql-wordlist — field/type/mutation wordlists
  - Curated files (graphql templates, prototype-pollution/*, file-upload/*, csrf/*) are manual — not overwritten
  - cmdi/generic.txt may be quarantined by Windows Defender after sync; use bypass-polyglot.txt or add exclusion
"""

from __future__ import annotations

import argparse
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PAYLOADS = REPO / "payloads"
BASE = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"

# PAT Intruder files -> local paths (verified paths)
ESCAPE_BASE = "https://raw.githubusercontent.com/Escape-Technologies/graphql-wordlist/main"

# Escape-Technologies/graphql-wordlist (10k tiers — RAG-friendly size)
ESCAPE_FILES: dict[str, str] = {
    "graphql/wordlist-query-fields-10k.txt": "wordlists/10k/queryFieldWordlist-10k.txt",
    "graphql/wordlist-types-10k.txt": "wordlists/10k/typeWordlist-10k.txt",
    "graphql/wordlist-mutations-10k.txt": "wordlists/10k/mutationFieldWordlist-10k.txt",
    "graphql/wordlist-arguments-10k.txt": "wordlists/10k/argumentWordlist-10k.txt",
}

PAT_FILES: dict[str, str] = {
    "sqli/auth-bypass.txt": "SQL Injection/Intruder/Auth_Bypass.txt",
    "sqli/auth-bypass2.txt": "SQL Injection/Intruder/Auth_Bypass2.txt",
    "sqli/error-based.txt": "SQL Injection/Intruder/Generic_ErrorBased.txt",
    "sqli/time-based.txt": "SQL Injection/Intruder/Generic_TimeBased.txt",
    "sqli/polyglots.txt": "SQL Injection/Intruder/SQLi_Polyglots.txt",
    "sqli/union-select.txt": "SQL Injection/Intruder/Generic_UnionSelect.txt",
    "sqli/mysql-blind-where.txt": "SQL Injection/Intruder/payloads-sql-blind-MySQL-WHERE",
    "sqli/mssql-blind-where.txt": "SQL Injection/Intruder/payloads-sql-blind-MSSQL-WHERE",
    "sqli/oracle-fuzzdb.txt": "SQL Injection/Intruder/FUZZDB_Oracle.txt",
    "sqli/postgres-enum.txt": "SQL Injection/Intruder/FUZZDB_Postgres_Enumeration.txt",
    "nosql/mongodb.txt": "NoSQL Injection/Intruder/MongoDB.txt",
    "nosql/nosql-generic.txt": "NoSQL Injection/Intruder/NoSQL.txt",
    "lfi/directory-traversal.txt": "Directory Traversal/Intruder/directory_traversal.txt",
    "lfi/deep-traversal.txt": "Directory Traversal/Intruder/deep_traversal.txt",
    "lfi/exotic-encoding.txt": "Directory Traversal/Intruder/traversals-8-deep-exotic-encoding.txt",
    "cmdi/unix.txt": "Command Injection/Intruder/command-execution-unix.txt",
    "cmdi/generic.txt": "Command Injection/Intruder/command_exec.txt",
    "ldap/ldap-fuzz.txt": "LDAP Injection/Intruder/LDAP_FUZZ.txt",
    "ldap/ldap-small.txt": "LDAP Injection/Intruder/LDAP_FUZZ_SMALL.txt",
    "open-redirect/payloads.txt": "Open Redirect/Intruder/Open-Redirect-payloads.txt",
    "open-redirect/wordlist.txt": "Open Redirect/Intruder/open_redirect_wordlist.txt",
    "ssti/ssti-fuzz.txt": "Server Side Template Injection/Intruder/ssti.fuzz",
    "xxe/xxe-fuzz.txt": "XXE Injection/Intruders/XXE_Fuzzing.txt",
    "xxe/xml-attacks.txt": "XXE Injection/Intruders/xml-attacks.txt",
    "deserialization/java.txt": "Insecure Deserialization/Java.md",
    "deserialization/php.txt": "Insecure Deserialization/PHP.md",
    "deserialization/node.txt": "Insecure Deserialization/Node.md",
    "deserialization/python.txt": "Insecure Deserialization/Python.md",
    "deserialization/dotnet.txt": "Insecure Deserialization/DotNET.md",
    "deserialization/ruby.txt": "Insecure Deserialization/Ruby.md",
}


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    return ctx


def download_url(url: str, dest: Path, header: str, dry_run: bool = False) -> bool:
    if dry_run:
        print(f"DRY  {dest.relative_to(REPO)} <- {url}")
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "bugbounty-kit-sync/1.0"})
    try:
        data = urllib.request.urlopen(req, context=_ssl_ctx(), timeout=120).read()
    except urllib.error.HTTPError as e:
        print(f"FAIL {dest.name}: HTTP {e.code}", file=sys.stderr)
        return False
    dest.write_bytes(header.encode("utf-8") + data)
    print(f"OK   {dest.relative_to(REPO)} ({len(data)} bytes)")
    return True


def download_pat(src: str, dest: Path, dry_run: bool = False) -> bool:
    url = f"{BASE}/{src.replace(' ', '%20')}"
    header = f"# Source: PayloadsAllTheThings/{src}\n# Sync: authorized testing only\n\n"
    return download_url(url, dest, header, dry_run=dry_run)


def download_escape(src: str, dest: Path, dry_run: bool = False) -> bool:
    url = f"{ESCAPE_BASE}/{src}"
    header = f"# Source: Escape-Technologies/graphql-wordlist/{src}\n# Sync: authorized testing only\n\n"
    return download_url(url, dest, header, dry_run=dry_run)


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync payload wordlists from upstream repos")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--external", action="store_true", help="Also sync Escape GraphQL wordlists")
    args = parser.parse_args()

    ok = fail = 0
    for rel, src in PAT_FILES.items():
        dest = PAYLOADS / rel.replace("/", os.sep)
        if download_pat(src, dest, dry_run=args.dry_run):
            ok += 1
        else:
            fail += 1

    if args.external:
        for rel, src in ESCAPE_FILES.items():
            dest = PAYLOADS / rel.replace("/", os.sep)
            if download_escape(src, dest, dry_run=args.dry_run):
                ok += 1
            else:
                fail += 1

    print(f"\nDone: {ok} ok, {fail} fail")
    if fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
