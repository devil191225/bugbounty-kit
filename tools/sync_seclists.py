#!/usr/bin/env python3
"""
sync_seclists.py — Pull selected wordlists from danielmiessler/SecLists.

Usage:
  python tools/sync_seclists.py
  python tools/sync_seclists.py --dry-run

Note: wordlists/sensitive-files.txt is curated locally and not overwritten.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORDLISTS = REPO / "wordlists"
BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"

# Verified SecLists paths -> local filenames
SECLISTS_FILES: dict[str, str] = {
    "wordlists/common.txt": "Discovery/Web-Content/common.txt",
    "wordlists/params.txt": "Discovery/Web-Content/burp-parameter-names.txt",
    "wordlists/api-endpoints.txt": "Discovery/Web-Content/api/api-endpoints.txt",
    "wordlists/raft-medium-dirs.txt": "Discovery/Web-Content/raft-medium-directories.txt",
}

# Import shared download helper from sync_payloads
sys.path.insert(0, str(REPO))
from tools.sync_payloads import download_url  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync wordlists from SecLists")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    ok = fail = 0
    for rel, src in SECLISTS_FILES.items():
        dest = REPO / rel.replace("/", os.sep)
        url = f"{BASE}/{src.replace(' ', '%20')}"
        header = f"# Source: SecLists/{src}\n# Sync: authorized testing only\n\n"
        if download_url(url, dest, header, dry_run=args.dry_run):
            ok += 1
        else:
            fail += 1

    print(f"\nDone: {ok} ok, {fail} fail")
    print("Note: wordlists/sensitive-files.txt is curated — not synced.")
    if fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
