#!/usr/bin/env python3
"""
os_query.py — Unified knowledge retrieval over skills (RAG) + payloads.

Usage:
  python tools/os_query.py "GraphQL batching IDOR"
  python tools/os_query.py "SSRF metadata" --top 5
  python tools/os_query.py "oauth redirect" --payloads-only
  python tools/os_query.py "sqli union" --layer code-audit
  python tools/os_query.py "prototype pollution" --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tools.rag_chunk import (  # noqa: E402
    CHUNKS_FILE,
    PAYLOADS_DIR,
    _load_chunks,
    _load_memory_vuln_boost,
    _tfidf_search,
    _tokenize,
)

MAX_PAYLOAD_FILE_BYTES = 512_000
MAX_PAYLOAD_HITS = 8
MAX_LINE_PREVIEW = 120


def _search_payload_files(query: str, top: int = MAX_PAYLOAD_HITS) -> list[dict]:
    q_tokens = set(_tokenize(query))
    if not q_tokens:
        return []

    hits: list[tuple[float, dict]] = []
    if not PAYLOADS_DIR.is_dir():
        return []

    for path in sorted(PAYLOADS_DIR.rglob("*.txt")):
        rel = path.relative_to(_REPO).as_posix()
        name_tokens = set(_tokenize(rel.replace("/", " ").replace(".", " ")))
        name_score = len(q_tokens & name_tokens) * 2.0

        try:
            if path.stat().st_size > MAX_PAYLOAD_FILE_BYTES:
                if name_score > 0:
                    hits.append((name_score, {
                        "path": rel,
                        "match": "filename",
                        "preview": f"({path.stat().st_size:,} bytes — open file directly)",
                    }))
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        content_score = 0.0
        best_line = ""
        for line in lines[:5000]:
            line_lower = line.lower()
            matched = sum(1 for t in q_tokens if t in line_lower)
            if matched > content_score:
                content_score = float(matched)
                best_line = line.strip()[:MAX_LINE_PREVIEW]

        total = name_score + content_score
        if total > 0:
            hits.append((total, {
                "path": rel,
                "match": "content" if content_score else "filename",
                "preview": best_line or "(filename match)",
            }))

    hits.sort(key=lambda x: x[0], reverse=True)
    return [h for _, h in hits[:top]]


def _filter_chunks(chunks: list[dict], layer: str | None) -> list[dict]:
    if not layer:
        return chunks
    layer = layer.lower()
    return [c for c in chunks if c.get("skill_layer", "web-hunting") == layer]


def run_query(
    query: str,
    top: int = 5,
    layer: str | None = None,
    target_type: str | None = None,
    skills: bool = True,
    payloads: bool = True,
) -> dict:
    result: dict = {"query": query, "skills": [], "payloads": [], "memory_boost": {}}

    if skills:
        if not CHUNKS_FILE.is_file():
            result["skills_error"] = "RAG index missing — run: python tools/rag_chunk.py --build"
        else:
            result["memory_boost"] = {
                k: round(v, 2)
                for k, v in sorted(
                    _load_memory_vuln_boost(query, target_type=target_type).items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:8]
            }
            chunks = _filter_chunks(_load_chunks(), layer)
            for score, ch in _tfidf_search(query, chunks, top=top, target_type=target_type):
                result["skills"].append({
                    "score": round(score, 2),
                    "source": ch["source_file"],
                    "section": ch["section"],
                    "layer": ch.get("skill_layer", "web-hunting"),
                    "tags": ch.get("vuln_type", []),
                    "preview": ch["text"][:400].replace("\n", " "),
                })

    if payloads:
        result["payloads"] = _search_payload_files(query, top=top)

    return result


def _print_human(data: dict, top: int) -> None:
    print(f"\nQuery: {data['query']}\n{'=' * 60}")

    if "skills_error" in data:
        print(f"\n[SKILLS] ERROR: {data['skills_error']}")
    elif data["skills"]:
        if data.get("memory_boost"):
            boosts = ", ".join(f"{k}={v}" for k, v in data["memory_boost"].items())
            print(f"\n[MEMORY BOOST] {boosts}")
        print("\n[SKILLS — RAG]")
        for i, hit in enumerate(data["skills"][:top], 1):
            tags = ", ".join(hit["tags"]) if hit["tags"] else "general"
            print(f"\n  [{i}] score={hit['score']} | {hit['source']} :: {hit['section']}")
            print(f"      layer: {hit['layer']} | tags: {tags}")
            preview = hit["preview"]
            if len(preview) >= 400:
                preview += "..."
            print(f"      {preview}")

    if data["payloads"]:
        print("\n[PAYLOADS]")
        for i, hit in enumerate(data["payloads"][:top], 1):
            print(f"\n  [{i}] {hit['path']} ({hit['match']})")
            print(f"      {hit['preview']}")

    if not data.get("skills") and not data.get("payloads") and "skills_error" not in data:
        print("\nNo matches.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Unified OS query — skills RAG + payloads")
    parser.add_argument("query", help="Natural language query")
    parser.add_argument("--top", type=int, default=5, help="Max results per section (default 5)")
    parser.add_argument("--layer", type=str, default="", help="Filter RAG by skill_layer (e.g. code-audit)")
    parser.add_argument("--target-type", type=str, default="", help="Boost with hunt-memory for target archetype (saas, fintech)")
    parser.add_argument("--skills-only", action="store_true", help="Search skills/RAG only")
    parser.add_argument("--payloads-only", action="store_true", help="Search payloads only")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.skills_only and args.payloads_only:
        print("Choose --skills-only OR --payloads-only, not both.", file=sys.stderr)
        return 2

    layer = args.layer or None
    target_type = args.target_type or None
    data = run_query(
        args.query,
        top=args.top,
        layer=layer,
        target_type=target_type,
        skills=not args.payloads_only,
        payloads=not args.skills_only,
    )

    if args.json:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        _print_human(data, args.top)

    has_results = bool(data.get("skills") or data.get("payloads"))
    return 0 if has_results or "skills_error" not in data else 1


if __name__ == "__main__":
    raise SystemExit(main())
