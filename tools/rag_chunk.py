#!/usr/bin/env python3
"""
rag_chunk.py — Chunk skills/ markdown for RAG retrieval.

Usage:
  python tools/rag_chunk.py --build
  python tools/rag_chunk.py --query "SSRF to AWS metadata chain"
  python tools/rag_chunk.py --query "SAML XSW" --top 5
  python tools/rag_chunk.py --stats
"""

import argparse
import json
import math
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
SKILLS_DIR = _REPO / "skills"
PAYLOADS_DIR = _REPO / "payloads"
INDEX_DIR = _REPO / "rag"
CHUNKS_FILE = INDEX_DIR / "chunks.jsonl"
META_FILE = INDEX_DIR / "index_meta.json"
PATTERNS_FILE = _REPO / "hunt-memory" / "patterns.jsonl"

# Boost RAG scores using hunt-memory outcomes (see PROJECT-NOTES ADR-010)
OUTCOME_BOOST = {
    "high_impact": 4.0,
    "valid": 3.0,
    "duplicate": 0.5,
    "informational": 0.0,
    "no_effect": -2.0,
}

# Tag inference from filename and headings (basename keys)
FILE_TAGS = {
    "bug-chains.md": ["chain", "exploit"],
    "saml-attacks.md": ["saml", "sso", "auth"],
    "ci-cd-attacks.md": ["cicd", "supply-chain"],
    "oauth-oidc-advanced.md": ["oauth", "oidc", "auth"],
    "portswigger-injection.md": ["sqli", "xss", "xxe", "ssrf", "injection", "cmdi", "upload"],
    "prototype-pollution.md": ["prototype-pollution", "pp", "nodejs"],
    "cloud-attacks.md": ["cloud", "aws", "ssrf"],
    "kubernetes-security.md": ["kubernetes", "container"],
    "graphql-advanced.md": ["graphql", "api"],
}

# Nested skill packages (Trail of Bits + future code-audit vision)
NESTED_SKILL_DIRS = {
    "sharp-edges": {"skill_layer": "code-audit", "tags": ["sharp-edges", "footgun", "api-design"]},
    "codeql": {"skill_layer": "code-audit", "tags": ["codeql", "sast", "static-analysis"]},
    "variant-analysis": {"skill_layer": "code-audit", "tags": ["variant-analysis", "semgrep"]},
    "semgrep-rule-creator": {"skill_layer": "code-audit", "tags": ["semgrep", "rules"]},
    "constant-time-analysis": {"skill_layer": "code-audit", "tags": ["crypto", "timing"]},
    "insecure-defaults": {"skill_layer": "code-audit", "tags": ["defaults", "misconfiguration"]},
    "agentic-actions-auditor": {"skill_layer": "code-audit", "tags": ["agentic", "ci", "supply-chain"]},
    "burpsuite-project-parser": {"skill_layer": "tooling", "tags": ["burp", "parser"]},
    "sarif-parsing": {"skill_layer": "code-audit", "tags": ["sarif", "findings"]},
    "firebase-apk-scanner": {"skill_layer": "mobile-audit", "tags": ["firebase", "mobile"]},
}

VULN_KEYWORDS = {
    "ssrf": ["ssrf", "server-side request"],
    "sqli": ["sql injection", "sqli", "union select"],
    "xss": ["cross-site scripting", "xss", "stored xss", "reflected xss"],
    "idor": ["idor", "insecure direct object", "bola"],
    "oauth": ["oauth", "oidc", "redirect_uri", "authorization code"],
    "saml": ["saml", "xsw", "xml signature wrapping"],
    "cicd": ["github actions", "ci/cd", "pipeline", "workflow injection"],
    "chain": ["chain", "chained", "bridge"],
    "kubernetes": ["kubernetes", "k8s", "kubectl", "etcd"],
    "graphql": ["graphql", "introspection", "batching"],
    "prototype-pollution": ["prototype pollution", "__proto__", "prototype-pollution"],
    "ssti": ["template injection", "ssti", "jinja", "freemarker"],
    "deserialization": ["deserialization", "pickle", "ysoserial", "unserialize"],
    "code-audit": ["static analysis", "codeql", "semgrep", "variant analysis", "sharp edge"],
}


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9_\-/]+", text.lower())


def _infer_vuln_types(text: str) -> list[str]:
    lower = text.lower()
    found = []
    for tag, keywords in VULN_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            found.append(tag)
    return found or ["general"]


def _split_markdown(content: str, source_file: str) -> list[dict]:
    """Split on ## and ### headers; keep chunks 200-2000 chars where possible."""
    chunks = []
    lines = content.splitlines()
    current_heading = "Overview"
    current_section = ""
    current_lines: list[str] = []

    def flush():
        nonlocal current_lines, current_section
        body = "\n".join(current_lines).strip()
        if not body or len(body) < 80:
            current_lines = []
            return
        section_id = re.sub(r"[^a-z0-9]+", "-", current_section.lower()).strip("-") or "overview"
        chunks.append({
            "id": f"{source_file}::{section_id}",
            "source_file": source_file,
            "section": current_section,
            "heading_level": current_heading,
            "text": body,
            "char_count": len(body),
        })
        current_lines = []

    for line in lines:
        if line.startswith("## ") and not line.startswith("### "):
            flush()
            current_heading = "##"
            current_section = line[3:].strip()
            current_lines = [line]
        elif line.startswith("### "):
            flush()
            current_heading = "###"
            current_section = line[4:].strip()
            current_lines = [line]
        else:
            current_lines.append(line)

    flush()

    # Merge tiny adjacent chunks from same file
    merged = []
    for ch in chunks:
        if merged and ch["char_count"] < 200 and merged[-1]["source_file"] == ch["source_file"]:
            prev = merged[-1]
            if prev["char_count"] + ch["char_count"] < 2500:
                prev["text"] += "\n\n" + ch["text"]
                prev["char_count"] = len(prev["text"])
                prev["section"] += " | " + ch["section"]
                continue
        merged.append(ch)

    return merged


def _skill_layer_and_tags(source_file: str) -> tuple[str, list[str]]:
    """Return skill_layer + extra tags from path (top-level vs nested ToB packages)."""
    parts = source_file.replace("\\", "/").split("/")
    if len(parts) >= 2 and parts[0] == "skills":
        pkg = parts[1]
        meta = NESTED_SKILL_DIRS.get(pkg)
        if meta:
            return meta["skill_layer"], list(meta["tags"])
    if len(parts) >= 3 and parts[0] == "skills":
        pkg = parts[1]
        meta = NESTED_SKILL_DIRS.get(pkg)
        if meta:
            return meta["skill_layer"], list(meta["tags"])
    return "web-hunting", []


def _enrich_chunk(chunk: dict) -> dict:
    source = chunk["source_file"]
    basename = source.split("/")[-1] if "/" in source else source
    text = chunk["text"]
    base_tags = FILE_TAGS.get(basename, [])
    skill_layer, nested_tags = _skill_layer_and_tags(source)
    vuln_types = _infer_vuln_types(text)
    platform = ["mobile"] if skill_layer == "mobile-audit" else (
        ["code"] if skill_layer == "code-audit" else ["web"]
    )
    return {
        **chunk,
        "vuln_type": sorted(set(vuln_types + base_tags + nested_tags)),
        "skill_layer": skill_layer,
        "platform": platform,
        "indexed_at": datetime.now(timezone.utc).isoformat(),
    }


def _collect_skill_markdown() -> list[tuple[str, Path]]:
    """Top-level skills/*.md plus nested SKILL.md, METHODOLOGY.md, references/, resources/, workflows/."""
    collected: list[tuple[str, Path]] = []
    seen: set[str] = set()

    def add(rel: str, path: Path) -> None:
        key = rel.replace("\\", "/")
        if key in seen or not path.is_file():
            return
        if path.suffix.lower() not in {".md", ".yaml"}:
            return
        if path.suffix.lower() == ".yaml" and path.name != "openai.yaml":
            return
        seen.add(key)
        collected.append((key, path))

    if not SKILLS_DIR.is_dir():
        return collected

    for p in sorted(SKILLS_DIR.glob("*.md")):
        add(p.name, p)

    nested_patterns = [
        "**/SKILL.md",
        "**/METHODOLOGY.md",
        "**/README.md",
        "**/references/**/*.md",
        "**/resources/**/*.md",
        "**/workflows/**/*.md",
    ]
    for pattern in nested_patterns:
        for p in sorted(SKILLS_DIR.glob(pattern)):
            if p.parent == SKILLS_DIR:
                continue
            rel = str(p.relative_to(_REPO)).replace("\\", "/")
            add(rel, p)

    return collected


def _collect_sources() -> list[tuple[str, Path]]:
    sources = list(_collect_skill_markdown())
    if PAYLOADS_DIR.is_dir():
        for p in sorted(PAYLOADS_DIR.rglob("*.txt")):
            rel = str(p.relative_to(_REPO)).replace("\\", "/")
            sources.append((rel, p))
    return sources


def build_index() -> int:
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    all_chunks = []

    for name, path in _collect_sources():
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"WARN: skip {name}: {e}", file=sys.stderr)
            continue

        if name.endswith(".txt"):
            # Payload files: one chunk per file
            if content.strip():
                all_chunks.append(_enrich_chunk({
                    "id": f"{name}::payloads",
                    "source_file": name,
                    "section": "Payloads",
                    "heading_level": "file",
                    "text": content.strip(),
                    "char_count": len(content.strip()),
                }))
        elif name.endswith(".yaml"):
            if content.strip():
                all_chunks.append(_enrich_chunk({
                    "id": f"{name}::agent",
                    "source_file": name,
                    "section": "AgentConfig",
                    "heading_level": "file",
                    "text": content.strip(),
                    "char_count": len(content.strip()),
                }))
        else:
            for ch in _split_markdown(content, name):
                all_chunks.append(_enrich_chunk(ch))

    with CHUNKS_FILE.open("w", encoding="utf-8") as f:
        for ch in all_chunks:
            f.write(json.dumps(ch, ensure_ascii=False) + "\n")

    meta = {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "chunk_count": len(all_chunks),
        "source_files": len(_collect_sources()),
        "skills_dir": str(SKILLS_DIR),
        "payloads_dir": str(PAYLOADS_DIR),
    }
    META_FILE.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Built {len(all_chunks)} chunks from {meta['source_files']} sources -> {CHUNKS_FILE}")
    return len(all_chunks)


def _load_chunks() -> list[dict]:
    if not CHUNKS_FILE.exists():
        print("Index not found. Run: python tools/rag_chunk.py --build", file=sys.stderr)
        sys.exit(1)
    chunks = []
    with CHUNKS_FILE.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                chunks.append(json.loads(line))
    return chunks


def _load_memory_vuln_boost(query: str, target_type: str | None = None) -> dict[str, float]:
    """Aggregate per-vuln_class boost from hunt-memory patterns.jsonl."""
    if not PATTERNS_FILE.is_file():
        return {}

    q_tokens = set(_tokenize(query))
    boosts: Counter = Counter()

    try:
        lines = PATTERNS_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            p = json.loads(line)
        except json.JSONDecodeError:
            continue

        if target_type and p.get("target_type") not in (target_type, None):
            continue

        vc = (p.get("vuln_class") or "").lower().replace("-", "_")
        if not vc:
            continue

        outcome = p.get("outcome", "no_effect")
        weight = OUTCOME_BOOST.get(outcome, 0.0)
        if weight == 0.0 and outcome not in OUTCOME_BOOST:
            continue

        # Live patterns count more; CTF-only techniques skipped on live-weighted queries
        env = p.get("environment", "live")
        if env == "ctf" and p.get("safe_for_live") is False:
            weight *= 0.25

        technique = (p.get("technique") or "").lower()
        signals = " ".join(p.get("signals") or []).lower()
        text_blob = f"{vc} {technique} {signals}"
        blob_tokens = set(_tokenize(text_blob))

        relevance = 1.0
        if q_tokens:
            overlap = len(q_tokens & blob_tokens)
            if overlap:
                relevance += overlap * 0.5
            elif target_type is None:
                relevance *= 0.3

        boosts[vc] += weight * relevance
        # Also boost normalized tag variants (oauth_oidc → oauth)
        for part in vc.split("_"):
            if len(part) > 2:
                boosts[part] += weight * relevance * 0.5

    return {k: v for k, v in boosts.items() if v != 0.0}


def _memory_boost_for_chunk(chunk: dict, memory_boost: dict[str, float]) -> float:
    if not memory_boost:
        return 0.0
    extra = 0.0
    vuln_types = [t.lower() for t in chunk.get("vuln_type", [])]
    source = chunk.get("source_file", "").lower()
    section = chunk.get("section", "").lower()
    for tag, boost in memory_boost.items():
        tag_norm = tag.replace("-", "_")
        if any(tag_norm in vt or vt in tag_norm for vt in vuln_types):
            extra += boost
        if tag_norm in source or tag_norm in section:
            extra += boost * 0.5
    return extra


def _tfidf_search(
    query: str,
    chunks: list[dict],
    top: int = 5,
    target_type: str | None = None,
) -> list[tuple[float, dict]]:
    q_tokens = _tokenize(query)
    if not q_tokens:
        return []

    memory_boost = _load_memory_vuln_boost(query, target_type=target_type)

    doc_freq: Counter = Counter()
    doc_tokens = []
    for ch in chunks:
        tokens = _tokenize(ch["text"] + " " + ch.get("section", "") + " " + ch.get("source_file", ""))
        doc_tokens.append(tokens)
        doc_freq.update(set(tokens))

    n_docs = len(chunks)
    scores = []
    for i, tokens in enumerate(doc_tokens):
        tf = Counter(tokens)
        score = 0.0
        for qt in q_tokens:
            if qt in tf:
                idf = math.log((n_docs + 1) / (doc_freq[qt] + 1)) + 1
                score += (1 + math.log(1 + tf[qt])) * idf
        # Boost vuln_type / skill_layer tag matches
        vuln_types = chunks[i].get("vuln_type", [])
        skill_layer = chunks[i].get("skill_layer", "")
        for qt in q_tokens:
            if qt in vuln_types:
                score += 3.0
            if skill_layer and qt in skill_layer.replace("-", " "):
                score += 2.0
        score += _memory_boost_for_chunk(chunks[i], memory_boost)
        if score > 0:
            scores.append((score, chunks[i]))

    scores.sort(key=lambda x: x[0], reverse=True)
    return scores[:top]


def query_index(query: str, top: int = 5, target_type: str | None = None) -> None:
    chunks = _load_chunks()
    memory_boost = _load_memory_vuln_boost(query, target_type=target_type)
    results = _tfidf_search(query, chunks, top=top, target_type=target_type)
    if not results:
        print("No matches.")
        return
    print(f"\nQuery: {query}\n{'='*60}")
    if memory_boost:
        top_boosts = sorted(memory_boost.items(), key=lambda x: x[1], reverse=True)[:5]
        print("Memory boost (top vuln classes):", ", ".join(f"{k}={v:.1f}" for k, v in top_boosts))
    for rank, (score, ch) in enumerate(results, 1):
        preview = ch["text"][:400].replace("\n", " ")
        if len(ch["text"]) > 400:
            preview += "..."
        print(f"\n[{rank}] score={score:.2f} | {ch['source_file']} :: {ch['section']}")
        print(f"    layer: {ch.get('skill_layer', 'web-hunting')} | tags: {', '.join(ch.get('vuln_type', []))}")
        print(f"    {preview}")


def show_stats() -> None:
    if META_FILE.exists():
        print(json.dumps(json.loads(META_FILE.read_text()), indent=2))
    if CHUNKS_FILE.exists():
        chunks = _load_chunks()
        by_file: Counter = Counter(c["source_file"] for c in chunks)
        print(f"\nChunks per file (top 15):")
        for name, count in by_file.most_common(15):
            print(f"  {count:4d}  {name}")
        print(f"\nTotal chunks: {len(chunks)}")


def main():
    parser = argparse.ArgumentParser(description="RAG chunk builder for skills/ knowledge base")
    parser.add_argument("--build", action="store_true", help="Build/rebuild chunk index")
    parser.add_argument("--query", type=str, help="Search index with natural language query")
    parser.add_argument("--target-type", type=str, default="", help="Boost RAG with hunt-memory weights (e.g. fintech, saas)")
    parser.add_argument("--top", type=int, default=5, help="Number of results (default 5)")
    parser.add_argument("--stats", action="store_true", help="Show index statistics")
    args = parser.parse_args()

    if args.build:
        build_index()
    elif args.query:
        tt = args.target_type or None
        query_index(args.query, top=args.top, target_type=tt)
    elif args.stats:
        show_stats()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
