#!/usr/bin/env python3
"""
hunt-similar.py — Hunt duplicate detection using TF-IDF cosine similarity

Usage:
    python3 scripts/hunt-similar.py "OAuth token abuse in SaaS"
    python3 scripts/hunt-similar.py --hunt H-0015
    python3 scripts/hunt-similar.py "credential dumping" --threshold 0.3
    python3 scripts/hunt-similar.py "supply chain npm" --json

Requires:
    pip install scikit-learn
"""

import argparse
import glob
import json
import os
import re
import sys

SKILL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HUNTS_DIR = os.path.join(SKILL_ROOT, "hunts")

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    import numpy as np
except ImportError:
    print("ERROR: scikit-learn is required.", file=sys.stderr)
    print("Run:  pip install scikit-learn", file=sys.stderr)
    sys.exit(1)


# ── Hunt loading ──────────────────────────────────────────────────────────────

def _parse_frontmatter_text(content):
    """Return (frontmatter_dict, body_text)."""
    m = re.match(r"^---\n(.*?)\n---\n?(.*)", content, re.DOTALL)
    if not m:
        return {}, content
    fm_raw, body = m.group(1), m.group(2)
    fm = {}
    for line in fm_raw.splitlines():
        kv = re.match(r"^(\w[\w_-]*):\s*['\"]?(.*?)['\"]?\s*$", line)
        if kv:
            fm[kv.group(1)] = kv.group(2)
    # Inline list for techniques
    tech_m = re.search(r"^techniques:\s*\[([^\]]*)\]", fm_raw, re.MULTILINE)
    if tech_m:
        fm["techniques"] = [x.strip().strip("'\"") for x in tech_m.group(1).split(",")]
    return fm, body


def load_hunts():
    """Return list of {id, title, path, techniques, text} dicts."""
    hunts = []
    for path in sorted(glob.glob(os.path.join(HUNTS_DIR, "H-*.md"))):
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()
            fm, body = _parse_frontmatter_text(content)
            hunt_id = fm.get("hunt_id") or os.path.splitext(os.path.basename(path))[0]
            title = fm.get("title", "")
            techniques = fm.get("techniques", [])
            if isinstance(techniques, str):
                techniques = [t.strip() for t in techniques.split(",")]
            # Build searchable text: title + techniques + section headers + first 500 chars of body
            section_headers = " ".join(re.findall(r"^#{1,3}\s+(.+)", body, re.MULTILINE))
            text = f"{title} {' '.join(techniques)} {section_headers} {body[:500]}"
            hunts.append({
                "id": hunt_id,
                "title": title,
                "path": path,
                "techniques": techniques,
                "text": text,
            })
        except Exception:
            continue
    return hunts


# ── Similarity ────────────────────────────────────────────────────────────────

def find_similar(query_text, hunts, top_n=10, threshold=0.25):
    """Return list of {id, title, score, techniques} sorted by score desc."""
    if not hunts:
        return []

    corpus = [h["text"] for h in hunts]
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        stop_words="english",
        min_df=1,
        max_features=10000,
    )
    tfidf_matrix = vectorizer.fit_transform(corpus)
    query_vec = vectorizer.transform([query_text])
    scores = cosine_similarity(query_vec, tfidf_matrix)[0]

    results = []
    for i, score in enumerate(scores):
        if score >= threshold:
            results.append({
                "id": hunts[i]["id"],
                "title": hunts[i]["title"],
                "score": float(score),
                "techniques": hunts[i]["techniques"],
                "path": hunts[i]["path"],
            })
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:top_n]


# ── Output ────────────────────────────────────────────────────────────────────

SCORE_LABELS = [
    (0.50, "LIKELY DUPLICATE"),
    (0.30, "RELATED"),
    (0.00, "WEAK MATCH"),
]


def score_label(score):
    for threshold, label in SCORE_LABELS:
        if score >= threshold:
            return label
    return "WEAK MATCH"


def print_results(results, threshold):
    if not results:
        print(f"No hunts found above similarity threshold {threshold:.2f}.")
        return
    for r in results:
        label = score_label(r["score"])
        techs = ", ".join(r["techniques"]) if r["techniques"] else "—"
        print(f"  [{r['score']:.2f}] {r['id']}  {label}")
        print(f"         Title:      {r['title']}")
        print(f"         Techniques: {techs}")
        print()


# ── Commands ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Find similar hunts using TF-IDF cosine similarity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("query", nargs="?", metavar="QUERY",
                        help="Free-text query to match against existing hunts")
    parser.add_argument("--hunt", metavar="HUNT_ID",
                        help="Find hunts similar to an existing hunt (e.g. H-0015)")
    parser.add_argument("--threshold", type=float, default=0.25, metavar="N",
                        help="Minimum similarity score to show (default: 0.25)")
    parser.add_argument("--top", type=int, default=10,
                        help="Maximum results to show (default: 10)")
    parser.add_argument("--json", dest="json_out", action="store_true",
                        help="Output as JSON array")
    args = parser.parse_args()

    if not args.query and not args.hunt:
        parser.print_help()
        sys.exit(1)

    hunts = load_hunts()
    if not hunts:
        print(f"No hunt files found in {HUNTS_DIR}")
        print("Run some hunts first: /soc-hunter hunt <topic>")
        sys.exit(0)

    # Resolve query text
    if args.hunt:
        hunt_id = args.hunt.upper()
        source = next((h for h in hunts if h["id"].upper() == hunt_id), None)
        if not source:
            print(f"Hunt {hunt_id} not found in {HUNTS_DIR}", file=sys.stderr)
            sys.exit(1)
        query_text = source["text"]
        # Exclude the source hunt itself from results
        search_corpus = [h for h in hunts if h["id"].upper() != hunt_id]
        label = f"Hunts similar to {hunt_id}: {source['title']}"
    else:
        query_text = args.query
        search_corpus = hunts
        label = f"Hunts similar to: \"{args.query}\""

    print(f"{label}\n")
    results = find_similar(query_text, search_corpus, top_n=args.top,
                           threshold=args.threshold)

    if args.json_out:
        print(json.dumps(results, indent=2))
    else:
        print_results(results, args.threshold)
        if results:
            print(f"  Score guide: >=0.50 LIKELY DUPLICATE  0.30–0.49 RELATED  "
                  f"0.25–0.29 WEAK MATCH")


if __name__ == "__main__":
    main()
