#!/usr/bin/env python3
"""
attack-lookup.py — MITRE ATT&CK STIX reference tool

Usage:
    python3 scripts/attack-lookup.py T1003.001
    python3 scripts/attack-lookup.py T1003
    python3 scripts/attack-lookup.py --tactic credential-access
    python3 scripts/attack-lookup.py --coverage
    python3 scripts/attack-lookup.py --gaps
    python3 scripts/attack-lookup.py --gaps --tactic lateral-movement
    python3 scripts/attack-lookup.py --update

Requires:
    No external dependencies (stdlib only)
    STIX bundle at data/enterprise-attack.json (download with --update)
"""

import argparse
import glob
import json
import math
import os
import re
import sys
import textwrap
import urllib.request

SKILL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STIX_PATH = os.path.join(SKILL_ROOT, "data", "enterprise-attack.json")
HUNTS_DIR = os.path.join(SKILL_ROOT, "hunts")
STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


# ── STIX loading ─────────────────────────────────────────────────────────────

def load_stix():
    if not os.path.exists(STIX_PATH):
        print(f"ERROR: STIX bundle not found at {STIX_PATH}", file=sys.stderr)
        print("Run:  python3 scripts/attack-lookup.py --update", file=sys.stderr)
        sys.exit(1)
    with open(STIX_PATH, encoding="utf-8") as f:
        return json.load(f)


def get_techniques(bundle):
    """Return {external_id: obj} for active (non-revoked, non-deprecated) techniques."""
    out = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                eid = ref.get("external_id", "")
                if re.match(r"T\d{4}(\.\d{3})?$", eid):
                    out[eid] = obj
    return out


def technique_tactics(technique):
    return [
        p["phase_name"]
        for p in technique.get("kill_chain_phases", [])
        if p.get("kill_chain_name") == "mitre-attack"
    ]


# ── Hunt file parsing ─────────────────────────────────────────────────────────

def _parse_frontmatter(content):
    """Return dict of frontmatter fields from a hunt markdown file."""
    m = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
    if not m:
        return {}
    fm = m.group(1)
    result = {}
    # Inline list:  techniques: [T1003.001, T1078]
    for line in fm.splitlines():
        kv = re.match(r"^(\w[\w_-]*):\s*\[([^\]]*)\]", line)
        if kv:
            items = [x.strip().strip("'\"") for x in kv.group(2).split(",") if x.strip()]
            result[kv.group(1)] = items
            continue
        kv = re.match(r"^(\w[\w_-]*):\s*(.+)", line)
        if kv:
            result[kv.group(1)] = kv.group(2).strip().strip("'\"")
    # Multi-line lists
    current_key = None
    for line in fm.splitlines():
        if re.match(r"^\w[\w_-]*:\s*$", line):
            current_key = line.split(":")[0].strip()
            if current_key not in result:
                result[current_key] = []
            continue
        if current_key and isinstance(result.get(current_key), list):
            item = re.match(r"^\s+-\s+['\"]?(.*?)['\"]?\s*$", line)
            if item:
                result[current_key].append(item.group(1))
            elif line.strip() and not line.startswith(" ") and not line.startswith("\t"):
                current_key = None
    return result


def get_hunted_techniques():
    """Return set of technique IDs present in any hunt frontmatter."""
    covered = set()
    for path in glob.glob(os.path.join(HUNTS_DIR, "H-*.md")):
        try:
            with open(path, encoding="utf-8") as f:
                fm = _parse_frontmatter(f.read())
            for t in fm.get("techniques", []):
                if re.match(r"T\d{4}(\.\d{3})?$", t):
                    covered.add(t)
        except Exception:
            continue
    return covered


# ── Formatters ────────────────────────────────────────────────────────────────

def format_technique(eid, tech, verbose=True):
    name = tech.get("name", "Unknown")
    platforms = tech.get("x_mitre_platforms", [])
    data_sources = tech.get("x_mitre_data_sources", [])
    tactics = technique_tactics(tech)
    is_sub = tech.get("x_mitre_is_subtechnique", False)

    lines = [f"{'Sub-technique' if is_sub else 'Technique'}: {eid} — {name}"]
    lines.append(f"  Tactics:      {', '.join(t.replace('-', ' ').title() for t in tactics)}")
    lines.append(f"  Platforms:    {', '.join(platforms) if platforms else 'N/A'}")
    if data_sources:
        shown = data_sources[:6]
        lines.append(f"  Data Sources: {', '.join(shown)}")
        if len(data_sources) > 6:
            lines.append(f"                (+ {len(data_sources) - 6} more)")

    if verbose:
        desc = (tech.get("description") or "").split("\n\n")[0]
        if desc:
            lines.append("\n  Description:")
            lines.append(textwrap.fill(desc, width=80, initial_indent="  ",
                                       subsequent_indent="  "))
        detection = (tech.get("x_mitre_detection") or "").split("\n\n")[0]
        if detection:
            lines.append("\n  Detection Guidance:")
            lines.append(textwrap.fill(detection, width=80, initial_indent="  ",
                                       subsequent_indent="  "))
    return "\n".join(lines)


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_lookup(args):
    bundle = load_stix()
    techniques = get_techniques(bundle)
    eid = args.technique.upper()

    if eid in techniques:
        print(format_technique(eid, techniques[eid]))
        if "." not in eid:
            subs = {k: v for k, v in techniques.items() if k.startswith(eid + ".")}
            if subs:
                print(f"\n  Sub-techniques ({len(subs)}):")
                for sid, sub in sorted(subs.items()):
                    print(f"    {sid}  {sub.get('name', '')}")
        return

    # Not found — check if it's a valid parent with subs only
    subs = {k: v for k, v in techniques.items() if k.startswith(eid + ".")}
    if subs:
        print(f"  Parent {eid} is revoked/deprecated but has active sub-techniques:")
        for sid, sub in sorted(subs.items()):
            print(f"    {sid}  {sub.get('name', '')}")
    else:
        print(f"Technique '{eid}' not found (revoked, deprecated, or invalid ID).")


def cmd_tactic(args):
    bundle = load_stix()
    techniques = get_techniques(bundle)
    tactic = args.tactic.lower().replace(" ", "-").replace("_", "-")

    parents = {
        k: v for k, v in techniques.items()
        if tactic in technique_tactics(v) and not v.get("x_mitre_is_subtechnique")
    }
    if not parents:
        print(f"No techniques found for tactic '{tactic}'.")
        return

    print(f"Tactic: {tactic.replace('-', ' ').title()}  ({len(parents)} techniques)\n")
    for tid, tech in sorted(parents.items()):
        subs = [k for k in techniques if k.startswith(tid + ".")]
        sub_str = f"  [{len(subs)} sub-techniques]" if subs else ""
        print(f"  {tid:<12}  {tech.get('name', '')}{sub_str}")


def cmd_coverage(args):
    bundle = load_stix()
    techniques = get_techniques(bundle)
    covered = get_hunted_techniques()

    parents = {k: v for k, v in techniques.items() if not v.get("x_mitre_is_subtechnique")}
    total_covered = total_techniques = 0

    print("ATT&CK Enterprise Coverage (parent techniques)\n")
    for tactic in TACTIC_ORDER:
        tactic_techs = {k: v for k, v in parents.items() if tactic in technique_tactics(v)}
        if not tactic_techs:
            continue
        # Covered = parent OR any sub is in covered set
        n_covered = sum(
            1 for k in tactic_techs
            if k in covered or any(s in covered for s in techniques if s.startswith(k + "."))
        )
        n = len(tactic_techs)
        pct = n_covered / n if n else 0
        filled = int(pct * 20)
        bar = "█" * filled + "░" * (20 - filled)
        label = tactic.replace("-", " ").title()
        print(f"  {label:<28} {bar}  {n_covered:>2}/{n:<2}  ({pct:.0%})")
        total_covered += n_covered
        total_techniques += n

    print()
    if total_techniques:
        pct = total_covered / total_techniques
        filled = int(pct * 20)
        bar = "█" * filled + "░" * (20 - filled)
        print(f"  {'TOTAL':<28} {bar}  {total_covered:>2}/{total_techniques}  ({pct:.0%})")

    if not covered:
        print("\n  (No hunt files in hunts/ yet — coverage will populate as hunts complete)")


def cmd_gaps(args):
    bundle = load_stix()
    techniques = get_techniques(bundle)
    covered = get_hunted_techniques()

    tactic_filter = (
        args.tactic.lower().replace(" ", "-").replace("_", "-") if args.tactic else None
    )
    parents = {k: v for k, v in techniques.items() if not v.get("x_mitre_is_subtechnique")}

    gaps = []
    for tid, tech in parents.items():
        tactlist = technique_tactics(tech)
        if tactic_filter and tactic_filter not in tactlist:
            continue
        subs_covered = any(s in covered for s in techniques if s.startswith(tid + "."))
        if tid not in covered and not subs_covered:
            gaps.append((tid, tech, tactlist))

    gaps.sort(key=lambda x: (
        TACTIC_ORDER.index(x[2][0]) if x[2] and x[2][0] in TACTIC_ORDER else 99, x[0]
    ))

    header = "ATT&CK Coverage Gaps"
    if tactic_filter:
        header += f" — {tactic_filter.replace('-', ' ').title()}"
    print(f"{header}  ({len(gaps)} unhunted parent techniques)\n")

    current_tactic = None
    for tid, tech, tactlist in gaps:
        tactic = tactlist[0] if tactlist else "unknown"
        if tactic != current_tactic:
            current_tactic = tactic
            print(f"\n  {tactic.replace('-', ' ').title()}")
        platforms = tech.get("x_mitre_platforms", [])
        plat_str = f"  [{', '.join(platforms[:3])}]" if platforms else ""
        print(f"    {tid:<12}  {tech.get('name', '')}{plat_str}")


def cmd_update(args):
    print(f"Downloading MITRE ATT&CK STIX bundle (~43 MB)...")
    print(f"  URL:    {STIX_URL}")
    print(f"  Target: {STIX_PATH}")
    os.makedirs(os.path.dirname(STIX_PATH), exist_ok=True)

    downloaded = [0]

    def progress(count, block_size, total_size):
        downloaded[0] = count * block_size
        mb = downloaded[0] / 1_000_000
        if total_size > 0:
            pct = min(count * block_size * 100 // total_size, 100)
            print(f"\r  {pct}%  ({mb:.1f} MB)...", end="", flush=True)
        else:
            print(f"\r  {mb:.1f} MB...", end="", flush=True)

    try:
        urllib.request.urlretrieve(STIX_URL, STIX_PATH, progress)
        print()
        with open(STIX_PATH, encoding="utf-8") as f:
            bundle = json.load(f)
        count = len(get_techniques(bundle))
        print(f"  OK — {count} active techniques loaded.")
        print(f"  Saved to: {STIX_PATH}")
    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK STIX reference tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("technique", nargs="?", metavar="TECHNIQUE_ID",
                        help="Technique ID, e.g. T1003.001")
    parser.add_argument("--tactic", metavar="TACTIC",
                        help="List techniques by tactic, or filter --gaps by tactic")
    parser.add_argument("--coverage", action="store_true",
                        help="Show ATT&CK coverage matrix from hunt files")
    parser.add_argument("--gaps", action="store_true",
                        help="Show unhunted techniques (use --tactic to narrow)")
    parser.add_argument("--update", action="store_true",
                        help="Download/refresh STIX bundle from mitre/cti")

    args = parser.parse_args()

    if args.update:
        cmd_update(args)
    elif args.coverage:
        cmd_coverage(args)
    elif args.gaps:
        cmd_gaps(args)
    elif args.technique:
        cmd_lookup(args)
    elif args.tactic:
        cmd_tactic(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
