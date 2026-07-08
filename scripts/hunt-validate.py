#!/usr/bin/env python3
"""
hunt-validate.py — Hunt file frontmatter schema validation

Usage:
    python3 scripts/hunt-validate.py              # Validate all hunts
    python3 scripts/hunt-validate.py H-0019       # Validate one hunt
    python3 scripts/hunt-validate.py H-0019 --fix # Auto-fix simple issues
    python3 scripts/hunt-validate.py --stats       # Aggregate program stats
    python3 scripts/hunt-validate.py --fix         # Auto-fix all hunts

Requires:
    pip install pyyaml   (only needed for --fix; validate-only works without it)
"""

import argparse
import datetime
import glob
import json
import os
import re
import sys

SKILL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HUNTS_DIR = os.path.join(SKILL_ROOT, "hunts")

VALID_STATUSES = {"planning", "in-progress", "completed", "complete", "closed"}
REQUIRED_FIELDS = [
    "hunt_id", "title", "status", "date", "hunter", "platform",
    "tactics", "techniques", "findings_count", "true_positives",
    "false_positives", "inconclusive",
]
INT_FIELDS = {"findings_count", "true_positives", "false_positives", "inconclusive"}
LIST_FIELDS = {
    "tactics", "techniques", "data_sources", "related_hunts", "baselines", "tags",
}


# ── Frontmatter parsing ───────────────────────────────────────────────────────

def _extract_raw_frontmatter(content):
    """Return (fm_text, rest) or (None, content)."""
    m = re.match(r"^---\n(.*?)\n---\n?", content, re.DOTALL)
    if m:
        return m.group(1), content[m.end():]
    return None, content


def _parse_value(raw):
    """Parse a YAML scalar value from a string."""
    raw = raw.strip()
    if raw in ("true", "True"):
        return True
    if raw in ("false", "False"):
        return False
    if raw.lstrip("-").isdigit():
        return int(raw)
    try:
        return float(raw)
    except ValueError:
        pass
    return raw.strip("'\"")


def parse_frontmatter(content):
    """Return dict of fields parsed from YAML frontmatter."""
    fm_raw, _ = _extract_raw_frontmatter(content)
    if fm_raw is None:
        return None, "no frontmatter block (---) found"

    result = {}
    lines = fm_raw.splitlines()
    current_key = None
    current_list = None

    for line in lines:
        # Inline list:  techniques: [T1003, T1078]
        m = re.match(r"^(\w[\w_-]*):\s*\[([^\]]*)\]\s*$", line)
        if m:
            current_key = None
            items = [x.strip().strip("'\"") for x in m.group(2).split(",") if x.strip()]
            result[m.group(1)] = items
            continue

        # Key: value
        m = re.match(r"^(\w[\w_-]*):\s*(.+)$", line)
        if m:
            current_key = m.group(1)
            current_list = None
            result[current_key] = _parse_value(m.group(2))
            continue

        # Key: (start of block)
        m = re.match(r"^(\w[\w_-]*):\s*$", line)
        if m:
            current_key = m.group(1)
            result[current_key] = []
            current_list = current_key
            continue

        # List item
        if current_list is not None:
            m = re.match(r"^\s+-\s+(.+)$", line)
            if m:
                result[current_list].append(_parse_value(m.group(1)))
                continue
            # Nested dict key under a list — treat as sub-key, skip for now
            if re.match(r"^\s+\w[\w_-]*:", line):
                continue
            # Non-indented non-empty line ends the list
            if line.strip():
                current_list = None

    return result, None


# ── Validation ────────────────────────────────────────────────────────────────

def validate(hunt_id, content):
    """Return list of error strings."""
    errors = []
    fm, parse_err = parse_frontmatter(content)
    if fm is None:
        return [f"parse error: {parse_err}"]

    # Required fields present
    for field in REQUIRED_FIELDS:
        if field not in fm:
            errors.append(f"missing required field: {field}")

    # hunt_id format and match
    if "hunt_id" in fm:
        if not re.match(r"H-\d{4}$", str(fm["hunt_id"])):
            errors.append(f"hunt_id '{fm['hunt_id']}' must be H-XXXX (4 digits)")
        if str(fm["hunt_id"]) != hunt_id:
            errors.append(f"hunt_id '{fm['hunt_id']}' does not match filename '{hunt_id}'")

    # title non-empty, not placeholder
    if "title" in fm:
        t = str(fm["title"]).strip()
        if not t or t in ("[Hunt Title]", "Hunt Title"):
            errors.append("title is empty or still a placeholder")

    # status valid
    if "status" in fm:
        if str(fm["status"]).lower() not in VALID_STATUSES:
            errors.append(f"status '{fm['status']}' must be one of: {', '.join(sorted(VALID_STATUSES))}")

    # date format
    if "date" in fm:
        if not re.match(r"\d{4}-\d{2}-\d{2}", str(fm["date"])):
            errors.append(f"date '{fm['date']}' must be YYYY-MM-DD")
        elif str(fm["date"]) in ("YYYY-MM-DD",):
            errors.append("date is still a placeholder")

    # hunter non-empty
    if "hunter" in fm:
        if not str(fm["hunter"]).strip() or str(fm["hunter"]) in ("[Your Name]", "Your Name"):
            errors.append("hunter is empty or still a placeholder")

    # integer fields >= 0
    for field in INT_FIELDS:
        if field in fm:
            val = fm[field]
            if not isinstance(val, int) or val < 0:
                errors.append(f"{field} must be a non-negative integer (got: {val!r})")

    # list fields
    for field in LIST_FIELDS:
        if field in fm and not isinstance(fm[field], list):
            errors.append(f"{field} must be a list")

    # technique ID format
    techs = fm.get("techniques", [])
    if isinstance(techs, list):
        for t in techs:
            if t and not re.match(r"T\d{4}(\.\d{3})?$", str(t)):
                errors.append(f"technique '{t}' is not a valid ATT&CK ID (expected T####[.###])")

    # findings_count consistency
    if all(k in fm for k in ("findings_count", "true_positives", "false_positives", "inconclusive")):
        try:
            total = int(fm["true_positives"]) + int(fm["false_positives"]) + int(fm["inconclusive"])
            declared = int(fm["findings_count"])
            if declared > 0 and total != declared:
                errors.append(
                    f"findings_count ({declared}) != tp+fp+inconclusive ({total})"
                )
        except (ValueError, TypeError):
            pass

    return errors


# ── Auto-fix ──────────────────────────────────────────────────────────────────

_YAML_AVAILABLE = False
try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    pass


def _build_default_fm(hunt_id):
    return {
        "hunt_id": hunt_id,
        "title": "",
        "status": "planning",
        "date": datetime.date.today().isoformat(),
        "hunter": "",
        "platform": "Multi-Platform",
        "tactics": [],
        "techniques": [],
        "data_sources": {"siem": [], "edr": [], "vm_mcp": []},
        "related_hunts": [],
        "baselines": [],
        "findings_count": 0,
        "true_positives": 0,
        "false_positives": 0,
        "inconclusive": 0,
        "tags": [],
    }


def auto_fix(hunt_id, content):
    """Return (new_content, list_of_changes). Requires PyYAML."""
    if not _YAML_AVAILABLE:
        return content, ["--fix requires PyYAML: pip install pyyaml"]

    fm_raw, body = _extract_raw_frontmatter(content)
    if fm_raw is None:
        return content, ["cannot fix: no frontmatter block found"]

    try:
        fm = yaml.safe_load(fm_raw) or {}
    except yaml.YAMLError as e:
        return content, [f"cannot fix: YAML parse error: {e}"]

    defaults = _build_default_fm(hunt_id)
    changes = []

    for field, default in defaults.items():
        if field not in fm:
            fm[field] = default
            changes.append(f"added missing field '{field}' = {default!r}")

    # Fix hunt_id mismatch
    if str(fm.get("hunt_id", "")) != hunt_id:
        fm["hunt_id"] = hunt_id
        changes.append(f"corrected hunt_id to {hunt_id}")

    # Fix integer fields
    for field in INT_FIELDS:
        try:
            fm[field] = int(fm[field])
        except (ValueError, TypeError):
            fm[field] = 0
            changes.append(f"reset {field} to 0 (was invalid)")

    # Normalise list fields to actual lists
    for field in LIST_FIELDS:
        if field in fm and fm[field] is None:
            fm[field] = []
            changes.append(f"set {field} to empty list (was null)")

    new_fm = yaml.dump(fm, default_flow_style=False, allow_unicode=True, sort_keys=True)
    new_content = f"---\n{new_fm}---\n{body}"
    return new_content, changes


# ── Commands ──────────────────────────────────────────────────────────────────

def validate_file(path, fix=False):
    hunt_id = os.path.splitext(os.path.basename(path))[0]
    with open(path, encoding="utf-8") as f:
        content = f.read()

    errors = validate(hunt_id, content)

    if fix and errors:
        new_content, changes = auto_fix(hunt_id, content)
        if changes and new_content != content:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new_content)
            print(f"  {hunt_id}  FIXED ({len(changes)} changes)")
            for c in changes:
                print(f"    + {c}")
            # Re-validate
            errors = validate(hunt_id, new_content)
            if errors:
                print(f"    Remaining issues:")
                for e in errors:
                    print(f"    ! {e}")
        elif not changes:
            print(f"  {hunt_id}  nothing to auto-fix")
        return len(errors) == 0

    if errors:
        print(f"  {hunt_id}  FAIL ({len(errors)} issue{'s' if len(errors) != 1 else ''})")
        for e in errors:
            print(f"    ! {e}")
        return False
    else:
        print(f"  {hunt_id}  OK")
        return True


def cmd_stats():
    paths = sorted(glob.glob(os.path.join(HUNTS_DIR, "H-*.md")))
    if not paths:
        print(f"No hunt files found in {HUNTS_DIR}")
        return

    total = len(paths)
    statuses = {}
    all_tp = all_fp = all_inc = all_findings = 0
    techniques_all = set()
    errors_total = 0

    for path in paths:
        hunt_id = os.path.splitext(os.path.basename(path))[0]
        with open(path, encoding="utf-8") as f:
            content = f.read()
        fm, _ = parse_frontmatter(content)
        if fm is None:
            errors_total += 1
            continue
        status = str(fm.get("status", "unknown")).lower()
        statuses[status] = statuses.get(status, 0) + 1
        try:
            all_tp += int(fm.get("true_positives", 0))
            all_fp += int(fm.get("false_positives", 0))
            all_inc += int(fm.get("inconclusive", 0))
            all_findings += int(fm.get("findings_count", 0))
        except (ValueError, TypeError):
            pass
        techs = fm.get("techniques", [])
        if isinstance(techs, list):
            techniques_all.update(t for t in techs if t)

    errs = []
    valid = 0
    for path in paths:
        hunt_id = os.path.splitext(os.path.basename(path))[0]
        with open(path, encoding="utf-8") as f:
            content = f.read()
        e = validate(hunt_id, content)
        if not e:
            valid += 1
        else:
            errs.append((hunt_id, e))

    print(f"Hunt Program Statistics")
    print(f"  Total hunts:        {total}")
    for status in sorted(statuses):
        print(f"  {status:<20}  {statuses[status]}")
    print(f"  ATT&CK techniques:  {len(techniques_all)} unique")
    print(f"  Total findings:     {all_findings}  "
          f"(TP: {all_tp}  FP: {all_fp}  Inconclusive: {all_inc})")
    print(f"  Valid schema:       {valid}/{total}")
    if errs:
        print(f"\n  Schema errors in {len(errs)} file(s):")
        for hunt_id, e in errs[:5]:
            print(f"    {hunt_id}: {e[0]}" + (f" (+{len(e)-1} more)" if len(e) > 1 else ""))
        if len(errs) > 5:
            print(f"    ... and {len(errs)-5} more")


def main():
    parser = argparse.ArgumentParser(
        description="Validate hunt file frontmatter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("hunt_id", nargs="?", metavar="HUNT_ID",
                        help="Hunt ID to validate (e.g. H-0019). Omit for all.")
    parser.add_argument("--fix", action="store_true",
                        help="Auto-fix simple issues (requires pip install pyyaml)")
    parser.add_argument("--stats", action="store_true",
                        help="Show aggregate hunt program statistics")
    args = parser.parse_args()

    if args.stats:
        cmd_stats()
        return

    if args.hunt_id:
        hunt_id = args.hunt_id.upper()
        path = os.path.join(HUNTS_DIR, f"{hunt_id}.md")
        if not os.path.exists(path):
            print(f"Hunt file not found: {path}", file=sys.stderr)
            sys.exit(1)
        ok = validate_file(path, fix=args.fix)
        sys.exit(0 if ok else 1)

    # All hunts
    paths = sorted(glob.glob(os.path.join(HUNTS_DIR, "H-*.md")))
    if not paths:
        print(f"No hunt files found in {HUNTS_DIR}")
        sys.exit(0)

    passed = failed = 0
    for path in paths:
        ok = validate_file(path, fix=args.fix)
        if ok:
            passed += 1
        else:
            failed += 1

    print(f"\n  {passed} passed  {failed} failed  (total: {passed + failed})")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
