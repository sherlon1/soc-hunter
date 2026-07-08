#!/usr/bin/env python3
"""
baseline-manager.py — Versioned behavior baseline storage and deviation detection

Usage:
    # Create or refresh a baseline (Option A: raw weekly values)
    python3 scripts/baseline-manager.py establish \\
      --scope service-accounts \\
      --description "Auth events per service account per week" \\
      --data-source "<auth_index>" \\
      --sample-days 30 \\
      --metrics '{"svc_deploy": {"unique_hosts": [3, 4, 2, 3]}}'

    # Create or refresh a baseline (Option B: pre-computed stats)
    python3 scripts/baseline-manager.py establish \\
      --scope service-accounts \\
      --description "Auth events per service account per week" \\
      --data-source "<auth_index>" \\
      --sample-days 30 \\
      --stats '{"svc_deploy": {"unique_hosts": {"mean": 3.0, "stddev": 0.8, "sample_count": 4}}}'

    # Compare current observations against a stored baseline
    python3 scripts/baseline-manager.py compare \\
      --scope service-accounts \\
      --observed '{"svc_deploy": {"unique_hosts": 47}}' \\
      --json

    # List all baselines
    python3 scripts/baseline-manager.py list

    # Show a specific baseline
    python3 scripts/baseline-manager.py show B-0003
    python3 scripts/baseline-manager.py show --scope service-accounts

    # Refresh stats for an existing baseline (preserves B-XXXX ID)
    python3 scripts/baseline-manager.py refresh B-0003 \\
      --sample-days 30 \\
      --metrics '{"svc_deploy": {"unique_hosts": [3, 5, 4, 3]}}'

Requires:
    No external dependencies (stdlib only — math.sqrt for stddev)
"""

import argparse
import datetime
import glob
import json
import math
import os
import re
import sys

SKILL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINES_DIR = os.path.join(SKILL_ROOT, "baselines")

SIGMA_TIERS = [
    (4.0, "SEVERE",      "Escalate — offer /soc-hunter hunt"),
    (3.0, "SIGNIFICANT", "Create I-XXXX investigation"),
    (2.0, "NOTABLE",     "Log and monitor"),
    (0.0, "NORMAL",      "No action"),
]


# ── Math ──────────────────────────────────────────────────────────────────────

def _mean(values):
    return sum(values) / len(values) if values else 0.0


def _stddev(values):
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return math.sqrt(sum((v - m) ** 2 for v in values) / (len(values) - 1))


def _sigma(observed, mean, stddev):
    if stddev == 0:
        return float("inf") if observed != mean else 0.0
    return abs(observed - mean) / stddev


def _tier(sigma):
    for threshold, label, action in SIGMA_TIERS:
        if sigma >= threshold:
            return label, action
    return "NORMAL", "No action"


# ── Storage ───────────────────────────────────────────────────────────────────

def _ensure_baselines_dir():
    os.makedirs(BASELINES_DIR, exist_ok=True)


def _next_baseline_id():
    existing = glob.glob(os.path.join(BASELINES_DIR, "B-*.json"))
    if not existing:
        return "B-0001"
    ids = []
    for p in existing:
        m = re.search(r"B-(\d+)\.json$", p)
        if m:
            ids.append(int(m.group(1)))
    return f"B-{max(ids) + 1:04d}" if ids else "B-0001"


def _load_baseline_file(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _save_baseline(data):
    path = os.path.join(BASELINES_DIR, f"{data['id']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


def _find_baseline(bid=None, scope=None):
    """Return baseline dict or None."""
    if bid:
        path = os.path.join(BASELINES_DIR, f"{bid.upper()}.json")
        return _load_baseline_file(path) if os.path.exists(path) else None
    if scope:
        for path in glob.glob(os.path.join(BASELINES_DIR, "B-*.json")):
            try:
                data = _load_baseline_file(path)
                if data.get("scope") == scope:
                    return data
            except Exception:
                continue
    return None


# ── Establish ─────────────────────────────────────────────────────────────────

def _build_stats_from_raw(metrics_json):
    """Convert {entity: {metric: [v1, v2, ...]}} to {entity: {metric: {mean, stddev, sample_count}}}."""
    out = {}
    raw = json.loads(metrics_json)
    for entity, metric_dict in raw.items():
        out[entity] = {}
        for metric, values in metric_dict.items():
            if not isinstance(values, list):
                raise ValueError(f"Expected list of values for {entity}.{metric}, got {type(values)}")
            floats = [float(v) for v in values]
            out[entity][metric] = {
                "mean": round(_mean(floats), 4),
                "stddev": round(_stddev(floats), 4),
                "sample_count": len(floats),
            }
    return out


def _build_stats_from_precomputed(stats_json):
    """Validate and normalise pre-computed stats JSON."""
    raw = json.loads(stats_json)
    out = {}
    for entity, metric_dict in raw.items():
        out[entity] = {}
        for metric, stat in metric_dict.items():
            required = {"mean", "stddev", "sample_count"}
            missing = required - set(stat.keys())
            if missing:
                raise ValueError(f"{entity}.{metric} missing fields: {missing}")
            out[entity][metric] = {
                "mean": float(stat["mean"]),
                "stddev": float(stat["stddev"]),
                "sample_count": int(stat["sample_count"]),
            }
    return out


def cmd_establish(args):
    _ensure_baselines_dir()

    if args.metrics and args.stats:
        print("ERROR: specify either --metrics (raw) or --stats (pre-computed), not both.",
              file=sys.stderr)
        sys.exit(1)
    if not args.metrics and not args.stats:
        print("ERROR: one of --metrics or --stats is required.", file=sys.stderr)
        sys.exit(1)

    try:
        if args.metrics:
            stats = _build_stats_from_raw(args.metrics)
        else:
            stats = _build_stats_from_precomputed(args.stats)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"ERROR parsing metrics/stats JSON: {e}", file=sys.stderr)
        sys.exit(1)

    if args.sample_days < 14:
        print("WARNING: sample period is less than 14 days — baseline is provisional.")
        print("         Deviations from this baseline are informational only.")

    # Check if scope already exists
    existing = _find_baseline(scope=args.scope)
    if existing:
        bid = existing["id"]
        print(f"Updating existing baseline {bid} (scope: {args.scope})")
    else:
        bid = _next_baseline_id()
        print(f"Creating new baseline {bid} (scope: {args.scope})")

    data = {
        "id": bid,
        "scope": args.scope,
        "description": args.description or "",
        "data_source": args.data_source or "",
        "created": datetime.date.today().isoformat(),
        "sample_days": args.sample_days,
        "provisional": args.sample_days < 14,
        "stats": stats,
    }

    path = _save_baseline(data)
    print(f"Saved: {path}")
    print(f"  Entities:    {len(stats)}")
    print(f"  Sample days: {args.sample_days}")
    if data["provisional"]:
        print(f"  Status:      PROVISIONAL (< 14 day sample)")
    print(f"\nBaseline ID: {bid}")
    print("Add this ID to your hunt or investigation file's 'baselines' field.")


# ── Compare ───────────────────────────────────────────────────────────────────

def cmd_compare(args):
    baseline = _find_baseline(scope=args.scope)
    if not baseline:
        print(f"ERROR: no baseline found for scope '{args.scope}'.", file=sys.stderr)
        print("Run:  python3 scripts/baseline-manager.py list", file=sys.stderr)
        sys.exit(1)

    if baseline.get("provisional"):
        print(f"WARNING: baseline {baseline['id']} is provisional (< 14 day sample).")
        print("         Deviations are informational only.\n")

    try:
        observed = json.loads(args.observed)
    except json.JSONDecodeError as e:
        print(f"ERROR parsing --observed JSON: {e}", file=sys.stderr)
        sys.exit(1)

    results = []
    stats = baseline.get("stats", {})

    for entity, metric_dict in observed.items():
        if not isinstance(metric_dict, dict):
            metric_dict = {"value": metric_dict}
        for metric, obs_value in metric_dict.items():
            obs_value = float(obs_value)
            baseline_metric = stats.get(entity, {}).get(metric)
            if baseline_metric is None:
                results.append({
                    "entity": entity, "metric": metric,
                    "observed": obs_value, "mean": None, "stddev": None,
                    "sigma": None, "tier": "NO_BASELINE", "action": "No baseline data — establish first",
                })
                continue
            mean = baseline_metric["mean"]
            stddev = baseline_metric["stddev"]
            sigma = _sigma(obs_value, mean, stddev)
            tier, action = _tier(sigma)
            results.append({
                "entity": entity, "metric": metric,
                "observed": obs_value,
                "mean": mean, "stddev": stddev,
                "sigma": round(sigma, 2),
                "tier": tier, "action": action,
                "direction": "above" if obs_value > mean else "below",
            })

    if args.json_out:
        out = {
            "baseline_id": baseline["id"],
            "scope": baseline["scope"],
            "provisional": baseline.get("provisional", False),
            "deviations": results,
        }
        print(json.dumps(out, indent=2))
        return

    print(f"Baseline: {baseline['id']}  scope={baseline['scope']}\n")
    for r in sorted(results, key=lambda x: x.get("sigma") or 0, reverse=True):
        sigma_str = f"{r['sigma']:.1f}σ" if r["sigma"] is not None else "n/a"
        print(f"  [{r['tier']:<12}] {r['entity']}.{r['metric']:<30} "
              f"observed={r['observed']}  baseline={r.get('mean','?')}±{r.get('stddev','?')}  "
              f"({sigma_str})")
        if r["tier"] not in ("NORMAL",):
            print(f"             → {r['action']}")


# ── List / Show ───────────────────────────────────────────────────────────────

def cmd_list(args):
    paths = sorted(glob.glob(os.path.join(BASELINES_DIR, "B-*.json")))
    if not paths:
        print(f"No baselines found in {BASELINES_DIR}")
        print("Run 'baseline establish' to create one.")
        return
    print(f"{'ID':<8}  {'Scope':<30}  {'Sample':<8}  {'Created':<12}  Description")
    print("─" * 90)
    for path in paths:
        try:
            d = _load_baseline_file(path)
            prov = " (provisional)" if d.get("provisional") else ""
            print(f"  {d.get('id','?'):<8}  {d.get('scope','?'):<30}  "
                  f"{str(d.get('sample_days','?'))+'d':<8}  "
                  f"{d.get('created','?'):<12}  {d.get('description','')}{prov}")
        except Exception as e:
            print(f"  {os.path.basename(path)}  ERROR: {e}")


def cmd_show(args):
    bid = getattr(args, "baseline_id", None)
    scope = getattr(args, "scope", None)
    baseline = _find_baseline(bid=bid, scope=scope)
    if not baseline:
        ident = bid or f"scope={scope}"
        print(f"ERROR: baseline not found ({ident}).", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(baseline, indent=2))


# ── Refresh ───────────────────────────────────────────────────────────────────

def cmd_refresh(args):
    baseline = _find_baseline(bid=args.baseline_id)
    if not baseline:
        print(f"ERROR: baseline {args.baseline_id} not found.", file=sys.stderr)
        sys.exit(1)

    try:
        if args.metrics:
            stats = _build_stats_from_raw(args.metrics)
        elif args.stats:
            stats = _build_stats_from_precomputed(args.stats)
        else:
            print("ERROR: --metrics or --stats required for refresh.", file=sys.stderr)
            sys.exit(1)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"ERROR parsing JSON: {e}", file=sys.stderr)
        sys.exit(1)

    baseline["stats"] = stats
    baseline["created"] = datetime.date.today().isoformat()
    if args.sample_days:
        baseline["sample_days"] = args.sample_days
        baseline["provisional"] = args.sample_days < 14

    path = _save_baseline(baseline)
    print(f"Refreshed {baseline['id']} ({baseline['scope']}) → {path}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Versioned behavior baseline storage and deviation detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # establish
    p = sub.add_parser("establish", help="Create or update a baseline")
    p.add_argument("--scope", required=True, help="Scope name, e.g. service-accounts")
    p.add_argument("--description", default="")
    p.add_argument("--data-source", default="", dest="data_source")
    p.add_argument("--sample-days", type=int, default=30, dest="sample_days")
    p.add_argument("--metrics", help="JSON: {entity: {metric: [values]}}")
    p.add_argument("--stats", help="JSON: {entity: {metric: {mean, stddev, sample_count}}}")

    # compare
    p = sub.add_parser("compare", help="Sigma-score observations against a baseline")
    p.add_argument("--scope", required=True)
    p.add_argument("--observed", required=True, help="JSON: {entity: {metric: value}}")
    p.add_argument("--json", dest="json_out", action="store_true")

    # list
    sub.add_parser("list", help="List all baselines")

    # show
    p = sub.add_parser("show", help="Show full baseline JSON")
    p.add_argument("baseline_id", nargs="?", metavar="BASELINE_ID")
    p.add_argument("--scope", default=None)

    # refresh
    p = sub.add_parser("refresh", help="Update stats for an existing baseline")
    p.add_argument("baseline_id", metavar="BASELINE_ID")
    p.add_argument("--sample-days", type=int, dest="sample_days")
    p.add_argument("--metrics")
    p.add_argument("--stats")

    args = parser.parse_args()
    dispatch = {
        "establish": cmd_establish,
        "compare": cmd_compare,
        "list": cmd_list,
        "show": cmd_show,
        "refresh": cmd_refresh,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
