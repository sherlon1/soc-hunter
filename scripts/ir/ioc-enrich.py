#!/usr/bin/env python3
"""
ioc-enrich.py — IOC enrichment from multiple threat intelligence sources

Usage:
    python3 scripts/ir/ioc-enrich.py 8.8.8.8
    python3 scripts/ir/ioc-enrich.py evil.example.com
    python3 scripts/ir/ioc-enrich.py d41d8cd98f00b204e9800998ecf8427e
    python3 scripts/ir/ioc-enrich.py --batch iocs.txt
    python3 scripts/ir/ioc-enrich.py 8.8.8.8 --json

Supported IOC types:
    IPv4/IPv6 addresses, domains, MD5/SHA1/SHA256 hashes, URLs

Configuration:
    Set API keys via environment variables or your secret manager (see CONFIG.md):
        VT_API_KEY        — VirusTotal (https://www.virustotal.com/gui/my-apikey)
        GREYNOISE_API_KEY — GreyNoise  (https://viz.greynoise.io/account/api-key)
        OTX_API_KEY       — AlienVault OTX (https://otx.alienvault.com/api)

    To disable a source: set its env var to empty or add it to DISABLED_SOURCES below.

Output format:
    JSON envelope:
    {
      "ioc": "...", "type": "...",
      "summary": { "verdict": "malicious|suspicious|benign|unknown",
                   "confidence": "high|medium|low",
                   "consensus_risk": "critical|high|medium|low|none" },
      "sources": { "virustotal": {...}, "greynoise": {...}, "otx": {...} },
      "errors": []
    }

Requires:
    pip install requests
"""

import argparse
import json
import os
import re
import sys

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("ERROR: requests is required.  Run:  pip install requests", file=sys.stderr)
    sys.exit(1)

TIMEOUT = 10

# ── Source enable/disable ─────────────────────────────────────────────────────
# Add a source name here to disable it regardless of API key presence
DISABLED_SOURCES: list[str] = []

# ── IOC type detection ────────────────────────────────────────────────────────

def detect_type(ioc):
    ioc = ioc.strip()
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ioc):
        return "ip"
    if re.match(r"^[0-9a-fA-F]{32}$", ioc):
        return "md5"
    if re.match(r"^[0-9a-fA-F]{40}$", ioc):
        return "sha1"
    if re.match(r"^[0-9a-fA-F]{64}$", ioc):
        return "sha256"
    if re.match(r"^https?://", ioc):
        return "url"
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", ioc):
        return "domain"
    return "unknown"


# ── VirusTotal ────────────────────────────────────────────────────────────────

VT_BASE = "https://www.virustotal.com/api/v3"

_VT_ENDPOINTS = {
    "ip":     "/ip_addresses/{ioc}",
    "domain": "/domains/{ioc}",
    "md5":    "/files/{ioc}",
    "sha1":   "/files/{ioc}",
    "sha256": "/files/{ioc}",
    "url":    "/urls/{ioc}",  # URL requires base64 encoding
}


def enrich_virustotal(ioc, ioc_type, api_key):
    if ioc_type not in _VT_ENDPOINTS:
        return {"error": f"unsupported IOC type for VirusTotal: {ioc_type}"}

    endpoint = _VT_ENDPOINTS[ioc_type].format(ioc=ioc)
    if ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        endpoint = f"/urls/{url_id}"

    try:
        resp = requests.get(
            f"{VT_BASE}{endpoint}",
            headers={"x-apikey": api_key},
            timeout=TIMEOUT,
        )
        if resp.status_code == 404:
            return {"found": False}
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "reputation": data.get("reputation"),
            "last_analysis_date": data.get("last_analysis_date"),
            "tags": data.get("tags", [])[:10],
        }
    except requests.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ── GreyNoise ─────────────────────────────────────────────────────────────────

GN_BASE = "https://api.greynoise.io/v3"


def enrich_greynoise(ioc, ioc_type, api_key):
    if ioc_type != "ip":
        return {"skipped": "GreyNoise only supports IP addresses"}
    try:
        resp = requests.get(
            f"{GN_BASE}/community/{ioc}",
            headers={"key": api_key},
            timeout=TIMEOUT,
        )
        if resp.status_code == 404:
            return {"found": False, "noise": False, "riot": False}
        resp.raise_for_status()
        data = resp.json()
        return {
            "found": True,
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification"),
            "name": data.get("name"),
            "last_seen": data.get("last_seen"),
            "message": data.get("message"),
        }
    except requests.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ── AlienVault OTX ────────────────────────────────────────────────────────────

OTX_BASE = "https://otx.alienvault.com/api/v1"

_OTX_INDICATOR_TYPES = {
    "ip":     "IPv4",
    "domain": "domain",
    "md5":    "file",
    "sha1":   "file",
    "sha256": "file",
    "url":    "url",
}

_OTX_SECTIONS = {
    "ip":     "general",
    "domain": "general",
    "md5":    "general",
    "sha1":   "general",
    "sha256": "general",
    "url":    "general",
}


def enrich_otx(ioc, ioc_type, api_key):
    if ioc_type not in _OTX_INDICATOR_TYPES:
        return {"error": f"unsupported IOC type for OTX: {ioc_type}"}
    otype = _OTX_INDICATOR_TYPES[ioc_type]
    try:
        resp = requests.get(
            f"{OTX_BASE}/indicators/{otype}/{ioc}/general",
            headers={"X-OTX-API-KEY": api_key},
            timeout=TIMEOUT,
        )
        if resp.status_code == 404:
            return {"found": False, "pulse_count": 0}
        resp.raise_for_status()
        data = resp.json()
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        return {
            "found": True,
            "pulse_count": pulse_info.get("count", 0),
            "pulses": [
                {"name": p.get("name"), "tags": p.get("tags", [])[:5]}
                for p in pulses[:5]
            ],
            "reputation": data.get("reputation"),
        }
    except requests.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ── Verdict synthesis ─────────────────────────────────────────────────────────

def synthesize(ioc_type, sources):
    malicious_signals = 0
    suspicious_signals = 0
    total_signals = 0

    vt = sources.get("virustotal", {})
    if vt.get("found") and not vt.get("error"):
        total_signals += 1
        if vt.get("malicious", 0) >= 3:
            malicious_signals += 1
        elif vt.get("malicious", 0) >= 1 or vt.get("suspicious", 0) >= 3:
            suspicious_signals += 1

    gn = sources.get("greynoise", {})
    if gn.get("found") and not gn.get("error") and not gn.get("skipped"):
        total_signals += 1
        if gn.get("classification") in ("malicious",):
            malicious_signals += 1
        elif gn.get("noise") and not gn.get("riot"):
            suspicious_signals += 1

    otx = sources.get("otx", {})
    if not otx.get("error") and not otx.get("skipped"):
        total_signals += 1
        if otx.get("pulse_count", 0) >= 5:
            malicious_signals += 1
        elif otx.get("pulse_count", 0) >= 1:
            suspicious_signals += 1

    if total_signals == 0:
        return {"verdict": "unknown", "confidence": "low", "consensus_risk": "none"}

    if malicious_signals >= 2:
        return {"verdict": "malicious", "confidence": "high", "consensus_risk": "critical"}
    if malicious_signals == 1 and suspicious_signals >= 1:
        return {"verdict": "malicious", "confidence": "medium", "consensus_risk": "high"}
    if malicious_signals == 1:
        return {"verdict": "suspicious", "confidence": "medium", "consensus_risk": "high"}
    if suspicious_signals >= 2:
        return {"verdict": "suspicious", "confidence": "medium", "consensus_risk": "medium"}
    if suspicious_signals == 1:
        return {"verdict": "suspicious", "confidence": "low", "consensus_risk": "low"}
    return {"verdict": "benign", "confidence": "medium", "consensus_risk": "none"}


# ── Core enrichment ───────────────────────────────────────────────────────────

def enrich(ioc):
    ioc = ioc.strip()
    ioc_type = detect_type(ioc)
    result = {"ioc": ioc, "type": ioc_type, "summary": {}, "sources": {}, "errors": []}

    if ioc_type == "unknown":
        result["errors"].append("unrecognised IOC format — cannot classify as IP/domain/hash/URL")
        return result

    vt_key = os.environ.get("VT_API_KEY", "")
    gn_key = os.environ.get("GREYNOISE_API_KEY", "")
    otx_key = os.environ.get("OTX_API_KEY", "")

    if vt_key and "virustotal" not in DISABLED_SOURCES:
        result["sources"]["virustotal"] = enrich_virustotal(ioc, ioc_type, vt_key)
    else:
        result["sources"]["virustotal"] = {"skipped": "VT_API_KEY not set"}

    if gn_key and "greynoise" not in DISABLED_SOURCES:
        result["sources"]["greynoise"] = enrich_greynoise(ioc, ioc_type, gn_key)
    else:
        result["sources"]["greynoise"] = {"skipped": "GREYNOISE_API_KEY not set"}

    if otx_key and "otx" not in DISABLED_SOURCES:
        result["sources"]["otx"] = enrich_otx(ioc, ioc_type, otx_key)
    else:
        result["sources"]["otx"] = {"skipped": "OTX_API_KEY not set"}

    result["summary"] = synthesize(ioc_type, result["sources"])
    return result


def print_result(r, json_out=False):
    if json_out:
        print(json.dumps(r, indent=2))
        return

    s = r.get("summary", {})
    print(f"IOC:      {r['ioc']}")
    print(f"Type:     {r['type']}")
    print(f"Verdict:  {s.get('verdict','?').upper()}  "
          f"(confidence: {s.get('confidence','?')},  "
          f"risk: {s.get('consensus_risk','?').upper()})")
    print()
    for src, data in r.get("sources", {}).items():
        if data.get("skipped"):
            print(f"  {src:<14} skipped ({data['skipped']})")
        elif data.get("error"):
            print(f"  {src:<14} ERROR: {data['error']}")
        elif not data.get("found"):
            print(f"  {src:<14} not found")
        else:
            parts = []
            if "malicious" in data:
                parts.append(f"malicious={data['malicious']}/{data.get('total_engines','?')}")
            if "classification" in data:
                parts.append(f"classification={data['classification']}")
            if "noise" in data:
                parts.append(f"noise={data['noise']}  riot={data.get('riot',False)}")
            if "pulse_count" in data:
                parts.append(f"pulses={data['pulse_count']}")
            print(f"  {src:<14} {' | '.join(parts)}")
    if r.get("errors"):
        for e in r["errors"]:
            print(f"  ! {e}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="IOC enrichment from VirusTotal, GreyNoise, and OTX",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("ioc", nargs="?", metavar="IOC",
                        help="IOC to enrich (IP, domain, hash, URL)")
    parser.add_argument("--batch", metavar="FILE",
                        help="File with one IOC per line")
    parser.add_argument("--json", dest="json_out", action="store_true",
                        help="Output as JSON")
    args = parser.parse_args()

    if not args.ioc and not args.batch:
        parser.print_help()
        sys.exit(1)

    if args.batch:
        with open(args.batch, encoding="utf-8") as f:
            iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        results = [enrich(ioc) for ioc in iocs]
        if args.json_out:
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                print_result(r)
                print()
    else:
        r = enrich(args.ioc)
        print_result(r, json_out=args.json_out)


if __name__ == "__main__":
    main()
