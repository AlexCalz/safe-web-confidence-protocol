#!/usr/bin/env python3
"""Score a URL using reputation signals before browsing."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def load_json(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    return json.loads(Path(path).read_text())


def load_rules(path: str | None) -> set[str]:
    if not path:
        return set()
    lines = Path(path).read_text().splitlines()
    return {
        line.strip().lower()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    }


def api_json(url: str, *, headers: dict[str, str] | None = None, data: bytes | None = None) -> dict[str, Any]:
    request = urllib.request.Request(url, headers=headers or {}, data=data)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_virustotal(target_url: str) -> dict[str, Any] | None:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return None
    encoded = base64.urlsafe_b64encode(target_url.encode("utf-8")).decode("ascii").rstrip("=")
    return api_json(
        f"https://www.virustotal.com/api/v3/urls/{encoded}",
        headers={"x-apikey": api_key},
    )


def fetch_urlscan(target_url: str) -> dict[str, Any] | None:
    api_key = os.getenv("URLSCAN_API_KEY")
    if not api_key:
        return None
    query = urllib.parse.quote(f'page.url:"{target_url}"', safe="")
    return api_json(
        f"https://urlscan.io/api/v1/search/?q={query}&size=1",
        headers={"API-Key": api_key},
    )


def fetch_gsb(target_url: str) -> dict[str, Any] | None:
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not api_key:
        return None
    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={urllib.parse.quote(api_key, safe='')}"
    )
    payload = {
        "client": {"clientId": "safe-web-confidence-protocol", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": target_url}],
        },
    }
    return api_json(
        endpoint,
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload).encode("utf-8"),
    )


def vt_stats(vt_data: dict[str, Any] | None) -> tuple[int, int, int]:
    stats = (
        ((vt_data or {}).get("data") or {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 0
    return malicious, suspicious, total


def vt_ratio(vt_data: dict[str, Any] | None) -> float:
    malicious, _, total = vt_stats(vt_data)
    return malicious / total if total else 0.0


def url_host(target_url: str) -> str:
    return urllib.parse.urlparse(target_url).hostname or ""


def matches_rule(host: str, rules: set[str]) -> str | None:
    normalized = host.lower().rstrip(".")
    for rule in sorted(rules, key=len, reverse=True):
        candidate = rule.lstrip(".")
        if normalized == candidate or normalized.endswith(f".{candidate}"):
            return rule
    return None


def looks_suspicious_host(host: str) -> bool:
    if host.startswith("xn--"):
        return True
    if any(ch.isdigit() for ch in host) and host.replace(".", "").isdigit():
        return True
    return False


def has_login_theme(target_url: str) -> bool:
    path = urllib.parse.urlparse(target_url).path.lower()
    return any(token in path for token in ("login", "signin", "verify", "auth", "account"))


def score_url(
    target_url: str,
    *,
    vt_data: dict[str, Any] | None,
    urlscan_data: dict[str, Any] | None,
    gsb_data: dict[str, Any] | None,
    openphish_data: dict[str, Any] | None,
    otx_data: dict[str, Any] | None,
    allowlist_domain: str | None = None,
    allow_rules: set[str] | None = None,
    block_rules: set[str] | None = None,
) -> dict[str, Any]:
    host = url_host(target_url)
    allow_rules = allow_rules or set()
    block_rules = block_rules or set()

    matched_block = matches_rule(host, block_rules)
    if matched_block:
        return {
            "url": target_url,
            "score": 0,
            "verdict": "block",
            "reasons": [f"Host matched blocklist rule: {matched_block}."],
            "missing_sources": [],
            "signals": {"allowlist_match": None, "blocklist_match": matched_block},
        }

    matched_allow = matches_rule(host, allow_rules)
    if matched_allow:
        return {
            "url": target_url,
            "score": 100,
            "verdict": "allow",
            "reasons": [f"Host matched allowlist rule: {matched_allow}."],
            "missing_sources": [],
            "signals": {"allowlist_match": matched_allow, "blocklist_match": None},
        }

    score = 60
    reasons: list[str] = []
    overrides: list[str] = []

    vt_malicious, vt_suspicious, vt_total = vt_stats(vt_data)
    malicious_ratio = vt_ratio(vt_data)

    if malicious_ratio >= 0.20:
        score -= 45
        reasons.append(f"VirusTotal malicious ratio is high ({vt_malicious}/{vt_total}).")
        overrides.append("vt_high_malicious")
    elif malicious_ratio >= 0.05:
        score -= 30
        reasons.append(f"VirusTotal reports material malicious detections ({vt_malicious}/{vt_total}).")

    suspicious_ratio = (vt_suspicious / vt_total) if vt_total else 0.0
    if suspicious_ratio >= 0.10:
        score -= 15
        reasons.append(f"VirusTotal suspicious ratio is elevated ({vt_suspicious}/{vt_total}).")

    if vt_total and vt_malicious == 0 and vt_suspicious == 0 and vt_total >= 10:
        score += 15
        reasons.append("VirusTotal shows no malicious or suspicious detections across a broad scan set.")

    matches = (gsb_data or {}).get("matches", [])
    if matches:
        score -= 40
        reasons.append("Google Safe Browsing returned at least one threat match.")
        overrides.append("gsb_match")

    if openphish_data:
        score -= 35
        reasons.append("OpenPhish reported the URL or domain.")
        overrides.append("openphish_hit")

    results = (urlscan_data or {}).get("results", [])
    if results:
        top = results[0]
        verdicts = (((top.get("verdicts") or {}).get("overall")) or {})
        if verdicts.get("malicious") or verdicts.get("score", 0) >= 70:
            score -= 30
            reasons.append("urlscan indicates a malicious or highly suspicious result.")
        page = top.get("page") or {}
        target_host = url_host(target_url)
        final_host = urllib.parse.urlparse(page.get("url", "")).hostname or ""
        if final_host and target_host and final_host != target_host:
            score -= 20
            reasons.append(f"urlscan shows a redirect to a different host ({final_host}).")
        if final_host and final_host == target_host and not verdicts.get("malicious"):
            score += 10
            reasons.append("urlscan has prior benign context for the same final host.")

    if otx_data:
        pulse_count = len((otx_data.get("pulse_info") or {}).get("pulses", []))
        if pulse_count:
            score -= 15
            reasons.append(f"AlienVault OTX returned {pulse_count} pulse hit(s).")

    if looks_suspicious_host(host):
        score -= 10
        reasons.append("Host structure looks suspicious (punycode or IP-style host).")

    if has_login_theme(target_url):
        score -= 10
        reasons.append("Login or verification path increases phishing risk.")

    if allowlist_domain and host == allowlist_domain:
        score += 20
        reasons.append("Host matches an explicit allowlist domain.")

    missing_sources = []
    for name, payload in (
        ("virustotal", vt_data),
        ("urlscan", urlscan_data),
        ("google_safe_browsing", gsb_data),
    ):
        if payload is None:
            missing_sources.append(name)

    score = max(0, min(100, score))
    verdict = "allow" if score >= 80 else "sandbox-only" if score >= 50 else "block"

    strong_negative_count = sum(
        1
        for item in ("vt_high_malicious", "gsb_match", "openphish_hit")
        if item in overrides
    )
    if "gsb_match" in overrides or "openphish_hit" in overrides:
        verdict = "sandbox-only" if verdict == "allow" else verdict
    if "vt_high_malicious" in overrides and verdict == "allow":
        verdict = "sandbox-only"
    if strong_negative_count >= 2:
        verdict = "block"
    if vt_data is None and urlscan_data is None and gsb_data is None and openphish_data is None and otx_data is None:
        verdict = "sandbox-only"
        reasons.append("No source data was available; defaulting to sandbox-only.")

    return {
        "url": target_url,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "missing_sources": missing_sources,
        "signals": {
            "virustotal": {"malicious": vt_malicious, "suspicious": vt_suspicious, "total": vt_total},
            "google_safe_browsing_matches": len(matches),
            "urlscan_results": len(results),
            "openphish_hit": bool(openphish_data),
            "otx_hit": bool(otx_data),
            "allowlist_match": matched_allow,
            "blocklist_match": matched_block,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a URL confidence score before browsing.")
    parser.add_argument("--url", required=True, help="Candidate URL to assess.")
    parser.add_argument("--fetch", action="store_true", help="Query supported APIs using environment variables.")
    parser.add_argument("--vt-json", help="Path to stored VirusTotal JSON.")
    parser.add_argument("--urlscan-json", help="Path to stored urlscan JSON.")
    parser.add_argument("--gsb-json", help="Path to stored Google Safe Browsing JSON.")
    parser.add_argument("--openphish-json", help="Path to stored OpenPhish JSON.")
    parser.add_argument("--otx-json", help="Path to stored AlienVault OTX JSON.")
    parser.add_argument("--allowlist-domain", help="Optional trusted domain to boost when it matches the host.")
    parser.add_argument("--allowlist-file", help="Path to newline-separated host or domain allowlist rules.")
    parser.add_argument("--blocklist-file", help="Path to newline-separated host or domain blocklist rules.")
    args = parser.parse_args()

    vt_data = load_json(args.vt_json)
    urlscan_data = load_json(args.urlscan_json)
    gsb_data = load_json(args.gsb_json)
    openphish_data = load_json(args.openphish_json)
    otx_data = load_json(args.otx_json)
    allow_rules = load_rules(args.allowlist_file)
    block_rules = load_rules(args.blocklist_file)

    if args.fetch:
        try:
            vt_data = vt_data or fetch_virustotal(args.url)
            urlscan_data = urlscan_data or fetch_urlscan(args.url)
            gsb_data = gsb_data or fetch_gsb(args.url)
        except urllib.error.URLError as exc:
            print(json.dumps({"error": f"API fetch failed: {exc}"}))
            return 2

    result = score_url(
        args.url,
        vt_data=vt_data,
        urlscan_data=urlscan_data,
        gsb_data=gsb_data,
        openphish_data=openphish_data,
        otx_data=otx_data,
        allowlist_domain=args.allowlist_domain,
        allow_rules=allow_rules,
        block_rules=block_rules,
    )
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
