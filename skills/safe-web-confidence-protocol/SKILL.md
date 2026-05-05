---
name: safe-web-confidence-protocol
description: Assess URLs and domains before browsing by combining VirusTotal and other reputation or threat-intelligence sources into a confidence score and action decision. Use when an agent is about to open an unfamiliar website, download from a new host, validate a phishing or malware suspicion, or enforce a pre-browse safety protocol for internet research.
---

# Safe Web Confidence Protocol

## Overview

Use this skill to gate outbound browsing behind a reputation check. Gather URL intelligence first, convert the results into a normalized confidence score, decide `allow`, `sandbox-only`, or `block`, and record the evidence before opening the page.

## Quick Start

1. Canonicalize the candidate URL before doing anything else.
2. Check the blocklist and allowlist first. If a rule matches, stop there and skip external lookups.
3. Query VirusTotal first when the target is not already decided by a local rule. Add urlscan, Google Safe Browsing, OpenPhish, or AlienVault OTX when available.
4. Run [`scripts/url_confidence_score.py`](./scripts/url_confidence_score.py) to combine evidence into a single score and verdict.
5. Open the site only if the verdict is `allow`, or if the user explicitly wants a higher-risk investigation path.
6. If the verdict is `sandbox-only`, use the most restricted browsing workflow available and avoid downloads, form submission, or authentication.
7. If the verdict is `block`, do not browse to the site unless the user explicitly overrides the protocol.

## Workflow

### 1. Canonicalize the Target

- Strip fragments.
- Preserve the scheme, host, path, and query.
- Convert obvious punycode or Unicode tricks into a representation you can reason about.
- Score the fully-qualified URL and also note the registrable domain.

### 2. Gather Evidence Before Browsing

- Read [`references/blocklist.txt`](./references/blocklist.txt) and [`references/allowlist.txt`](./references/allowlist.txt) before external calls.
- Treat both files as suffix-based host rules. A line like `example.com` matches `example.com` and `sub.example.com`.
- Put stable internal or well-known trusted domains in the allowlist.
- Put confirmed malicious domains, recurring phishing hosts, or infrastructure you never want opened in the blocklist.

- Prefer VirusTotal because it aggregates many scanners and provides community and vendor context.
- Add at least one second source when the URL is unfamiliar or high-risk.
- Good complements:
  - `urlscan.io` for page rendering and IOC context
  - Google Safe Browsing for malware and social-engineering signals
  - OpenPhish or a phishing feed for targeted phishing context
  - AlienVault OTX for pulse hits or prior sightings

If live API access is available, set environment variables and call the script directly:

```bash
export VT_API_KEY=...
export URLSCAN_API_KEY=...
export GOOGLE_SAFE_BROWSING_API_KEY=...
python3 scripts/url_confidence_score.py \
  --url "https://candidate.example/login" \
  --allowlist-file references/allowlist.txt \
  --blocklist-file references/blocklist.txt \
  --fetch
```

If the APIs have already been queried elsewhere, pass the raw JSON artifacts instead:

```bash
python3 scripts/url_confidence_score.py \
  --url "https://candidate.example/login" \
  --allowlist-file references/allowlist.txt \
  --blocklist-file references/blocklist.txt \
  --vt-json vt.json \
  --urlscan-json urlscan.json \
  --gsb-json safebrowsing.json
```

### 3. Score and Decide

Use the scorer as the default implementation. The score is 0 to 100 and maps to:

- `80-100`: `allow`
- `50-79`: `sandbox-only`
- `0-49`: `block`

Apply the verdict conservatively. A single severe signal like confirmed phishing, malware, or many vendor detections should dominate the outcome even if one source is silent.

See [`references/scoring-model.md`](./references/scoring-model.md) for the exact weighting model.

### 4. Browse Safely

If the verdict is `allow`:

- Open only the exact URL that was assessed.
- Avoid downloading binaries unless the user asked for them.
- Re-check if the site redirects to a different host.

If the verdict is `sandbox-only`:

- Treat the page as hostile.
- Avoid authentication, file downloads, extensions, clipboard operations, and data entry.
- Stop if the page redirects to an unassessed URL or tries to trigger a download.

If the verdict is `block`:

- Do not open the site.
- Summarize the evidence and ask for an explicit override only if the user still needs deeper investigation.

### 5. Explain the Decision

Report:

- the normalized URL
- the final score and verdict
- which sources were checked
- the strongest positive and negative signals
- any missing sources that reduce certainty

## Decision Heuristics

- Favor false negatives over false positives only for clearly trusted domains already established in context.
- Treat newly registered, typo-squatted, punycode-heavy, or login-themed domains as higher risk even if reputation data is sparse.
- Treat sparse intelligence as uncertainty, not safety.
- Penalize redirects, cloaking behavior, disposable hosting, and mismatched brand/login paths.
- Re-assess if the domain, path, or redirect target changes.

## Bundled Resources

- [`scripts/url_confidence_score.py`](./scripts/url_confidence_score.py): aggregate raw API outputs into a score, verdict, and reason list
- [`references/scoring-model.md`](./references/scoring-model.md): weighting, thresholds, and override rules
- [`references/protocol-diagram.md`](./references/protocol-diagram.md): Mermaid diagram of the protocol
- [`references/allowlist.txt`](./references/allowlist.txt): trusted domains that bypass API checks
- [`references/blocklist.txt`](./references/blocklist.txt): denied domains that short-circuit to `block`

## Example Triggers

- "Before you open this URL, run the safe web protocol."
- "Check this suspicious login page with VirusTotal first."
- "Give me a confidence score before browsing the site."
- "Investigate this domain safely and tell me if it is worth opening."

## Output Template

Use this shape when reporting back:

```text
URL: https://candidate.example/login
Score: 42/100
Verdict: block

Sources checked: VirusTotal, urlscan, Google Safe Browsing
Key signals:
- 7 vendors marked the URL malicious or phishing
- Safe Browsing flagged social engineering
- urlscan has no prior benign history

Decision:
Do not browse to the site unless the user explicitly requests a higher-risk investigation.
```
