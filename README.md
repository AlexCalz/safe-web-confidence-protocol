# Safe Web Confidence Protocol

Safe Web Confidence Protocol is a reusable agent skill for checking URL reputation before a browser opens a site. It combines local allow and block policy with external reputation sources such as VirusTotal, urlscan, Google Safe Browsing, OpenPhish, and AlienVault OTX.

Created by Alexander Calzada.

## What it does

- short-circuits trusted or denied hosts through local policy files
- queries external reputation sources only when needed
- computes a normalized score and verdict: `allow`, `sandbox-only`, or `block`
- provides a Mermaid protocol diagram and a documented scoring model

## Repo layout

- `skills/safe-web-confidence-protocol/SKILL.md`
- `skills/safe-web-confidence-protocol/scripts/url_confidence_score.py`
- `skills/safe-web-confidence-protocol/references/scoring-model.md`
- `skills/safe-web-confidence-protocol/references/protocol-diagram.md`
- `skills/safe-web-confidence-protocol/references/allowlist.txt`
- `skills/safe-web-confidence-protocol/references/blocklist.txt`

## Install

Place `skills/safe-web-confidence-protocol` into your agent's skill directory, or keep the repo cloned and reference the skill path directly.

## Configure

Populate the policy files with your own domains:

- `references/allowlist.txt`
- `references/blocklist.txt`

Optional API keys for live lookups:

- `VT_API_KEY`
- `URLSCAN_API_KEY`
- `GOOGLE_SAFE_BROWSING_API_KEY`

## Example

```bash
python3 skills/safe-web-confidence-protocol/scripts/url_confidence_score.py \
  --url "https://candidate.example/login" \
  --allowlist-file skills/safe-web-confidence-protocol/references/allowlist.txt \
  --blocklist-file skills/safe-web-confidence-protocol/references/blocklist.txt \
  --fetch
```
