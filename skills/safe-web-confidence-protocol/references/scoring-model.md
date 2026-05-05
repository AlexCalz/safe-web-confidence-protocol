# Scoring Model

Use this reference when the agent needs a predictable decision rule instead of ad hoc judgment.

## Sources

- VirusTotal: strongest default source for URL and domain reputation
- Google Safe Browsing: strong binary malware or phishing signal
- urlscan.io: rendering, redirects, historical context, IOC relationships
- OpenPhish: phishing-specific evidence
- AlienVault OTX: pulse hits and prior analyst context

## Baseline

Start every URL at `60`.

That default means "unknown but not yet condemned." The score then moves down for risk and up for reassuring evidence.

Before using the baseline, check local policy:

- If the host matches `blocklist.txt`, return `block` immediately and skip external API calls.
- If the host matches `allowlist.txt`, return `allow` immediately and skip external API calls.
- Use suffix matching so `example.com` also matches `www.example.com`.

## Negative Weights

- VirusTotal malicious vendor ratio `>= 0.20`: `-45`
- VirusTotal malicious vendor ratio `>= 0.05` and `< 0.20`: `-30`
- VirusTotal suspicious vendor ratio `>= 0.10`: `-15`
- Google Safe Browsing match present: `-40`
- OpenPhish hit present: `-35`
- urlscan verdict malicious or phishing: `-30`
- urlscan shows recent scan with suspicious final domain different from submitted domain: `-20`
- AlienVault OTX pulse or malware hit: `-15`
- punycode host, Unicode spoofing risk, or brand-impersonation login path: `-10`
- naked IP host, unusual port, or newly observed host with no benign context: `-10`

## Positive Weights

- VirusTotal shows `0` malicious and `0` suspicious with at least `10` harmless or undetected vendors: `+15`
- urlscan shows prior benign history with same final domain: `+10`
- trusted allowlist domain already established by the task or user: `+20`

Never let positive evidence fully cancel a strong phishing or malware hit from a high-confidence source.

## Overrides

Apply these overrides before the final verdict:

- If Google Safe Browsing or OpenPhish flags the URL, the verdict cannot be `allow`.
- If VirusTotal malicious count is high enough to trigger `-45`, the verdict cannot be `allow`.
- If two or more independent sources produce strong negative signals, prefer `block` even if the numeric score lands above `50`.
- If no source data is available, treat the result as incomplete and default to `sandbox-only`, not `allow`.

## Verdict Thresholds

- `80-100`: `allow`
- `50-79`: `sandbox-only`
- `0-49`: `block`

Clamp the score into `0-100`.

## Missing Data

Missing data is not evidence of safety. Mention missing sources in the report and lower confidence in the narrative even if the verdict remains unchanged.
