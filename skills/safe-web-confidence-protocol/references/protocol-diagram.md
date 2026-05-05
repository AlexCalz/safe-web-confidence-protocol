# Protocol Diagram

```mermaid
flowchart TD
    A["Candidate URL arrives"] --> B["Canonicalize URL and registrable domain"]
    B --> C["Query VirusTotal"]
    C --> D{"More evidence needed?"}
    D -->|Yes| E["Query one or more: urlscan, Safe Browsing, OpenPhish, OTX"]
    D -->|No| F["Assemble available evidence"]
    E --> F
    F --> G["Run url_confidence_score.py"]
    G --> H{"Verdict?"}
    H -->|allow| I["Open exact assessed URL"]
    H -->|sandbox-only| J["Open only in restricted investigation mode"]
    H -->|block| K["Do not browse; report evidence"]
    I --> L["Monitor redirects and re-check on host change"]
    J --> L
    K --> M["Wait for explicit user override"]
    L --> N["Summarize score, sources, and rationale"]
    M --> N
```

## Notes

- Query VirusTotal first because it is the primary aggregation source in this protocol.
- Use additional sources whenever the URL is unfamiliar, login-themed, recently seen, or already suspected of phishing or malware.
- Re-run the protocol if the page redirects to a different host or starts a download flow.
