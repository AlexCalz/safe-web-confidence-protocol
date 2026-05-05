# Protocol Diagram

```mermaid
flowchart LR
    A["Candidate URL"] --> B{"Local policy?"}
    B -->|Allowlist| C["allow = 100"]
    B -->|Blocklist| D["block = 0"]
    B -->|No match| E["Canonicalize URL and host"]
    E --> F["VirusTotal
    +15 clean broad scan
    -30 material malicious
    -45 high malicious ratio
    -15 suspicious ratio"]
    F --> G{"Need more evidence?"}
    G -->|Yes| H["urlscan
    +10 benign same host
    -20 redirect host change
    -30 malicious verdict"]
    G -->|Yes| I["Safe Browsing
    -40 threat match"]
    G -->|Yes| J["OpenPhish
    -35 phishing hit"]
    G -->|Yes| K["OTX
    -15 pulse hit"]
    G -->|No| L["Use available evidence"]
    H --> M["Aggregate weighted signals"]
    I --> M
    J --> M
    K --> M
    L --> M
    M --> N["Host heuristics
    -10 punycode or IP-style host
    -10 login or verification path
    +20 explicit trusted domain"]
    N --> O{"Score 0-100"}
    O -->|80-100| P["allow"]
    O -->|50-79| Q["sandbox-only"]
    O -->|0-49| R["block"]
    P --> S["Open exact assessed URL"]
    Q --> T["Restricted investigation only"]
    R --> U["Do not browse"]
```

## Notes

- Query VirusTotal first because it is the primary aggregation source in this protocol.
- Add the secondary scans when the URL is unfamiliar, login-themed, recently seen, or already suspicious.
- Re-run the protocol if the page redirects to a different host or starts a download flow.
- Use the diagram weights as a quick visual summary; the full scoring rules live in `scoring-model.md`.
