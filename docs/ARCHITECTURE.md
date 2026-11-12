# SentinelLog System Architecture

## 1. High-Level Architecture Overview
SentinelLog is engineered around a pipeline architecture prioritizing low memory footprint, high throughput, and strict data provenance.

```mermaid
flowchart TD
    subgraph Ingestion ["1. Streaming Ingestion"]
        L1["Plain Text Files"] --> R["Streaming Reader (Lazy Generator)"]
        L2["Gzip Compressed (.gz)"] --> R
        L3["Live Stream (Tail)"] --> R
    end

    subgraph Normalization ["2. Parsing & Normalization"]
        R --> REG["Parser Registry"]
        REG --> P1["SSH Auth Parser"]
        REG --> P2["Web Access Parser"]
        REG --> P3["Windows EVTX Parser"]
        REG --> P4["Syslog Parser"]
        P1 & P2 & P3 & P4 --> EVT["Normalized Event Model (UTC)"]
    end

    subgraph Detection ["3. Multi-Engine Detection"]
        EVT --> REORDER["Out-of-Order Reorder Buffer"]
        REORDER --> ENGINE["Engine Dispatcher"]
        ENGINE --> M1["Match Engine (Regex / CIDR)"]
        ENGINE --> M2["Threshold Engine (Sliding Deque)"]
        ENGINE --> M3["Sequence Engine (State Machine)"]
        ENGINE --> M4["Anomaly Engine (Z-Score)"]
    end

    subgraph Enrichment ["4. Context & Scoring"]
        M1 & M2 & M3 & M4 --> RAW_ALERT["Candidate Alert"]
        RAW_ALERT --> TI["Threat Intel (Local Radix/Hash)"]
        RAW_ALERT --> ASSET["Asset Criticality Weighting"]
        RAW_ALERT --> ALLOW["Allowlist Suppression"]
        TI & ASSET & ALLOW --> SCORE["Composite Scoring (0-100)"]
    end

    subgraph Storage ["5. Persistence & Triage"]
        SCORE --> DEDUPE["Entity Deduplicator"]
        DEDUPE --> SQLITE["SQLite Store (Alert Lifecycle)"]
    end

    subgraph Presentation ["6. Presentation"]
        SQLITE --> CLI["Rich Terminal CLI"]
        SQLITE --> HTML["Self-Contained HTML Report"]
        SQLITE --> DASH["Streamlit Web Dashboard"]
    end
```

## 2. Key Design Decisions

### Streaming over In-Memory Buffering
Log files routinely range from several hundred megabytes to tens of gigabytes. Loading an entire log into a Python list consumes gigabytes of RAM. SentinelLog utilizes Python generator pipelines (`yield Event(...)`), reading line-by-line so memory usage stays flat regardless of input size.

### UTC Datetime Normalization
Logs from distributed systems come from varying time zones. All internal calculations, sliding windows, and event correlation normalize immediately to UTC.

### Pure Functions & Immutability
Core parsing and matching engines are stateless pure functions wherever possible, facilitating deterministic testing and avoiding race conditions.
