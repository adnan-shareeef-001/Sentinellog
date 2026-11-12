# Architecture & Implementation Decisions

- D001: Target Python 3.11+ using Pydantic v2 for data normalization and rule validation.
- D002: Use direct virtual environment interpreter invocation (`.venv\Scripts\python.exe` / `.venv/bin/python`) to prevent PowerShell script execution policy issues.
- D003: Configure Ruff with rules E, F, I, UP, B, S and Mypy strict mode for `src` to guarantee defensive coding practices.
- D004: In classic SSH logs without year, infer the year from file mtime, subtracting one year if resulting date is in the future.
- D005: Use Rich for CLI rendering with color-coded severity levels and clean tabular formatting.
- D006: In Web access log parsing, unquote raw URLs safely, normalizing '-' to None for user and user_agent fields.
- D007: Truncate lines defensively at 8192 characters and sanitize ANSI control codes during streaming ingestion.
- D008: Auto-detect format by probing the first 20 non-empty lines with a 60% match rate threshold.
- D009: In DetectionEngine, use a sliding time-window deque with cooldown periods to prevent alert flooding from identical entity keys.
- D010: Validate all rule regexes against nested quantifier patterns to eliminate ReDoS vulnerabilities at load time.
- D011: Support rich filter operators (`exact`, `__in`, `__contains`, `__icontains`, `__regex`, `__cidr`, `__gte`, `__lte`, `__exists`) with automatic type coercion.
- D012: In synthetic log simulation, inject attack lines with precise ground-truth line indexing recorded into labels.json for automated benchmarking.
- D013: Measure scenario recall as the ratio of scenarios where all expected rules triggered, and alert precision as the ratio of alerts referencing labeled malicious lines.
- D014: Enforce an automated Pytest test coverage threshold of >= 80% starting in Stage S3.
- D015: Windows Security Event log parser supports both JSON Lines and CSV exports with automated field mapping (Event IDs 4625, 4624, 4688, 4698, 4720, 4732, 1102).
- D016: State-machine sequence correlation engine tracks ordered multi-stage attack patterns grouped by entity keys (`same: [src_ip]`) within strict time windows.
