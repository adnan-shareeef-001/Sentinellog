# SentinelLog Agent Instructions & Operating Protocol

## 1. EXECUTION PROTOCOL

1. **Stages run on command.** Stages are S0 to S8. Start with S0 immediately. After each stage, print the status block and wait for `go` (next stage) or `go all` (run every remaining stage without stopping).
2. **Pause conditions:** (a) authentication or credentials, (b) a destructive command (delete, overwrite, system-level change), (c) a test that still fails after 3 fix attempts, (d) a blocking ambiguity that instructions do not resolve. Everything else, decide autonomously and document.
3. **Terminal command guidelines:**
   - Create and edit files with file editor tools, never with shell heredocs or echo redirection.
   - Chain related commands into one call (`;` in PowerShell, `&&` in bash).
   - Never activate the venv. Call the venv interpreter directly (`.venv\Scripts\python.exe` on Windows, `.venv/bin/python` on Linux/macOS) and run everything as `python -m ...`. This avoids PowerShell execution-policy problems.
4. **Platform & Environment:** Required: Python 3.11+ and Git.
5. **Self-verify loop after every stage:** run `ruff check .`, `ruff format --check .`, `mypy src`, and `pytest -q`. Fix failures and re-run until green. Never report a stage as done with failing checks, and never claim a result not actually run.
6. **Commit per stage:** Conventional Commit message (`git add -A; git commit -m "feat(sX): ..."`). Do not push until S8 remote is configured.
7. **Keep chat output minimal:** No essays or tutorials. Status block plus the exact command output that proves acceptance.
8. **Cross-platform:** Use `pathlib` everywhere. Forward-slash paths in YAML and docs. Everything must run on Windows PowerShell and Ubuntu.
9. **Offline and free:** No paid services, no required API keys, no network calls at runtime unless an optional feature is explicitly enabled.

## 2. SAFETY RULES (FIXED)

- Defensive tool only. No exploit, scanning, or attack code. The simulator only **writes fake log lines to local files**.
- Synthetic data only. IPs come from `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (attackers) and `10.0.0.0/24` (internal). Fake usernames and hostnames only.
- `yaml.safe_load` only. No `eval`/`exec` on log or rule content.
- Treat logs as untrusted: max line length 8192 (truncate, flag), default max file size 500 MB, decode with `errors="replace"`, HTML-escape everything in reports, strip ANSI escape codes from values before terminal output, no nested-quantifier regexes.
- Secrets only from environment variables; `.env` is git-ignored; never print them.

## 3. FIXED STACK

Python 3.11+. Package layout `src/sentinellog`, build backend `setuptools`, installed with `python -m pip install -e ".[dev]"`.

Runtime deps: `pydantic>=2`, `PyYAML`, `typer`, `rich`, `jinja2`.
Optional extras: `evtx` = `python-evtx`; `dashboard` = `streamlit`, `pandas`; `geoip` = `geoip2`.
Dev deps: `pytest`, `pytest-cov`, `ruff`, `mypy`, `types-PyYAML`.

Config in `pyproject.toml`: ruff line length 100, rules `E,F,I,UP,B,S`; mypy `strict = true` for `src`; pytest `testpaths = ["tests"]`, `addopts = "-q --cov=sentinellog --cov-fail-under=80"` (turn the coverage gate on only from S3 onward).

Console script: `sentinellog = sentinellog.cli:app`.

## 6. QUALITY GATES (apply to every stage)

- `ruff check .`, `ruff format --check .`, `mypy src`, `pytest -q` all green.
- Unit tests per parser (valid, malformed, IPv6, timezone, empty, 10 KB line), per filter operator, per rule type (boundary: exactly at threshold, one below, window edge), scoring, dedupe.
- Integration test: `simulate --seed 42` -> `scan` -> asserts the expected rule IDs fire and normal-only logs produce 0 alerts.
- Security tests: ANSI escapes in user-agent, `<script>` in URL (confirm it is escaped in HTML), binary garbage line, 1 MB single line, malicious YAML (`!!python/object`) rejected.
- Performance test (`tests/performance`, marked `slow`): 100k lines scanned in under 10 s; print events/sec.
- Coverage >= 80% from S3 onward.
