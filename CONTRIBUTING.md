# Contributing to SentinelLog

Thank you for contributing to SentinelLog! As an educational and portfolio-driven project, we maintain strict defensive, code quality, and testing standards.

## Code of Conduct & Ethics
* **Strictly Defensive:** SentinelLog is designed solely for defensive log analysis, threat detection, and telemetry monitoring. Never submit exploit payloads, attack scripts that transmit network traffic, or offensive tools.
* **Untrusted Data Hygiene:** Always treat log lines as untrusted user input. Ensure all parser implementations escape output, validate line lengths, and avoid catastrophic-backtracking regexes (ReDoS).

## Development Workflow
1. **Fork and branch:** Create a feature branch with a descriptive name (`git checkout -b feat/ssh-parser`).
2. **Follow style rules:**
   - Format with `black` (line length: 100).
   - Lint with `ruff`.
   - Ensure complete static type annotations verified by `mypy`.
3. **Tests are mandatory:**
   - Write unit tests under `tests/unit/` for every parser, rule, or engine component.
   - Run `pytest` and ensure total coverage remains $\ge 80\%$.
4. **Conventional Commits:**
   - Format commit messages as `feat: ...`, `fix: ...`, `test: ...`, `docs: ...`, or `chore: ...`.
