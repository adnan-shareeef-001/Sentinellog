# Architecture & Implementation Decisions

- D001: Target Python 3.11+ using Pydantic v2 for data normalization and rule validation.
- D002: Use direct virtual environment interpreter invocation (`.venv\Scripts\python.exe` / `.venv/bin/python`) to prevent PowerShell script execution policy issues.
- D003: Configure Ruff with rules E, F, I, UP, B, S and Mypy strict mode for `src` to guarantee defensive coding practices.
- D004: In classic SSH logs without year, infer the year from file mtime, subtracting one year if resulting date is in the future.
- D005: Use Rich for CLI rendering with color-coded severity levels and clean tabular formatting.

