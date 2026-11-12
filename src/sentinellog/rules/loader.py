"""Safe YAML detection rule and allowlist loading utilities."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from sentinellog.rules.schema import Rule, validate_safe_regex


def load_rule(path: Path | str) -> Rule:
    """Load and validate a single YAML detection rule file.

    Uses yaml.safe_load exclusively and reports helpful error messages.
    """
    file_path = Path(path)
    if not file_path.is_file():
        msg = f"Rule file '{file_path}' does not exist"
        raise FileNotFoundError(msg)

    try:
        with open(file_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        msg = f"YAML syntax error in rule '{file_path}': {e}"
        raise ValueError(msg) from e

    if not isinstance(data, dict):
        msg = f"Rule '{file_path}' content must be a dictionary, got {type(data).__name__}"
        raise ValueError(msg)

    try:
        rule = Rule.model_validate(data)
    except ValidationError as e:
        field_errors = []
        for err in e.errors():
            loc = " -> ".join(str(p) for p in err["loc"])
            field_errors.append(f"  - [{loc}]: {err['msg']}")
        msg = f"Rule validation failed in '{file_path.name}':\n" + "\n".join(field_errors)
        raise ValueError(msg) from e

    # Validate regex patterns in detection filter if any
    filter_dict = rule.detection.filter
    for key, val in filter_dict.items():
        if key.endswith("__regex") and isinstance(val, str):
            try:
                validate_safe_regex(val)
            except ValueError as e:
                msg = f"Regex validation failed in '{file_path.name}' field '{key}': {e}"
                raise ValueError(msg) from e

    return rule


def load_rules_from_dir(directory: Path | str) -> list[Rule]:
    """Recursively discover, load, and validate all YAML rules in a directory tree."""
    dir_path = Path(directory)
    if not dir_path.is_dir():
        return []

    rules: list[Rule] = []
    for f in sorted(dir_path.rglob("*")):
        if f.is_file() and f.suffix.lower() in (".yaml", ".yml"):
            rules.append(load_rule(f))

    rules.sort(key=lambda r: r.id)
    return rules


def load_allowlist(path: Path | str = "config/allowlist.yaml") -> dict[str, Any]:
    """Load suppression allowlist configuration using yaml.safe_load."""
    allowlist_path = Path(path)
    if not allowlist_path.is_file():
        return {}

    try:
        with open(allowlist_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}
