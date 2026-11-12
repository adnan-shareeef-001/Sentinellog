"""Pydantic schema definitions and validation for YAML detection rules."""

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinellog.models import Severity

RULE_ID_PATTERN = re.compile(r"^[A-Z]+-\d{3}$")
WINDOW_PATTERN = re.compile(r"^(\d+)([smhd])$")
NESTED_QUANTIFIER_PATTERN = re.compile(r"\([^)]*(?<!\\)[+*][^)]*\)(?<!\\)[+*]")


def parse_window_seconds(window: str | None) -> int:
    """Parse time window string (e.g., '30s', '5m', '2h', '1d') into total seconds."""
    if not window:
        return 0
    m = WINDOW_PATTERN.match(window.strip().lower())
    if not m:
        msg = f"Invalid window format '{window}'. Must match pattern like '30s', '5m', '1h', '1d'."
        raise ValueError(msg)
    val = int(m.group(1))
    unit = m.group(2)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return val * multipliers[unit]


def validate_safe_regex(pattern_str: str) -> None:
    """Validate regex pattern compiles and does not contain dangerous nested quantifiers."""
    if NESTED_QUANTIFIER_PATTERN.search(pattern_str):
        msg = f"Potentially catastrophic backtracking in regex (ReDoS risk): {pattern_str}"
        raise ValueError(msg)
    try:
        re.compile(pattern_str)
    except re.error as e:
        msg = f"Invalid regex pattern '{pattern_str}': {e}"
        raise ValueError(msg) from e


class MitreMapping(BaseModel):
    """MITRE ATT&CK framework tactical and technical mapping."""

    model_config = ConfigDict(extra="ignore")

    tactic: str
    technique: str


class StepConfig(BaseModel):
    """Single stage in a multi-event sequence detection rule."""

    model_config = ConfigDict(extra="ignore")

    filter: dict[str, Any]
    min_count: int = 1


class DetectionConfig(BaseModel):
    """Detection logic specification."""

    model_config = ConfigDict(extra="ignore")

    filter: dict[str, Any] = Field(default_factory=dict)
    group_by: list[str] = Field(default_factory=list)
    threshold: int | None = None
    window: str | None = None
    distinct: str | None = None

    # Multi-event sequence configuration
    steps: list[StepConfig] = Field(default_factory=list)
    same: list[str] = Field(default_factory=list)

    # Anomaly configuration
    kind: str | None = None  # offhours | rate_spike
    hours: dict[str, Any] | None = None
    z: float = 3.0

    @field_validator("window")
    @classmethod
    def validate_window(cls, v: str | None) -> str | None:
        if v is not None:
            parse_window_seconds(v)
        return v


class ResponseConfig(BaseModel):
    """Analyst response guidance."""

    model_config = ConfigDict(extra="ignore")

    recommended_action: str = ""


class RuleTestsConfig(BaseModel):
    """Paths to positive and negative validation fixtures."""

    model_config = ConfigDict(extra="ignore")

    should_fire: str
    should_not_fire: str


class Rule(BaseModel):
    """Complete YAML detection rule schema."""

    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    description: str
    enabled: bool = True
    severity: Severity
    type: str  # match | threshold | sequence | anomaly | intel
    log_source: str  # ssh_auth | web_access | windows | syslog | jsonl | any
    mitre: MitreMapping
    detection: DetectionConfig
    exceptions: dict[str, Any] = Field(default_factory=dict)
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    tests: RuleTestsConfig

    @field_validator("id")
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        if not RULE_ID_PATTERN.match(v):
            msg = f"Rule ID '{v}' does not match required format ^[A-Z]+-\\d{{3}}$ (e.g., SSH-001)"
            raise ValueError(msg)
        return v

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        valid_types = {"match", "threshold", "sequence", "anomaly", "intel"}
        if v.lower() not in valid_types:
            msg = f"Rule type '{v}' invalid. Must be one of: {', '.join(sorted(valid_types))}"
            raise ValueError(msg)
        return v.lower()
