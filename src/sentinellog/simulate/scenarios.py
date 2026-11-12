"""Attack scenario models and definitions for synthetic log generation."""

from dataclasses import dataclass, field


@dataclass
class ScenarioRecord:
    """Ground truth record for a generated attack scenario."""

    scenario: str
    file: str
    line_numbers: list[int] = field(default_factory=list)
    expected_rules: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Convert record to dictionary for labels.json serialization."""
        return {
            "scenario": self.scenario,
            "file": self.file,
            "line_numbers": self.line_numbers,
            "expected_rules": self.expected_rules,
        }
