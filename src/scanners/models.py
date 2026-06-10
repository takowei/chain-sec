"""Data models for scanner findings."""

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single vulnerability finding from static analysis."""

    rule_id: str
    severity: Severity
    contract: str
    function: str | None
    description: str
    source_file: str
    line_start: int | None = None
    line_end: int | None = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "contract": self.contract,
            "function": self.function,
            "description": self.description,
            "source_file": self.source_file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "extra": self.extra,
        }
