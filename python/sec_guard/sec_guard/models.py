from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def parse(cls, value: str) -> "Severity":
        normalized = value.strip().upper()
        try:
            return cls(normalized)
        except ValueError as exc:
            expected = ", ".join(item.value.lower() for item in cls)
            raise ValueError(f"unsupported severity '{value}'; expected {expected}") from exc

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    severity: Severity
    title: str
    description: str
    file: str
    line: int | None = None
    evidence: str = ""
    remediation: str = ""


class ReportSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    total_findings: int
    by_severity: dict[str, int]
    highest_severity: Severity | None = None


class Report(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: str
    repository: str
    workspace: str
    generated_at_unix: int
    severity_threshold: Severity
    findings: list[Finding]
    summary: ReportSummary

    def model_payload(self) -> dict[str, Any]:
        """Return a JSON-compatible payload for prompts and diagnostics."""

        return self.model_dump(mode="json")
