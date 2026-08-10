from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


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


class ScanError(BaseModel):
    model_config = ConfigDict(extra="ignore")

    path: str
    error: str


class ScanSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    scanned_files: int = 0
    skipped_non_text_files: int = 0
    ignored_files: int = 0
    ignored_directories: int = 0
    oversized_files: list[str] = Field(default_factory=list)
    non_utf8_files: list[str] = Field(default_factory=list)
    read_errors: list[ScanError] = Field(default_factory=list)
    syntax_error_files: list[str] = Field(default_factory=list)

    @property
    def incomplete_reasons(self) -> list[str]:
        reasons: list[str] = []
        if self.oversized_files:
            reasons.append(f"{len(self.oversized_files)} file(s) exceeded the size limit")
        if self.non_utf8_files:
            reasons.append(f"{len(self.non_utf8_files)} file(s) were not valid UTF-8")
        if self.read_errors:
            reasons.append(f"{len(self.read_errors)} file or directory read error(s)")
        return reasons


class Report(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: str
    repository: str
    workspace: str
    generated_at_unix: int
    severity_threshold: Severity
    findings: list[Finding]
    summary: ReportSummary
    scan_complete: bool = True
    scan_summary: ScanSummary = Field(default_factory=ScanSummary)

    def model_payload(self) -> dict[str, Any]:
        """Return a JSON-compatible payload for prompts and diagnostics."""

        return self.model_dump(mode="json")
