import json

from sec_guard.agent import main
from sec_guard.models import Finding, Report, ReportSummary, Severity


def write_report(path, findings):
    report = Report(
        schema_version="1.0",
        repository="https://github.com/dabdul-wahab1988/sec-guard-action",
        workspace=".",
        generated_at_unix=0,
        severity_threshold=Severity.HIGH,
        findings=findings,
        summary=ReportSummary(
            total_findings=len(findings),
            by_severity={finding.severity.value: 1 for finding in findings},
            highest_severity=max((finding.severity for finding in findings), key=lambda value: value.rank, default=None),
        ),
    )
    path.write_text(json.dumps(report.model_dump(mode="json")), encoding="utf-8")


def test_agent_passes_when_no_finding_meets_threshold(tmp_path):
    finding = Finding(
        id="SEC005",
        severity=Severity.MEDIUM,
        title="Dynamic evaluation call",
        description="A dynamic call was found.",
        file="src/app.py",
        line=3,
    )
    report_path = tmp_path / "report.json"
    write_report(report_path, [finding])

    assert main(["--report", str(report_path), "--severity-threshold", "high"]) == 0


def test_agent_fails_when_finding_meets_threshold(tmp_path):
    finding = Finding(
        id="SEC003",
        severity=Severity.CRITICAL,
        title="Private key material detected",
        description="A private-key header was found.",
        file="secrets.txt",
        line=1,
    )
    report_path = tmp_path / "report.json"
    write_report(report_path, [finding])

    assert main(["--report", str(report_path), "--severity-threshold", "high"]) == 1
