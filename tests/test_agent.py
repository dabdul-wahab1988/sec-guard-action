import json

from sec_guard.agent import _emit_annotation, _safe_log_text, main
from sec_guard.models import Finding, Report, ReportSummary, ScanSummary, Severity


def write_report(path, findings, **updates):
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
    if updates:
        report = report.model_copy(update=updates)
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


def test_annotations_escape_untrusted_workflow_command_fields(capsys):
    finding = Finding(
        id="SEC001",
        severity=Severity.HIGH,
        title="Potential hard-coded secret",
        description="A credential-shaped value was found.",
        file="safe,part:py\n::warning file=pwned::injected%value",
        line=1,
    )

    _emit_annotation(finding)
    output = capsys.readouterr().out

    assert "::error file=safe%2Cpart%3Apy%0A%3A%3Awarning file=pwned%3A%3Ainjected%25value,line=1::" in output
    assert "\n::warning" not in output


def test_untrusted_model_log_text_stays_on_one_line():
    assert _safe_log_text("suggestion\n::warning::injected") == r"suggestion\n::warning::injected"


def test_agent_writes_machine_readable_github_outputs(tmp_path):
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "github-output"
    write_report(report_path, [])

    assert main(
        [
            "--report",
            str(report_path),
            "--github-output",
            str(output_path),
        ]
    ) == 0

    outputs = output_path.read_text(encoding="utf-8")
    assert "blocking_findings=0" in outputs
    assert "scan_complete=true" in outputs
    assert "exit_code=0" in outputs


def test_agent_fails_closed_for_an_incomplete_scan(tmp_path):
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "github-output"
    write_report(
        report_path,
        [],
        scan_complete=False,
        scan_summary=ScanSummary(oversized_files=["large.txt"]),
    )

    assert main(
        [
            "--report",
            str(report_path),
            "--github-output",
            str(output_path),
        ]
    ) == 2

    outputs = output_path.read_text(encoding="utf-8")
    assert "scan_complete=false" in outputs
    assert "exit_code=2" in outputs
