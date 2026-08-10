import json
from types import SimpleNamespace

from sec_guard.codex_client import CodexClient, redact_sensitive_text
from sec_guard.models import Finding, Report, ReportSummary, Severity


def sample_report() -> Report:
    finding = Finding(
        id="SEC001",
        severity=Severity.HIGH,
        title="Potential hard-coded secret",
        description="A credential-shaped value was found.",
        file="config.py",
        line=4,
        evidence="<redacted: credential-shaped value>",
        remediation="Move the value to a secret manager.",
    )
    return Report(
        schema_version="1.0",
        repository="https://github.com/dabdul-wahab1988/sec-guard-action",
        workspace=".",
        generated_at_unix=0,
        severity_threshold=Severity.HIGH,
        findings=[finding],
        summary=ReportSummary(
            total_findings=1,
            by_severity={"HIGH": 1},
            highest_severity=Severity.HIGH,
        ),
    )


class FakeResponses:
    def __init__(self) -> None:
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        return SimpleNamespace(
            output_text='{"summary":"Move the credential to CI secrets.","patch":"--- a/config.py\\n+++ b/config.py","tests":["pytest -q"]}'
        )


class FakeOpenAI:
    def __init__(self) -> None:
        self.responses = FakeResponses()


def test_codex_client_parses_structured_patch_response():
    fake_client = FakeOpenAI()
    api_key = "test" + "-key"
    result = CodexClient(api_key=api_key, client=fake_client).generate_patch(sample_report())

    assert result.summary == "Move the credential to CI secrets."
    assert result.patch.startswith("--- a/config.py")
    assert result.tests == ["pytest -q"]
    assert fake_client.responses.kwargs["model"] == "gpt-4.1-mini"


def test_codex_client_keeps_plain_text_as_a_patch_draft():
    fake_client = FakeOpenAI()
    fake_client.responses.create = lambda **kwargs: SimpleNamespace(output_text="--- a/file.py\n+++ b/file.py")

    api_key = "test" + "-key"
    result = CodexClient(api_key=api_key, client=fake_client).generate_patch(sample_report())

    assert result.patch == "--- a/file.py\n+++ b/file.py"
    assert result.tests == []


def test_prompt_omits_sensitive_context_and_redacts_other_excerpts(tmp_path):
    secret_file = tmp_path / "config.py"
    secret_file.write_text('api_key = "super-secret-value-123"\n', encoding="utf-8")
    app_file = tmp_path / "app.py"
    app_file.write_text(
        'api_key = "super-secret-value-123"\neval(user_input)\n',
        encoding="utf-8",
    )
    secret = sample_report().findings[0]
    dynamic = Finding(
        id="SEC005",
        severity=Severity.MEDIUM,
        title="Dynamic evaluation call",
        description="A dynamic call was found.",
        file="app.py",
        line=2,
        evidence="eval(user_input)",
        remediation="Use a safe parser.",
    )
    report = sample_report().model_copy(update={"findings": [secret, dynamic]})

    prompt = CodexClient._build_prompt(report, tmp_path, None)
    payload = json.loads(prompt)

    assert "super-secret-value-123" not in prompt
    assert str(tmp_path) not in prompt
    assert payload["source_context"]
    assert "<redacted: secret-like value>" in prompt


def test_sensitive_only_report_does_not_send_source_context(tmp_path):
    secret_file = tmp_path / "config.py"
    secret_file.write_text('api_key = "super-secret-value-123"\n', encoding="utf-8")

    prompt = CodexClient._build_prompt(sample_report(), tmp_path, None)
    payload = json.loads(prompt)

    assert payload["source_context"] == []
    assert "super-secret-value-123" not in prompt


def test_redaction_covers_temporary_aws_and_fine_grained_github_tokens():
    aws_access_key = "ASIA" + "1234567890123456"
    github_token = "github_pat_" + "11ABCDEFGHijklmnopQRSTUV"
    value = f"{aws_access_key} {github_token}"

    redacted = redact_sensitive_text(value)

    assert aws_access_key not in redacted
    assert github_token not in redacted
    assert redacted.count("<redacted: secret-like value>") == 2
