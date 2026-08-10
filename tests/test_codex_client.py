from types import SimpleNamespace

from sec_guard.codex_client import CodexClient
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
