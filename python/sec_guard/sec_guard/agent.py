from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import requests
from pydantic import ValidationError

from .codex_client import CodexClient, redact_sensitive_text
from .models import Finding, Report, Severity


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate a sec-guard-action JSON report")
    parser.add_argument("--report", required=True, type=Path, help="Rust report JSON path")
    parser.add_argument("--workspace", type=Path, default=Path("."))
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--severity-threshold", default="", help="Override the report threshold")
    parser.add_argument("--generate-patch", action="store_true")
    parser.add_argument(
        "--patch-output",
        type=Path,
        default=Path(".sec-guard/sec-guard.patch"),
        help="Path for the optional unified diff",
    )
    parser.add_argument(
        "--github-output",
        type=Path,
        default=None,
        help="Optional GITHUB_OUTPUT file for action result values",
    )
    args = parser.parse_args(argv)

    try:
        report = _load_report(args.report)
        threshold = Severity.parse(args.severity_threshold) if args.severity_threshold else report.severity_threshold
    except (OSError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        print(f"sec-guard-agent: unable to load report: {exc}", file=sys.stderr)
        _write_github_outputs(
            args.github_output,
            blocking_findings=0,
            scan_complete=False,
            exit_code=2,
            patch_path=args.patch_output,
        )
        return 2

    blocking = [finding for finding in report.findings if finding.severity.rank >= threshold.rank]
    print(
        f"sec-guard-agent: {len(report.findings)} finding(s); "
        f"{len(blocking)} at or above {threshold.value}"
    )
    for finding in blocking:
        _emit_annotation(finding)

    if not report.scan_complete:
        print(
            "sec-guard-agent: scan was incomplete; refusing to evaluate a partial workspace",
            file=sys.stderr,
        )
        for reason in report.scan_summary.incomplete_reasons:
            print(f"sec-guard-agent: {reason}", file=sys.stderr)
        _write_github_outputs(
            args.github_output,
            blocking_findings=len(blocking),
            scan_complete=False,
            exit_code=2,
            patch_path=args.patch_output,
        )
        return 2

    if args.generate_patch and blocking:
        _maybe_generate_patch(report, blocking, args)

    if blocking:
        print("sec-guard-agent: severity gate failed", file=sys.stderr)
        exit_code = 1
    else:
        print("sec-guard-agent: severity gate passed")
        exit_code = 0
    _write_github_outputs(
        args.github_output,
        blocking_findings=len(blocking),
        scan_complete=True,
        exit_code=exit_code,
        patch_path=args.patch_output,
    )
    return exit_code


def _load_report(path: Path) -> Report:
    with path.open("r", encoding="utf-8") as handle:
        return Report.model_validate(json.load(handle))


def _emit_annotation(finding: Finding) -> None:
    location = f"file={finding.file}"
    if finding.line is not None:
        location += f",line={finding.line}"
    message = f"{finding.id} {finding.title}: {finding.description}"
    print(f"::error {location}::{message}")


def _maybe_generate_patch(report: Report, blocking: list[Finding], args: argparse.Namespace) -> None:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        print("sec-guard-agent: OPENAI_API_KEY is not set; skipping patch generation")
        return

    repository = args.repository or report.repository
    repository_context = _fetch_repository_context(repository, os.environ.get("GITHUB_TOKEN", ""))
    narrowed_report = report.model_copy(update={"findings": blocking})
    model = os.environ.get("SEC_GUARD_MODEL", "gpt-4.1-mini")
    try:
        result = CodexClient(api_key=api_key, model=model).generate_patch(
            narrowed_report,
            workspace=args.workspace,
            repository_context=repository_context,
        )
        args.patch_output.parent.mkdir(parents=True, exist_ok=True)
        safe_patch = redact_sensitive_text(result.patch.rstrip())
        args.patch_output.write_text(safe_patch + "\n", encoding="utf-8")
        print(f"sec-guard-agent: patch draft written to {args.patch_output}")
        if result.summary:
            print(f"sec-guard-agent: {redact_sensitive_text(result.summary)}")
        if result.tests:
            print("sec-guard-agent: suggested verification commands:")
            for command in result.tests:
                print(f"  - {command}")
    except Exception as exc:  # pragma: no cover - provider failures depend on the network
        print(
            "sec-guard-agent: patch generation skipped after provider error: "
            f"{type(exc).__name__}",
            file=sys.stderr,
        )


def _write_github_outputs(
    path: Path | None,
    *,
    blocking_findings: int,
    scan_complete: bool,
    exit_code: int,
    patch_path: Path,
) -> None:
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"blocking_findings={blocking_findings}\n")
            handle.write(f"scan_complete={str(scan_complete).lower()}\n")
            handle.write(f"exit_code={exit_code}\n")
            handle.write(f"patch_path={patch_path}\n")
    except OSError as exc:
        print(f"sec-guard-agent: unable to write GitHub outputs: {exc}", file=sys.stderr)


def _fetch_repository_context(repository: str, token: str) -> dict[str, Any]:
    slug = _repository_slug(repository)
    if not slug or not token:
        return {}

    try:
        response = requests.get(
            f"https://api.github.com/repos/{slug}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        return {
            "full_name": data.get("full_name"),
            "default_branch": data.get("default_branch"),
            "language": data.get("language"),
            "visibility": data.get("visibility"),
        }
    except (requests.RequestException, ValueError) as exc:
        print(f"sec-guard-agent: GitHub metadata lookup skipped: {exc}", file=sys.stderr)
        return {}


def _repository_slug(repository: str) -> str:
    value = repository.strip().removesuffix(".git").rstrip("/")
    if value.startswith("git@github.com:"):
        value = value.removeprefix("git@github.com:")
    elif value.startswith("ssh://git@github.com/"):
        value = value.removeprefix("ssh://git@github.com/")
    if "github.com/" in value:
        value = value.split("github.com/", 1)[1]
    return value.strip("/")


if __name__ == "__main__":
    raise SystemExit(main())
