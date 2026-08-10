from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_composite_action_exposes_result_outputs_and_pins_artifact_upload():
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))

    assert action["runs"]["using"] == "composite"
    assert {"openai_api_key", "github_token", "severity_threshold"}.issubset(action["inputs"])
    assert {
        "report_path",
        "sarif_path",
        "patch_path",
        "blocking_findings",
        "scan_complete",
        "exit_code",
    }.issubset(
        action["outputs"]
    )
    upload_steps = [
        step
        for step in action["runs"]["steps"]
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert len(upload_steps) == 1
    assert len(upload_steps[0]["uses"].split("@", 1)[1]) == 40


def test_runtime_lock_contains_direct_dependencies():
    lock = (ROOT / "requirements-runtime.txt").read_text(encoding="utf-8")
    for package in ("openai==", "pydantic==", "requests=="):
        assert package in lock


def test_ci_exercises_the_composite_action():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))

    smoke_job = workflow["jobs"]["action-smoke"]
    local_action_steps = [step for step in smoke_job["steps"] if step.get("uses") == "./"]

    assert len(local_action_steps) == 1
    assert local_action_steps[0]["with"]["severity_threshold"] == "critical"


def test_external_action_references_are_sha_pinned():
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))

    action_references = [
        step["uses"]
        for step in action["runs"]["steps"]
        if "uses" in step and not str(step["uses"]).startswith("./")
    ]
    workflow_references = [
        step["uses"]
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if "uses" in step and not str(step["uses"]).startswith("./")
    ]

    for reference in action_references + workflow_references:
        assert len(str(reference).split("@", 1)[-1]) == 40
