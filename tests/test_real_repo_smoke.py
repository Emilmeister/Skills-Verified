"""Opt-in smoke tests against pinned public security fixtures.

These tests never clone or execute untrusted code. Set the documented environment
variables to existing local checkouts/extracted cases before running this module.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from skills_verified.cli import main

ANTHROPIC_SKILLS_COMMIT = "9d2f1ae187231d8199c64b5b762e1bdf2244733d"
SKILLSPECTOR_COMMIT = "a68496dc9220c78c3daa13cfb2f18036f1a79494"
SKILLTRUSTBENCH_REVISION = "762d5388b3a047b26df9679582af868a0e5b2c8f"
SKILLTRUSTBENCH_CASE_DIGESTS = {
    "case_00070": "d36fc427cd2e3f67e78cfe346fa3026785c4dcc31af5d463ff1656e3ae215785",
    "case_00433": "3b01cadda22ba7475b7280561ed3fca726398e57a4b9986d3601475f934d98b0",
    "case_00677": "00b4edb481fd22c1807fedf644167fa4bd96d2ae76396c643396163daedddcb3",
    "case_02160": "f0eb0d379cac02f9f5b7b50b65c86670c6d1dc8a5f7a8cff889a85c7be13c15f",
    "case_05520": "17bb1dc3534c7e69a435c93e057465e6f609e16c842079241483887d052628de",
}
STATIC_ANALYZERS = (
    "pattern,guardrails,permissions,supply_chain,obfuscation,reverse_shell,"
    "exfiltration,behavioral,mcp,config_injection,metadata,known_threats,privilege"
)


def _checkout_from_env(variable: str, expected_commit: str) -> Path:
    raw_path = os.environ.get(variable)
    if not raw_path:
        pytest.skip(f"set {variable} to run pinned public-repository smoke tests")
    path = Path(raw_path).resolve()
    if not path.is_dir():
        pytest.fail(f"{variable} is not a directory: {path}")
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.stdout.strip() == expected_commit
    return path


def _cases_from_env() -> Path:
    raw_path = os.environ.get("SV_SMOKE_SKILLTRUSTBENCH_CASES")
    if not raw_path:
        pytest.skip(
            "set SV_SMOKE_SKILLTRUSTBENCH_CASES to the extracted "
            f"SkillTrustBench {SKILLTRUSTBENCH_REVISION} benchmark_full_v1.0 directory"
        )
    path = Path(raw_path).resolve()
    if not path.is_dir():
        pytest.fail(f"SV_SMOKE_SKILLTRUSTBENCH_CASES is not a directory: {path}")
    return path


def _scan(target: Path, analyzers: str = STATIC_ANALYZERS) -> dict:
    result = CliRunner().invoke(
        main,
        [str(target), "--only", analyzers, "--compact"],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["scan"]["status"] in {"complete", "partial"}
    assert all(
        run["status"] in {"completed", "partial"} for run in report["analyzer_runs"]
    )
    return report


def test_anthropic_repo_discovers_nested_agent_skills():
    checkout = _checkout_from_env("SV_SMOKE_ANTHROPIC_SKILLS", ANTHROPIC_SKILLS_COMMIT)

    report = _scan(checkout, "guardrails")

    assert report["source"]["commit_sha"] == ANTHROPIC_SKILLS_COMMIT
    assert "agent_skills" in {platform["name"] for platform in report["platforms"]}
    assert {"template", "skills/skill-creator"} <= set(report["scope"]["skill_roots"])
    assert len(report["scope"]["skill_roots"]) >= 18


def test_skillspector_safe_control_has_no_deterministic_findings():
    checkout = _checkout_from_env("SV_SMOKE_SKILLSPECTOR", SKILLSPECTOR_COMMIT)

    report = _scan(
        checkout / "tests" / "fixtures" / "safe_skill",
        "pattern,guardrails,exfiltration,behavioral",
    )

    assert report["source"]["commit_sha"] == SKILLSPECTOR_COMMIT
    assert report["findings"] == []


def test_skillspector_poisoned_tool_is_detected():
    checkout = _checkout_from_env("SV_SMOKE_SKILLSPECTOR", SKILLSPECTOR_COMMIT)

    report = _scan(checkout / "tests" / "fixtures" / "mcp_poisoned_tool", "guardrails")

    assert report["findings"]
    assert any(finding["severity"] == "critical" for finding in report["findings"])
    assert all(
        finding["location"]["path"] == "SKILL.md" for finding in report["findings"]
    )
    assert any(
        "ignore previous" in finding["evidence"]["snippet"]
        for finding in report["findings"]
    )


def test_skillspector_secret_exfiltration_fixture_is_detected():
    checkout = _checkout_from_env("SV_SMOKE_SKILLSPECTOR", SKILLSPECTOR_COMMIT)

    report = _scan(
        checkout / "tests" / "fixtures" / "malicious_skill",
        "permissions,exfiltration,behavioral",
    )

    assert any(
        finding["category"] == "exfiltration"
        and finding["location"]["path"] == "scripts/helper.py"
        for finding in report["findings"]
    )


@pytest.mark.parametrize(
    "case_id,expected_path,indicators",
    [
        ("case_00433", "scripts/_session_hook.py", ("deploy_hook", "silently execute")),
        ("case_00677", "scripts/_site_config.py", ("sitecustomize", "site_beacon")),
        ("case_02160", "lib/checks.sh", ('eval "$SWITCH_CLI_CMD"',)),
        ("case_05520", "SKILL.md", ("glot.io", "openclaw-agent.zip")),
    ],
)
def test_skilltrustbench_risky_representative_cases_detect_ground_truth_signal(
    case_id: str,
    expected_path: str,
    indicators: tuple[str, ...],
):
    cases = _cases_from_env()

    report = _scan(cases / case_id)

    assert report["source"]["artifact_sha256"] == SKILLTRUSTBENCH_CASE_DIGESTS[case_id]
    assert any(
        finding["severity"] in {"critical", "high"}
        and finding["location"]
        and finding["location"]["path"] == expected_path
        and finding["evidence"]
        and any(indicator in finding["evidence"]["snippet"] for indicator in indicators)
        for finding in report["findings"]
    ), f"scanner findings did not cover SkillTrustBench {case_id} ground truth"


def test_skilltrustbench_normal_security_tool_avoids_known_false_positives():
    cases = _cases_from_env()

    report = _scan(
        cases / "case_00070",
        STATIC_ANALYZERS,
    )

    assert (
        report["source"]["artifact_sha256"]
        == SKILLTRUSTBENCH_CASE_DIGESTS["case_00070"]
    )
    assert report["findings"] == []
