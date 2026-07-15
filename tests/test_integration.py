import json
from pathlib import Path

from click.testing import CliRunner

from skills_verified.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skills_verified.analyzers.config_injection_analyzer import ConfigInjectionAnalyzer
from skills_verified.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from skills_verified.analyzers.guardrails_analyzer import GuardrailsAnalyzer
from skills_verified.analyzers.known_threats_analyzer import KnownThreatsAnalyzer
from skills_verified.analyzers.mcp_analyzer import MCPAnalyzer
from skills_verified.analyzers.metadata_analyzer import MetadataAnalyzer
from skills_verified.analyzers.obfuscation_analyzer import ObfuscationAnalyzer
from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.analyzers.permissions_analyzer import PermissionsAnalyzer
from skills_verified.analyzers.privilege_analyzer import PrivilegeAnalyzer
from skills_verified.analyzers.reverse_shell_analyzer import ReverseShellAnalyzer
from skills_verified.analyzers.supply_chain_analyzer import SupplyChainAnalyzer
from skills_verified.cli import main
from skills_verified.core.models import (
    AnalyzerRunStatus,
    Category,
    ScanStatus,
    Severity,
)
from skills_verified.core.pipeline import Pipeline


def _builtin_analyzers():
    return [
        PatternAnalyzer(),
        GuardrailsAnalyzer(),
        PermissionsAnalyzer(),
        SupplyChainAnalyzer(),
        ObfuscationAnalyzer(),
        ReverseShellAnalyzer(),
        ExfiltrationAnalyzer(),
        BehavioralAnalyzer(),
        MCPAnalyzer(),
        ConfigInjectionAnalyzer(),
        MetadataAnalyzer(),
        KnownThreatsAnalyzer(),
        PrivilegeAnalyzer(),
    ]


def test_full_pipeline_on_fake_repo(fake_repo_path: Path):
    report = Pipeline(analyzers=_builtin_analyzers()).run(
        repo_path=fake_repo_path,
        repo_url="test://fake",
    )

    assert report.scan.status == ScanStatus.COMPLETE
    assert report.source.input == "test://fake"
    assert report.scope.files_scanned > 0
    assert report.scope.skill_roots == ["."]
    assert all(
        run.status == AnalyzerRunStatus.COMPLETED for run in report.analyzer_runs
    )
    assert len(report.findings) > 0

    categories_with_findings = {finding.category for finding in report.findings}
    assert Category.CODE_SAFETY in categories_with_findings
    assert Category.GUARDRAILS in categories_with_findings
    assert Category.SUPPLY_CHAIN in categories_with_findings

    severities = {finding.severity for finding in report.findings}
    assert Severity.CRITICAL in severities or Severity.HIGH in severities
    assert all(finding.rule_id and finding.fingerprint for finding in report.findings)


def test_full_cli_on_fake_repo_emits_and_saves_same_json(
    fake_repo_path: Path,
    tmp_path: Path,
):
    out_file = tmp_path / "integration_report.json"
    result = CliRunner().invoke(
        main,
        [
            str(fake_repo_path),
            "--output",
            str(out_file),
            "--skip",
            "bandit,semgrep,cve,llm",
            "--compact",
        ],
    )

    assert result.exit_code == 0, result.output
    stdout_report = json.loads(result.output)
    file_report = json.loads(out_file.read_text(encoding="utf-8"))
    assert stdout_report == file_report
    assert stdout_report["scan"]["status"] == "complete"
    assert stdout_report["summary"]["findings_total"] > 0
    assert stdout_report["findings"]
    assert "overall_grade" not in stdout_report
    assert "overall_score" not in stdout_report
