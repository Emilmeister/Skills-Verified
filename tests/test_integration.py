
from click.testing import CliRunner

from skills_verified.cli import main
from skills_verified.core.models import Category, Severity
from skills_verified.core.pipeline import Pipeline
from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.analyzers.guardrails_analyzer import GuardrailsAnalyzer
from skills_verified.analyzers.permissions_analyzer import PermissionsAnalyzer
from skills_verified.analyzers.supply_chain_analyzer import SupplyChainAnalyzer


def test_full_pipeline_on_fake_repo(fake_repo_path):
    analyzers = [
        PatternAnalyzer(),
        GuardrailsAnalyzer(),
        PermissionsAnalyzer(),
        SupplyChainAnalyzer(),
    ]
    pipeline = Pipeline(analyzers=analyzers)
    report = pipeline.run(repo_path=fake_repo_path, repo_url="test://fake")

    assert len(report.findings) > 0
    assert report.overall_score < 100
    assert len(report.categories) == 6

    categories_with_findings = {f.category for f in report.findings}
    assert Category.CODE_SAFETY in categories_with_findings
    assert Category.GUARDRAILS in categories_with_findings
    assert Category.SUPPLY_CHAIN in categories_with_findings
    severities = {f.severity for f in report.findings}
    assert Severity.CRITICAL in severities or Severity.HIGH in severities


def test_full_cli_on_fake_repo(fake_repo_path, tmp_path):
    out_file = tmp_path / "integration_report.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        str(fake_repo_path),
        "--output", str(out_file),
        "--skip", "bandit,semgrep,cve,llm,container",
    ])
    assert result.exit_code == 0
    assert "TRUST SCORE" in result.output
    assert out_file.exists()

    import json
    data = json.loads(out_file.read_text())
    assert "overall_grade" in data
    assert "findings" in data
    assert len(data["findings"]) > 0
