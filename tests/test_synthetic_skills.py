from pathlib import Path

import pytest

from skills_verified.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skills_verified.analyzers.config_injection_analyzer import ConfigInjectionAnalyzer
from skills_verified.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from skills_verified.analyzers.guardrails_analyzer import GuardrailsAnalyzer
from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.analyzers.privilege_analyzer import PrivilegeAnalyzer
from skills_verified.analyzers.reverse_shell_analyzer import ReverseShellAnalyzer
from skills_verified.analyzers.supply_chain_analyzer import SupplyChainAnalyzer
from skills_verified.core.models import Category, Severity
from skills_verified.core.pipeline import Pipeline


SYNTHETIC_ROOT = Path(__file__).parent / "fixtures" / "synthetic"


def _scan(name: str):
    return Pipeline(
        [
            PatternAnalyzer(),
            GuardrailsAnalyzer(),
            SupplyChainAnalyzer(),
            ReverseShellAnalyzer(),
            ExfiltrationAnalyzer(),
            BehavioralAnalyzer(),
            ConfigInjectionAnalyzer(),
            PrivilegeAnalyzer(),
        ]
    ).run(SYNTHETIC_ROOT / name, repo_url=f"test://synthetic/{name}")


def test_vulnerable_synthetic_skill_covers_independent_attack_classes():
    report = _scan("vulnerable")
    analyzers = {finding.analyzer for finding in report.findings}
    rule_ids = {finding.rule_id for finding in report.findings}

    assert {
        "pattern",
        "guardrails",
        "supply_chain",
        "reverse_shell",
        "exfiltration",
        "behavioral",
        "config_injection",
        "privilege",
    } <= analyzers
    assert "SV-DATAFLOW-SENSITIVE-NETWORK" in rule_ids
    assert any(
        finding.title == "Subprocess with shell=True" for finding in report.findings
    )
    assert any(
        finding.category == Category.CODE_SAFETY
        and finding.severity == Severity.CRITICAL
        for finding in report.findings
    )


def test_safe_synthetic_skill_has_no_security_findings():
    report = _scan("safe")

    assert report.findings == []


@pytest.mark.parametrize("name", ["safe", "vulnerable"])
def test_synthetic_skill_findings_have_bounded_evidence(name: str):
    report = _scan(name)
    roots = [Path(root) for root in report.scope.skill_roots]

    assert roots
    for finding in report.findings:
        if finding.file_path is not None:
            assert not Path(finding.file_path).is_absolute()
            assert ".." not in Path(finding.file_path).parts
        if finding.evidence is not None:
            assert len(finding.evidence.snippet) <= 500
