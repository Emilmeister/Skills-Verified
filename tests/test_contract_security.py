import json
from pathlib import Path

from click.testing import CliRunner

from skills_verified.cli import main
from skills_verified.analyzers.guardrails_analyzer import GuardrailsAnalyzer
from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import (
    AnalyzerRunStatus,
    Category,
    Evidence,
    Finding,
    ScanStatus,
    Severity,
)
from skills_verified.core.pipeline import Pipeline
from skills_verified.output.json_report import report_to_dict


class _CompletedAnalyzer(Analyzer):
    name = "completed"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        return []


class _UnavailableAnalyzer(Analyzer):
    name = "unavailable"

    def is_available(self) -> bool:
        return False

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        raise AssertionError("an unavailable analyzer must not run")


class _CrashingAnalyzer(Analyzer):
    name = "crashing"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        raise RuntimeError("controlled test failure")


class _NaiveRglobAnalyzer(Analyzer):
    """Deliberately ignores repository trust boundaries."""

    name = "naive_rglob"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        for path in repo_path.rglob("*"):
            if not path.is_file():
                continue
            content = path.read_text(errors="ignore")
            if "OUTSIDE_CANARY_SECRET" in content:
                findings.append(
                    Finding(
                        title="Secret read",
                        description=content,
                        severity=Severity.CRITICAL,
                        category=Category.EXFILTRATION,
                        file_path=str(path.relative_to(repo_path)),
                        line_number=1,
                        analyzer=self.name,
                        evidence=Evidence(kind="source", snippet=content),
                    )
                )
        return findings


def _policy_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {
            nested for child in value.values() for nested in _policy_keys(child)
        }
    if isinstance(value, list):
        return {nested for child in value for nested in _policy_keys(child)}
    return set()


def test_cli_emits_one_policy_free_json_document(tmp_path: Path):
    (tmp_path / "SKILL.md").write_text(
        "---\nname: example\ndescription: A harmless example skill\n---\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        main, [str(tmp_path), "--only", "guardrails", "--compact"]
    )

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["schema_version"] == "1.0"
    assert report["scan"]["status"] == "complete"
    assert report["analyzer_runs"][0]["version"]
    assert report["analyzer_runs"] == [
        {
            "duration_ms": report["analyzer_runs"][0]["duration_ms"],
            "findings_count": 0,
            "name": "guardrails",
            "reason": None,
            "status": "completed",
            "version": report["analyzer_runs"][0]["version"],
        }
    ]
    forbidden = {"score", "grade", "trust_score", "publish", "allow", "deny", "verdict"}
    assert forbidden.isdisjoint(_policy_keys(report))


def test_pipeline_reports_unavailable_analyzer_as_partial(tmp_path: Path):
    report = Pipeline([_CompletedAnalyzer(), _UnavailableAnalyzer()]).run(
        tmp_path,
        repo_url=str(tmp_path),
    )

    assert report.scan.status == ScanStatus.PARTIAL
    assert [(run.name, run.status, run.reason) for run in report.analyzer_runs] == [
        ("completed", AnalyzerRunStatus.COMPLETED, None),
        ("unavailable", AnalyzerRunStatus.SKIPPED, "not_available"),
    ]


def test_pipeline_reports_crash_instead_of_clean_scan(tmp_path: Path):
    report = Pipeline([_CrashingAnalyzer()]).run(tmp_path, repo_url=str(tmp_path))
    serialized = report_to_dict(report)

    assert report.scan.status == ScanStatus.FAILED
    assert report.analyzer_runs[0].status == AnalyzerRunStatus.FAILED
    assert report.analyzer_runs[0].reason == "analyzer_crashed:RuntimeError"
    assert serialized["findings"] == []
    assert any(
        diagnostic["code"] == "analyzer_failed"
        and diagnostic["analyzer"] == "crashing"
        and diagnostic["level"] == "error"
        for diagnostic in serialized["diagnostics"]
    )


def test_cli_rejects_unknown_analyzer_name(tmp_path: Path):
    result = CliRunner().invoke(main, [str(tmp_path), "--only", "guardrailz"])

    assert result.exit_code == 2
    assert "unknown analyzer name(s): guardrailz" in result.output


def test_finding_fingerprint_is_stable():
    fields = {
        "title": "Instruction override detected",
        "description": "The skill attempts to replace host instructions.",
        "severity": Severity.CRITICAL,
        "category": Category.GUARDRAILS,
        "file_path": "SKILL.md",
        "line_number": 12,
        "analyzer": "guardrails",
        "evidence": Evidence(kind="source", snippet="ignore previous instructions"),
    }

    first = Finding(**fields)
    second = Finding(**fields)

    assert first.rule_id == second.rule_id
    assert first.fingerprint == second.fingerprint
    assert first.fingerprint.startswith("sha256:")


def test_pipeline_staging_blocks_naive_analyzer_symlink_escape(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SKILL.md").write_text("# Safe input\n", encoding="utf-8")
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("OUTSIDE_CANARY_SECRET", encoding="utf-8")
    (repo / "leak.txt").symlink_to(outside)

    report = Pipeline([_NaiveRglobAnalyzer()]).run(repo, repo_url=str(repo))
    serialized = report_to_dict(report)

    assert report.scan.status == ScanStatus.PARTIAL
    assert report.findings == []
    assert report.analyzer_runs[0].status == AnalyzerRunStatus.COMPLETED
    assert any(
        diagnostic["code"] == "repository_path_skipped"
        and diagnostic["path"] == "leak.txt"
        and diagnostic["details"]["reason"] == "symlink_outside_repository"
        for diagnostic in serialized["diagnostics"]
    )
    assert "OUTSIDE_CANARY_SECRET" not in json.dumps(serialized)


def test_invalid_skill_metadata_makes_scan_partial(tmp_path: Path):
    (tmp_path / "SKILL.md").write_text(
        "---\nname: [not-a-string]\ndescription:\n---\n",
        encoding="utf-8",
    )

    report = Pipeline([GuardrailsAnalyzer()]).run(tmp_path, repo_url=str(tmp_path))

    assert report.scan.status == ScanStatus.PARTIAL
    assert any(
        diagnostic.code == "skill_metadata_invalid" for diagnostic in report.diagnostics
    )
