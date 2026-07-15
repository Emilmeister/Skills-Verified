import threading
from pathlib import Path

import pytest

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import (
    AnalyzerRunStatus,
    Category,
    Diagnostic,
    DiagnosticLevel,
    Finding,
    FindingVerification,
    ScanStatus,
    Severity,
    VerificationStatus,
)
from skills_verified.core.pipeline import Pipeline, _add_co_located_deterministic_rules
from skills_verified.output.json_report import report_to_json


class FakeAnalyzer(Analyzer):
    name = "fake"

    def __init__(self, findings: list[Finding] | None = None, available: bool = True):
        self._findings = findings or []
        self._available = available

    def is_available(self) -> bool:
        return self._available

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        return self._findings


class CrashingAnalyzer(Analyzer):
    name = "crasher"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        raise RuntimeError("boom")


class DiagnosticAnalyzer(FakeAnalyzer):
    name = "diagnostic"

    @property
    def diagnostics(self) -> list[Diagnostic]:
        return [Diagnostic("degraded_check", "One sub-check could not run")]


class AbsoluteLocationAnalyzer(Analyzer):
    name = "absolute_location"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        return [
            Finding(
                title="normalized location",
                description="location identity must not depend on the staging path",
                severity=Severity.LOW,
                category=Category.CODE_SAFETY,
                file_path=str(repo_path / "x.py"),
                line_number=1,
                analyzer=self.name,
            )
        ]


class BarrierAnalyzer(Analyzer):
    def __init__(self, name: str, barrier: threading.Barrier):
        self.name = name
        self.barrier = barrier

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        self.barrier.wait(timeout=2)
        return []


def test_pipeline_empty_analyzers_is_failed(tmp_path: Path):
    report = Pipeline(analyzers=[]).run(tmp_path, repo_url="test")

    assert report.scan.status == ScanStatus.FAILED
    assert report.findings == []
    assert report.analyzer_runs == []
    assert any(
        diagnostic.code == "no_analyzers_selected" for diagnostic in report.diagnostics
    )


def test_pipeline_runs_analyzers_concurrently_and_preserves_report_order(
    tmp_path: Path,
):
    barrier = threading.Barrier(2)
    messages: list[str] = []

    report = Pipeline(
        [BarrierAnalyzer("first", barrier), BarrierAnalyzer("second", barrier)],
        concurrency=2,
        progress=messages.append,
    ).run(tmp_path, repo_url="test")

    assert [run.name for run in report.analyzer_runs] == ["first", "second"]
    assert all(
        run.status == AnalyzerRunStatus.COMPLETED for run in report.analyzer_runs
    )
    assert any("[1/2] first: started" in message for message in messages)
    assert any("[2/2] second: started" in message for message in messages)
    assert any("first: completed" in message for message in messages)
    assert any("second: completed" in message for message in messages)


@pytest.mark.parametrize("concurrency", [0, 19])
def test_pipeline_rejects_invalid_analyzer_concurrency(concurrency: int):
    with pytest.raises(ValueError, match="analyzer concurrency"):
        Pipeline([], concurrency=concurrency)


def test_pipeline_collects_findings_and_evidence(tmp_path: Path):
    (tmp_path / "x.py").write_text("dangerous_call()\n", encoding="utf-8")
    finding = Finding(
        title="bad eval",
        description="eval usage",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="x.py",
        line_number=1,
        analyzer="fake",
    )

    report = Pipeline(analyzers=[FakeAnalyzer(findings=[finding])]).run(
        tmp_path,
        repo_url="test",
    )

    assert report.scan.status == ScanStatus.COMPLETE
    assert report.findings == [finding]
    assert finding.evidence is not None
    assert finding.evidence.snippet == "dangerous_call()"
    assert report.analyzer_runs[0].status == AnalyzerRunStatus.COMPLETED
    assert report.analyzer_runs[0].findings_count == 1


def test_pipeline_admits_file_larger_than_two_mib_within_total_budget(tmp_path: Path):
    large = tmp_path / "large.txt"
    large.write_bytes(b"x" * (2 * 1024 * 1024 + 1))

    report = Pipeline(analyzers=[FakeAnalyzer()]).run(
        tmp_path,
        repo_url="test",
        max_total_bytes=3 * 1024 * 1024,
    )

    assert report.scan.status == ScanStatus.COMPLETE
    assert report.scope.files_scanned == 1
    assert report.scope.files_skipped == 0
    assert report.scope.bytes_scanned == large.stat().st_size


def test_pipeline_internal_symlink_alias_does_not_degrade_covered_target(
    tmp_path: Path,
):
    (tmp_path / "shared.txt").write_text("shared", encoding="utf-8")
    (tmp_path / "alias.txt").symlink_to("shared.txt")

    report = Pipeline(analyzers=[FakeAnalyzer()]).run(tmp_path, repo_url="test")

    assert report.scan.status == ScanStatus.COMPLETE
    assert report.scope.files_scanned == 1
    assert report.scope.files_skipped == 0
    diagnostic = next(
        item
        for item in report.diagnostics
        if item.code == "repository_internal_symlink_alias"
    )
    assert diagnostic.level == DiagnosticLevel.INFO
    assert diagnostic.details == {
        "reason": "internal_symlink_alias",
        "count": 1,
        "aliases": [{"path": "alias.txt", "target": "shared.txt"}],
    }


def test_pipeline_records_overlapping_deterministic_rules_for_llm_candidate(
    tmp_path: Path,
):
    (tmp_path / "x.py").write_text("dangerous_call()\n", encoding="utf-8")
    deterministic = Finding(
        title="Dangerous call",
        description="Deterministic match",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="x.py",
        line_number=1,
        analyzer="pattern",
        rule_id="SV-PATTERN-DANGEROUS",
    )
    candidate = Finding(
        title="Dangerous call candidate",
        description="LLM candidate",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="x.py",
        line_number=1,
        analyzer="llm",
        verification=FindingVerification(
            candidate_id="sha256:" + "d" * 64,
            status=VerificationStatus.CORROBORATED,
            method="llm_adversarial_consensus",
            attempts=3,
            agreements=2,
            disagreements=1,
            inconclusive=0,
            evidence_matched=True,
            requested_model="test",
            candidate_prompt_sha256="sha256:" + "a" * 64,
            verification_prompt_sha256="sha256:" + "b" * 64,
            generation_response_sha256="sha256:" + "c" * 64,
        ),
    )
    deterministic_analyzer = FakeAnalyzer([deterministic])
    llm_analyzer = FakeAnalyzer([candidate])
    llm_analyzer.name = "llm"

    report = Pipeline([deterministic_analyzer, llm_analyzer]).run(
        tmp_path, repo_url="test"
    )

    llm_finding = next(
        finding for finding in report.findings if finding.analyzer == "llm"
    )
    assert llm_finding.verification is not None
    assert llm_finding.verification.co_located_deterministic_rule_ids == [
        "SV-PATTERN-DANGEROUS"
    ]


def test_pipeline_does_not_match_findings_below_eighty_percent_line_overlap(
    tmp_path: Path,
):
    (tmp_path / "x.py").write_text("one\ntwo\nthree\nfour\nfive\n", encoding="utf-8")
    deterministic = Finding(
        title="First range",
        description="Deterministic match",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="x.py",
        line_number=1,
        end_line=4,
        analyzer="pattern",
        rule_id="SV-PATTERN-RANGE",
    )
    candidate = Finding(
        title="Second range",
        description="LLM candidate",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="x.py",
        line_number=4,
        end_line=5,
        analyzer="llm",
        verification=FindingVerification(
            candidate_id="sha256:" + "d" * 64,
            status=VerificationStatus.UNVERIFIED,
            method="llm_adversarial_consensus",
            attempts=0,
            agreements=0,
            disagreements=0,
            inconclusive=0,
            evidence_matched=True,
            requested_model="test",
            candidate_prompt_sha256="sha256:" + "a" * 64,
            verification_prompt_sha256="sha256:" + "b" * 64,
            generation_response_sha256="sha256:" + "c" * 64,
        ),
    )
    deterministic_analyzer = FakeAnalyzer([deterministic])
    llm_analyzer = FakeAnalyzer([candidate])
    llm_analyzer.name = "llm"

    report = Pipeline([deterministic_analyzer, llm_analyzer]).run(
        tmp_path, repo_url="test"
    )

    llm_finding = next(
        finding for finding in report.findings if finding.analyzer == "llm"
    )
    assert llm_finding.verification is not None
    assert llm_finding.verification.co_located_deterministic_rule_ids == []


def test_pipeline_does_not_match_point_finding_inside_broad_llm_range(tmp_path: Path):
    (tmp_path / "x.py").write_text("line\n" * 20, encoding="utf-8")
    deterministic = Finding(
        title="Point finding",
        description="Deterministic match",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="x.py",
        line_number=10,
        analyzer="pattern",
        rule_id="SV-PATTERN-POINT",
    )
    candidate = Finding(
        title="Broad range",
        description="LLM candidate",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="x.py",
        line_number=1,
        end_line=20,
        analyzer="llm",
        verification=FindingVerification(
            candidate_id="sha256:" + "d" * 64,
            status=VerificationStatus.UNVERIFIED,
            method="llm_adversarial_consensus",
            attempts=0,
            agreements=0,
            disagreements=0,
            inconclusive=0,
            evidence_matched=True,
            requested_model="test",
            candidate_prompt_sha256="sha256:" + "a" * 64,
            verification_prompt_sha256="sha256:" + "b" * 64,
            generation_response_sha256="sha256:" + "c" * 64,
        ),
    )
    deterministic_analyzer = FakeAnalyzer([deterministic])
    llm_analyzer = FakeAnalyzer([candidate])
    llm_analyzer.name = "llm"

    report = Pipeline([deterministic_analyzer, llm_analyzer]).run(
        tmp_path, repo_url="test"
    )

    llm_finding = next(
        finding for finding in report.findings if finding.analyzer == "llm"
    )
    assert llm_finding.verification is not None
    assert llm_finding.verification.co_located_deterministic_rule_ids == []


@pytest.mark.parametrize(
    ("candidate_path", "candidate_category"),
    [("other.py", Category.CODE_SAFETY), ("x.py", Category.EXFILTRATION)],
)
def test_co_location_requires_same_path_and_category(
    candidate_path: str,
    candidate_category: Category,
):
    deterministic = Finding(
        title="Deterministic",
        description="Rule match",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="x.py",
        line_number=1,
        analyzer="pattern",
        rule_id="SV-PATTERN-POINT",
    )
    candidate = Finding(
        title="Candidate",
        description="LLM claim",
        severity=Severity.HIGH,
        category=candidate_category,
        file_path=candidate_path,
        line_number=1,
        analyzer="llm",
        verification=FindingVerification(
            candidate_id="sha256:" + "d" * 64,
            status=VerificationStatus.UNVERIFIED,
            method="llm_adversarial_consensus",
            attempts=0,
            agreements=0,
            disagreements=0,
            inconclusive=0,
            evidence_matched=True,
            requested_model="test",
            candidate_prompt_sha256="sha256:" + "a" * 64,
            verification_prompt_sha256="sha256:" + "b" * 64,
            generation_response_sha256="sha256:" + "c" * 64,
        ),
    )

    _add_co_located_deterministic_rules([deterministic, candidate])

    assert candidate.verification.co_located_deterministic_rule_ids == []


def test_pipeline_records_unavailable_analyzer(tmp_path: Path):
    report = Pipeline(analyzers=[FakeAnalyzer(available=False)]).run(
        tmp_path,
        repo_url="test",
    )

    assert report.scan.status == ScanStatus.FAILED
    assert report.analyzer_runs[0].status == AnalyzerRunStatus.SKIPPED
    assert report.analyzer_runs[0].reason == "not_available"


def test_pipeline_records_crashing_analyzer(tmp_path: Path):
    report = Pipeline(analyzers=[CrashingAnalyzer()]).run(tmp_path, repo_url="test")

    assert report.scan.status == ScanStatus.FAILED
    assert report.findings == []
    assert report.analyzer_runs[0].status == AnalyzerRunStatus.FAILED
    assert report.analyzer_runs[0].reason == "analyzer_crashed:RuntimeError"
    assert any(
        diagnostic.code == "analyzer_failed"
        and diagnostic.level == DiagnosticLevel.ERROR
        and diagnostic.analyzer == "crasher"
        for diagnostic in report.diagnostics
    )


def test_pipeline_is_partial_when_one_analyzer_is_skipped(tmp_path: Path):
    report = Pipeline(
        analyzers=[FakeAnalyzer(), FakeAnalyzer(available=False)],
    ).run(tmp_path, repo_url="test")

    assert report.scan.status == ScanStatus.PARTIAL
    assert [run.status for run in report.analyzer_runs] == [
        AnalyzerRunStatus.COMPLETED,
        AnalyzerRunStatus.SKIPPED,
    ]


@pytest.mark.parametrize("with_finding", [False, True])
def test_sole_analyzer_with_typed_diagnostic_is_partial_not_failed(
    tmp_path: Path,
    with_finding: bool,
):
    findings = []
    if with_finding:
        findings.append(
            Finding(
                title="Detected fact",
                description="A deterministic finding",
                severity=Severity.MEDIUM,
                category=Category.CODE_SAFETY,
                file_path=None,
                line_number=None,
                analyzer="diagnostic",
            )
        )

    report = Pipeline([DiagnosticAnalyzer(findings=findings)]).run(
        tmp_path,
        repo_url="test",
    )

    assert report.scan.status == ScanStatus.PARTIAL
    assert report.analyzer_runs[0].status == AnalyzerRunStatus.PARTIAL
    assert report.analyzer_runs[0].findings_count == len(findings)
    assert report.analyzer_runs[0].reason == "analyzer_reported_diagnostics"
    assert any(diagnostic.code == "degraded_check" for diagnostic in report.diagnostics)


def test_pipeline_records_scope_source_and_duration(tmp_path: Path):
    (tmp_path / "SKILL.md").write_text("# example\n", encoding="utf-8")

    report = Pipeline(analyzers=[FakeAnalyzer()]).run(tmp_path, repo_url="test")

    assert report.scan.duration_ms >= 0
    assert report.source.input == "test"
    assert len(report.source.artifact_sha256) == 64
    assert report.scope.files_scanned == 1
    assert report.scope.bytes_scanned > 0


def test_artifact_digest_has_unambiguous_file_boundaries(tmp_path: Path):
    one_file = tmp_path / "one-file"
    two_files = tmp_path / "two-files"
    one_file.mkdir()
    two_files.mkdir()
    (one_file / "a").write_bytes(b"X\0b\0Y")
    (two_files / "a").write_bytes(b"X")
    (two_files / "b").write_bytes(b"Y")

    first = Pipeline([FakeAnalyzer()]).run(one_file, repo_url="one")
    second = Pipeline([FakeAnalyzer()]).run(two_files, repo_url="two")

    assert first.source.artifact_sha256 != second.source.artifact_sha256


def test_fingerprint_is_stable_after_absolute_staging_path_is_normalized(
    tmp_path: Path,
):
    (tmp_path / "x.py").write_text("pass\n", encoding="utf-8")

    first = Pipeline([AbsoluteLocationAnalyzer()]).run(tmp_path, repo_url="test")
    second = Pipeline([AbsoluteLocationAnalyzer()]).run(tmp_path, repo_url="test")

    assert first.findings[0].file_path == "x.py"
    assert first.findings[0].fingerprint == second.findings[0].fingerprint


def test_input_failure_redacts_remote_credentials_and_query():
    source = "https://user:super-secret@example.com/repo.git?token=also-secret"

    report = Pipeline([FakeAnalyzer()]).input_failure(
        source,
        ValueError(f"Could not fetch {source}"),
    )
    rendered = report_to_json(report)

    assert report.source.input == "https://example.com/repo.git"
    assert "super-secret" not in rendered
    assert "also-secret" not in rendered
