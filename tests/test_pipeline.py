from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import (
    Category, Finding, Grade, Severity,
)
from skills_verified.core.pipeline import Pipeline


class FakeAnalyzer(Analyzer):
    name = "fake"

    def __init__(self, findings: list[Finding] | None = None, available: bool = True):
        self._findings = findings or []
        self._available = available

    def is_available(self) -> bool:
        return self._available

    def analyze(self, repo_path: Path) -> list[Finding]:
        return self._findings


class CrashingAnalyzer(Analyzer):
    name = "crasher"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path) -> list[Finding]:
        raise RuntimeError("boom")


def test_pipeline_empty_analyzers():
    pipeline = Pipeline(analyzers=[])
    report = pipeline.run(Path("/tmp"), repo_url="test")
    assert report.overall_grade == Grade.A
    assert report.findings == []


def test_pipeline_collects_findings():
    finding = Finding(
        title="bad eval",
        description="eval usage",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="x.py",
        line_number=1,
        analyzer="fake",
    )
    pipeline = Pipeline(analyzers=[FakeAnalyzer(findings=[finding])])
    report = pipeline.run(Path("/tmp"), repo_url="test")
    assert len(report.findings) == 1
    assert report.findings[0].title == "bad eval"
    assert "fake" in report.analyzers_used


def test_pipeline_skips_unavailable():
    pipeline = Pipeline(analyzers=[FakeAnalyzer(available=False)])
    report = pipeline.run(Path("/tmp"), repo_url="test")
    assert report.analyzers_used == []


def test_pipeline_handles_crashing_analyzer():
    pipeline = Pipeline(analyzers=[CrashingAnalyzer()])
    report = pipeline.run(Path("/tmp"), repo_url="test")
    assert report.findings == []
    assert "crasher" in report.analyzers_used


def test_pipeline_measures_duration():
    pipeline = Pipeline(analyzers=[])
    report = pipeline.run(Path("/tmp"), repo_url="test")
    assert report.scan_duration_seconds >= 0
