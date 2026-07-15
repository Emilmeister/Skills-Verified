from io import StringIO

from rich.console import Console

from skills_verified.core.models import (
    AnalyzerRun,
    AnalyzerRunStatus,
    Category,
    Finding,
    ScanInfo,
    ScannerInfo,
    ScanReport,
    ScanStatus,
    ScopeInfo,
    Severity,
    SourceInfo,
)
from skills_verified.output.console import render_report


def _make_report() -> ScanReport:
    return ScanReport(
        scan=ScanInfo(
            status=ScanStatus.PARTIAL,
            started_at="2026-07-13T12:00:00Z",
            duration_ms=35,
            scanner=ScannerInfo("skills-verified", "1.0.0", "2026.07.13"),
        ),
        source=SourceInfo("https://github.com/test/repo", None, "a" * 64),
        scope=ScopeInfo(["."], 3, 1, 200),
        platforms=[],
        analyzer_runs=[
            AnalyzerRun("pattern", AnalyzerRunStatus.COMPLETED, 4, 1),
            AnalyzerRun("semgrep", AnalyzerRunStatus.SKIPPED, 0, 0, "not_available"),
        ],
        findings=[
            Finding(
                title="Unsafe eval() call",
                description="eval() usage detected",
                severity=Severity.HIGH,
                category=Category.CODE_SAFETY,
                file_path="danger.py",
                line_number=5,
                analyzer="pattern",
            ),
        ],
        diagnostics=[],
    )


def _render() -> str:
    buffer = StringIO()
    render_report(
        _make_report(),
        console=Console(file=buffer, color_system=None, width=100),
    )
    return buffer.getvalue()


def test_render_report_contains_execution_facts():
    output = _render()

    assert "Security Analyzer" in output
    assert "test/repo" in output
    assert "Execution status: partial" in output
    assert "3 files scanned, 1 skipped" in output
    assert "Scan duration: 35ms" in output


def test_render_report_contains_analyzer_status_and_reason():
    output = _render()

    assert "pattern" in output
    assert "completed" in output
    assert "semgrep" in output
    assert "not_available" in output


def test_render_report_contains_finding_evidence_location():
    output = _render()

    assert "Unsafe eval() call" in output
    assert "SV-PATTERN-" in output
    assert "danger.py:5" in output


def test_render_report_contains_no_policy_decision():
    output = _render().lower()

    assert "trust score" not in output
    assert "grade" not in output
    assert "publish" not in output
