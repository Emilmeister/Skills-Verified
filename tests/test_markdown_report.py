from pathlib import Path

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
from skills_verified.output.markdown_report import generate_markdown, save_markdown


def _make_report(*, findings: list[Finding] | None = None) -> ScanReport:
    if findings is None:
        findings = [
            Finding(
                title="Dangerous eval usage",
                description="eval() with untrusted input",
                severity=Severity.HIGH,
                category=Category.CODE_SAFETY,
                file_path="src/main.py",
                line_number=42,
                analyzer="pattern_analyzer",
                confidence=0.95,
            ),
        ]
    return ScanReport(
        scan=ScanInfo(
            status=ScanStatus.PARTIAL,
            started_at="2026-07-13T12:00:00Z",
            duration_ms=1500,
            scanner=ScannerInfo("skills-verified", "1.0.0", "2026.07.13"),
        ),
        source=SourceInfo("https://github.com/test/repo", None, "a" * 64),
        scope=ScopeInfo(["."], 10, 1, 1024),
        platforms=[],
        analyzer_runs=[
            AnalyzerRun("pattern_analyzer", AnalyzerRunStatus.COMPLETED, 5, 1),
            AnalyzerRun("semgrep", AnalyzerRunStatus.SKIPPED, 0, 0, "not_available"),
        ],
        findings=findings,
        diagnostics=[],
    )


def test_full_report_contains_execution_summary():
    markdown = generate_markdown(_make_report(), style="full")

    assert "## Skills Verified — Scan Report" in markdown
    assert "**Execution status:** `partial`" in markdown
    assert "**Duration:** 1500ms" in markdown
    assert "**Scope:** 10 scanned, 1 skipped" in markdown
    assert "| HIGH | 1 |" in markdown


def test_full_report_contains_analyzer_runs():
    markdown = generate_markdown(_make_report(), style="full")

    assert "### Analyzer execution" in markdown
    assert "| pattern_analyzer | completed | 1 |" in markdown
    assert "| semgrep | skipped | 0 | not_available |" in markdown


def test_full_report_contains_findings_without_verdict():
    markdown = generate_markdown(_make_report(), style="full")

    assert "| Severity | Rule | Title | Location | Confidence |" in markdown
    assert "Dangerous eval usage" in markdown
    assert "src/main.py:42" in markdown
    assert "0.95" in markdown
    assert "score" not in markdown.lower()
    assert "grade" not in markdown.lower()
    assert "publish" not in markdown.lower()


def test_summary_omits_finding_table_but_reports_count():
    markdown = generate_markdown(_make_report(), style="summary")

    assert "| Severity | Rule | Title | Location | Confidence |" not in markdown
    assert "> 1 findings reported." in markdown


def test_no_findings_omits_finding_table():
    markdown = generate_markdown(_make_report(findings=[]), style="full")

    assert "| Severity | Rule | Title | Location | Confidence |" not in markdown
    assert "| HIGH | 0 |" in markdown


def test_finding_without_file_uses_na_location():
    finding = Finding(
        title="Suspicious pattern",
        description="Suspicious behavior detected",
        severity=Severity.MEDIUM,
        category=Category.CODE_SAFETY,
        file_path=None,
        line_number=None,
        analyzer="behavioral_analyzer",
    )

    markdown = generate_markdown(_make_report(findings=[finding]), style="full")

    assert "| N/A |" in markdown


def test_untrusted_table_content_is_escaped():
    finding = Finding(
        title="Injected | title\nnew row",
        description="desc",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="unsafe|path.py",
        line_number=1,
        analyzer="test",
    )

    markdown = generate_markdown(_make_report(findings=[finding]), style="full")

    assert "Injected &#124; title new row" in markdown
    assert "unsafe&#124;path.py:1" in markdown


def test_save_markdown(tmp_path: Path):
    out_path = tmp_path / "report.md"

    save_markdown(_make_report(), "full", out_path)

    assert "## Skills Verified — Scan Report" in out_path.read_text(encoding="utf-8")
