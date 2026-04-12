from skills_verified.core.models import (
    Severity, Category, Grade, Finding, CategoryScore, Report,
)


def test_severity_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"


def test_category_values():
    assert Category.CODE_SAFETY.value == "code_safety"
    assert Category.CVE.value == "cve"
    assert Category.GUARDRAILS.value == "guardrails"
    assert Category.PERMISSIONS.value == "permissions"
    assert Category.SUPPLY_CHAIN.value == "supply_chain"


def test_grade_values():
    assert Grade.A.value == "A"
    assert Grade.B.value == "B"
    assert Grade.C.value == "C"
    assert Grade.D.value == "D"
    assert Grade.F.value == "F"


def test_finding_creation():
    f = Finding(
        title="Test finding",
        description="A test",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="foo.py",
        line_number=10,
        analyzer="test",
    )
    assert f.title == "Test finding"
    assert f.cve_id is None
    assert f.confidence == 1.0


def test_finding_with_cve():
    f = Finding(
        title="CVE found",
        description="desc",
        severity=Severity.CRITICAL,
        category=Category.CVE,
        file_path=None,
        line_number=None,
        analyzer="cve",
        cve_id="CVE-2024-1234",
        confidence=0.9,
    )
    assert f.cve_id == "CVE-2024-1234"
    assert f.confidence == 0.9


def test_category_score_creation():
    cs = CategoryScore(
        category=Category.CODE_SAFETY,
        score=85,
        grade=Grade.B,
        findings_count=3,
        critical_count=0,
        high_count=1,
    )
    assert cs.score == 85
    assert cs.grade == Grade.B


def test_report_creation():
    r = Report(
        repo_url="https://github.com/test/repo",
        overall_score=82,
        overall_grade=Grade.B,
        categories=[],
        findings=[],
        analyzers_used=["pattern"],
        llm_used=False,
        scan_duration_seconds=1.5,
    )
    assert r.overall_grade == Grade.B
    assert r.llm_used is False
