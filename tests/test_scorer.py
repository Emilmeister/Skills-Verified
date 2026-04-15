from skills_verified.core.models import (
    Severity, Category, Grade, Finding,
)
from skills_verified.core.scorer import Scorer


def _make_finding(severity: Severity, category: Category) -> Finding:
    return Finding(
        title="test",
        description="test",
        severity=severity,
        category=category,
        file_path="test.py",
        line_number=1,
        analyzer="test",
    )


def test_no_findings_gives_all_A():
    scorer = Scorer()
    categories = scorer.score_categories([])
    for cs in categories:
        assert cs.score == 100
        assert cs.grade == Grade.A


def test_one_critical_finding():
    findings = [_make_finding(Severity.CRITICAL, Category.CODE_SAFETY)]
    scorer = Scorer()
    categories = scorer.score_categories(findings)
    code_safety = next(c for c in categories if c.category == Category.CODE_SAFETY)
    assert code_safety.score == 75  # 100 - 25
    assert code_safety.grade == Grade.C
    assert code_safety.critical_count == 1


def test_score_does_not_go_below_zero():
    findings = [_make_finding(Severity.CRITICAL, Category.CVE) for _ in range(10)]
    scorer = Scorer()
    categories = scorer.score_categories(findings)
    cve = next(c for c in categories if c.category == Category.CVE)
    assert cve.score == 0
    assert cve.grade == Grade.F


def test_grade_boundaries():
    scorer = Scorer()
    assert scorer.score_to_grade(100) == Grade.A
    assert scorer.score_to_grade(90) == Grade.A
    assert scorer.score_to_grade(89) == Grade.B
    assert scorer.score_to_grade(80) == Grade.B
    assert scorer.score_to_grade(79) == Grade.C
    assert scorer.score_to_grade(65) == Grade.C
    assert scorer.score_to_grade(64) == Grade.D
    assert scorer.score_to_grade(50) == Grade.D
    assert scorer.score_to_grade(49) == Grade.F
    assert scorer.score_to_grade(0) == Grade.F


def test_overall_score_is_average():
    findings = [
        _make_finding(Severity.CRITICAL, Category.CODE_SAFETY),  # 75
        # Others stay at 100
    ]
    scorer = Scorer()
    categories = scorer.score_categories(findings)
    overall = scorer.compute_overall(categories)
    # (75 + 100 * 5) / 6 ≈ 95.83 → 96
    assert overall == 96


def test_multiple_severities():
    findings = [
        _make_finding(Severity.HIGH, Category.PERMISSIONS),    # -15
        _make_finding(Severity.MEDIUM, Category.PERMISSIONS),  # -7
        _make_finding(Severity.LOW, Category.PERMISSIONS),     # -3
    ]
    scorer = Scorer()
    categories = scorer.score_categories(findings)
    perms = next(c for c in categories if c.category == Category.PERMISSIONS)
    assert perms.score == 75  # 100 - 15 - 7 - 3
    assert perms.grade == Grade.C
    assert perms.findings_count == 3
    assert perms.high_count == 1
