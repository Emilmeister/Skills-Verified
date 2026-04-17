import pytest

from skills_verified.core.models import (
    Category,
    CategoryScore,
    Finding,
    Grade,
    Report,
    Severity,
)
from skills_verified.core.policy_engine import PolicyEngine, PolicyError


def _mk_report(
    grade: Grade = Grade.B,
    score: int = 82,
    criticals: int = 0,
    highs: int = 0,
) -> Report:
    findings: list[Finding] = []
    for _ in range(criticals):
        findings.append(Finding(
            title="c", description="", severity=Severity.CRITICAL,
            category=Category.CODE_SAFETY, file_path=None, line_number=None,
            analyzer="x",
        ))
    for _ in range(highs):
        findings.append(Finding(
            title="h", description="", severity=Severity.HIGH,
            category=Category.CODE_SAFETY, file_path=None, line_number=None,
            analyzer="x",
        ))
    categories = [
        CategoryScore(category=Category.CODE_SAFETY, score=score, grade=grade,
                      findings_count=len(findings), critical_count=criticals, high_count=highs),
        CategoryScore(category=Category.AI_BOM, score=100, grade=Grade.A,
                      findings_count=0, critical_count=0, high_count=0),
    ]
    return Report(
        repo_url="x", overall_score=score, overall_grade=grade,
        categories=categories, findings=findings, analyzers_used=["x"],
        llm_used=False, scan_duration_seconds=0.0,
    )


def test_builtin_strict_pass():
    engine = PolicyEngine()
    rule = engine.parse("strict")
    report = _mk_report(Grade.A, 95, criticals=0)
    passed, _ = engine.evaluate(rule, report)
    assert passed is True


def test_builtin_strict_fail_on_non_A():
    engine = PolicyEngine()
    rule = engine.parse("strict")
    report = _mk_report(Grade.B, 82, criticals=0)
    passed, _ = engine.evaluate(rule, report)
    assert passed is False


def test_builtin_standard():
    engine = PolicyEngine()
    rule = engine.parse("standard")
    assert engine.evaluate(rule, _mk_report(Grade.C, 70))[0] is True
    assert engine.evaluate(rule, _mk_report(Grade.D, 55))[0] is False


def test_builtin_relaxed():
    engine = PolicyEngine()
    rule = engine.parse("relaxed")
    assert engine.evaluate(rule, _mk_report(Grade.F, 40))[0] is False
    assert engine.evaluate(rule, _mk_report(Grade.D, 55, criticals=3))[0] is False


def test_free_form_without_llm_raises():
    engine = PolicyEngine(llm_config=None)
    with pytest.raises(PolicyError):
        engine.parse("no critical findings and grade above C")


def test_sandbox_blocks_import():
    engine = PolicyEngine()
    with pytest.raises(PolicyError):
        engine._compile("__import__('os').system('rm -rf /')")


def test_sandbox_blocks_function_call():
    engine = PolicyEngine()
    with pytest.raises(PolicyError):
        engine._compile("len([1,2,3]) > 0")


def test_sandbox_blocks_private_attribute():
    engine = PolicyEngine()
    with pytest.raises(PolicyError):
        engine._compile("report.__class__")


def test_direct_expression_evaluates():
    engine = PolicyEngine()
    rule = engine._compile("report.criticals == 0 and report.overall_grade in ('A','B')")
    report = _mk_report(Grade.B, 82, criticals=0)
    assert engine.evaluate(rule, report)[0] is True


def test_unknown_field_raises():
    engine = PolicyEngine()
    rule = engine._compile("report.made_up_field > 0")
    report = _mk_report()
    with pytest.raises(PolicyError):
        engine.evaluate(rule, report)


def test_categories_access():
    engine = PolicyEngine()
    rule = engine._compile("report.categories.code_safety.score >= 80")
    report = _mk_report(Grade.B, 82)
    assert engine.evaluate(rule, report)[0] is True


def test_llm_translation_monkeypatched(monkeypatch):
    from skills_verified.analyzers.llm_analyzer import LlmConfig

    class _R:
        class choices:
            class _c:
                class message:
                    content = "report.criticals == 0 and report.overall_grade != 'F'"
            _v = [_c]
        def __init__(self):
            self.choices = _R.choices._v

    class _Client:
        def __init__(self, base_url, api_key):
            self.chat = type("c", (), {"completions": type("co", (), {
                "create": staticmethod(lambda model, messages, temperature: _R()),
            })})

    import openai
    monkeypatch.setattr(openai, "OpenAI", _Client)

    engine = PolicyEngine(llm_config=LlmConfig(url="http://x", model="m", key="k"))
    rule = engine.parse("no critical findings and not F")
    report = _mk_report(Grade.B, 82, criticals=0)
    assert engine.evaluate(rule, report)[0] is True


def test_cli_free_form_rejects_eval_attempt(monkeypatch):
    """End-to-end: LLM returns malicious code → PolicyError, not code execution."""
    from skills_verified.analyzers.llm_analyzer import LlmConfig

    class _R:
        def __init__(self):
            self.choices = [type("c", (), {"message": type("m", (), {
                "content": "__import__('os').system('echo pwned')"
            })})]

    class _Client:
        def __init__(self, base_url, api_key):
            self.chat = type("c", (), {"completions": type("co", (), {
                "create": staticmethod(lambda model, messages, temperature: _R()),
            })})

    import openai
    monkeypatch.setattr(openai, "OpenAI", _Client)

    engine = PolicyEngine(llm_config=LlmConfig(url="http://x", model="m", key="k"))
    with pytest.raises(PolicyError):
        engine.parse("delete the filesystem")
