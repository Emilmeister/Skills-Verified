from pathlib import Path

from skills_verified.analyzers.llm_verifier import (
    LlmVerifier,
    VerificationResult,
    filter_verified,
)
from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.core.models import Category, Finding, Severity


def _mk_finding(rel_path: str = "x.py", line: int | None = 2) -> Finding:
    return Finding(
        title="Unsafe eval() call",
        description="eval is dangerous",
        severity=Severity.CRITICAL,
        category=Category.CODE_SAFETY,
        file_path=rel_path,
        line_number=line,
        analyzer="llm",
    )


def test_verified_true_when_patch_fixes(tmp_path: Path):
    (tmp_path / "x.py").write_text("def f():\n    eval('1')\n")

    def patch_gen(finding, content):
        return content.replace("eval('1')", "int('1')")

    verifier = LlmVerifier([PatternAnalyzer()], patch_generator=patch_gen)
    result = verifier.verify(tmp_path, _mk_finding())
    assert result.verified is True


def test_verified_false_when_patch_unchanged(tmp_path: Path):
    (tmp_path / "x.py").write_text("def f():\n    eval('1')\n")

    def patch_gen(finding, content):
        return content

    verifier = LlmVerifier([PatternAnalyzer()], patch_generator=patch_gen)
    result = verifier.verify(tmp_path, _mk_finding())
    assert result.verified is False
    assert "could not generate" in result.verification_notes


def test_verified_false_when_patch_does_not_remove_vuln(tmp_path: Path):
    (tmp_path / "x.py").write_text("def f():\n    eval('1')\n")

    def patch_gen(finding, content):
        return "# harmless header\n" + content

    verifier = LlmVerifier([PatternAnalyzer()], patch_generator=patch_gen)
    result = verifier.verify(tmp_path, _mk_finding())
    assert result.verified is False
    assert "still reported" in result.verification_notes


def test_verified_false_without_baseline_evidence(tmp_path: Path):
    (tmp_path / "x.py").write_text("def f():\n    return 1\n")
    finding = _mk_finding(line=2)
    verifier = LlmVerifier(
        [PatternAnalyzer()], patch_generator=lambda f, c: c.replace("return 1", "return 2")
    )
    result = verifier.verify(tmp_path, finding)
    assert result.verified is False
    assert "hallucination" in result.verification_notes


def test_verified_false_when_file_missing(tmp_path: Path):
    verifier = LlmVerifier([PatternAnalyzer()], patch_generator=lambda f, c: c)
    result = verifier.verify(tmp_path, _mk_finding("missing.py"))
    assert result.verified is False
    assert "file not found" in result.verification_notes


def test_verified_false_when_line_out_of_range(tmp_path: Path):
    (tmp_path / "x.py").write_text("one line\n")
    verifier = LlmVerifier([PatternAnalyzer()], patch_generator=lambda f, c: c)
    result = verifier.verify(tmp_path, _mk_finding(line=999))
    assert result.verified is False
    assert "out of range" in result.verification_notes


def test_verified_false_when_patch_generator_raises(tmp_path: Path):
    (tmp_path / "x.py").write_text("def f():\n    eval('1')\n")

    def bad(finding, content):
        raise RuntimeError("boom")

    verifier = LlmVerifier([PatternAnalyzer()], patch_generator=bad)
    result = verifier.verify(tmp_path, _mk_finding())
    assert result.verified is False


def test_filter_verified_drops_unverified_and_annotates(tmp_path: Path):
    (tmp_path / "x.py").write_text("def f():\n    eval('1')\n")
    good = _mk_finding()
    bad = _mk_finding("missing.py")

    def patch_gen(finding, content):
        return content.replace("eval('1')", "int('1')")

    verifier = LlmVerifier([PatternAnalyzer()], patch_generator=patch_gen)
    kept = filter_verified(verifier, tmp_path, [good, bad])
    assert len(kept) == 1
    assert kept[0].file_path == "x.py"
    assert kept[0].description.startswith("[verified]")


def test_false_positive_reduction_on_mocked_findings(tmp_path: Path):
    # Simulated LLM output: 5 findings, 3 are hallucinations, 2 are real.
    (tmp_path / "real.py").write_text("def f():\n    eval('1')\n")
    (tmp_path / "real2.py").write_text("def g():\n    os.system('ls')\n")
    (tmp_path / "clean.py").write_text("def h():\n    return 1\n")

    real1 = Finding(
        title="Unsafe eval() call", description="", severity=Severity.CRITICAL,
        category=Category.CODE_SAFETY, file_path="real.py", line_number=2, analyzer="llm",
    )
    real2 = Finding(
        title="os.system() usage", description="", severity=Severity.HIGH,
        category=Category.CODE_SAFETY, file_path="real2.py", line_number=2, analyzer="llm",
    )
    halluc1 = Finding(
        title="SQL injection", description="", severity=Severity.HIGH,
        category=Category.CODE_SAFETY, file_path="clean.py", line_number=2, analyzer="llm",
    )
    halluc2 = Finding(
        title="XSS", description="", severity=Severity.HIGH,
        category=Category.CODE_SAFETY, file_path="missing.py", line_number=1, analyzer="llm",
    )
    halluc3 = Finding(
        title="CSRF", description="", severity=Severity.MEDIUM,
        category=Category.CODE_SAFETY, file_path="clean.py", line_number=1, analyzer="llm",
    )
    findings = [real1, real2, halluc1, halluc2, halluc3]

    def patch_gen(f, content):
        if "eval" in content:
            return content.replace("eval('1')", "int('1')")
        if "os.system" in content:
            return content.replace("os.system('ls')", "subprocess.run(['ls'])")
        return content

    verifier = LlmVerifier([PatternAnalyzer()], patch_generator=patch_gen)
    kept = filter_verified(verifier, tmp_path, findings)
    # 3/5 false positives dropped => >= 30% reduction
    assert len(kept) == 2
    assert {f.title for f in kept} == {"Unsafe eval() call", "os.system() usage"}


def test_verification_result_dataclass():
    f = _mk_finding()
    r = VerificationResult(finding=f, verified=True, verification_notes="ok")
    assert r.finding is f
    assert r.verified is True
