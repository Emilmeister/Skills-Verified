from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.analyzers.taint_analyzer import TaintAnalyzer


def test_detects_three_taint_paths(fake_repo_path):
    findings = TaintAnalyzer().analyze(fake_repo_path)
    titles = {f.title for f in findings if f.file_path == "taint_sample.py"}
    assert any("Command injection" in t for t in titles)
    assert any("SSRF" in t for t in titles)
    assert any("Path traversal" in t for t in titles)


def test_correct_line_numbers(fake_repo_path):
    findings = [f for f in TaintAnalyzer().analyze(fake_repo_path)
                if f.file_path == "taint_sample.py"]
    lines = {f.line_number for f in findings}
    # subprocess.run, urlopen, open calls should be detected
    assert any(ln is not None and 8 <= ln <= 12 for ln in lines)  # cmd injection
    assert any(ln is not None and 12 <= ln <= 16 for ln in lines)  # ssrf
    assert any(ln is not None and 18 <= ln <= 22 for ln in lines)  # path traversal


def test_sanitized_call_not_reported(fake_repo_path):
    findings = [f for f in TaintAnalyzer().analyze(fake_repo_path)
                if f.file_path == "taint_sample.py"]
    # the safe_shell_call function wraps input in shlex.quote → no finding for that line
    lines = {f.line_number for f in findings}
    # safe_shell_call is around lines 24–26; no finding expected for subprocess there
    assert not any(ln is not None and 24 <= ln <= 26 for ln in lines)


def test_constant_sink_not_reported(fake_repo_path):
    findings = [f for f in TaintAnalyzer().analyze(fake_repo_path)
                if f.file_path == "taint_sample.py"]
    lines = {f.line_number for f in findings}
    # safe_constant_call lines ~28–30
    assert not any(ln is not None and 28 <= ln <= 30 for ln in lines)


def test_fp_rate_not_worse_than_pattern(fake_repo_path):
    """Informational cross-check: taint shouldn't wildly over-report relative to pattern."""
    pattern = PatternAnalyzer().analyze(fake_repo_path)
    taint = TaintAnalyzer().analyze(fake_repo_path)
    # Just sanity-check: both produce findings and taint doesn't flood
    assert len(taint) > 0
    assert len(taint) <= max(len(pattern) * 3, 20)


def test_handles_syntax_error(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n")
    findings = TaintAnalyzer().analyze(tmp_path)
    assert findings == []


def test_fastapi_handler_args_treated_as_tainted(tmp_path):
    src = """
import subprocess
from fastapi import FastAPI
app = FastAPI()

@app.get("/run")
def run(cmd: str):
    subprocess.run(cmd, shell=True)
"""
    (tmp_path / "api.py").write_text(src)
    findings = TaintAnalyzer().analyze(tmp_path)
    assert any("Command injection" in f.title for f in findings)


def test_is_available():
    assert TaintAnalyzer().is_available() is True
