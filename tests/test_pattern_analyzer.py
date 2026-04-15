
from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.core.models import Category, Severity


def test_is_available():
    analyzer = PatternAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "pattern"


def test_finds_eval(fake_repo_path):
    analyzer = PatternAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    eval_findings = [f for f in findings if "eval" in f.title.lower()]
    assert len(eval_findings) >= 1
    assert eval_findings[0].category == Category.CODE_SAFETY


def test_finds_exec(fake_repo_path):
    analyzer = PatternAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    exec_findings = [f for f in findings if "exec" in f.title.lower()]
    assert len(exec_findings) >= 1


def test_finds_shell_true(fake_repo_path):
    analyzer = PatternAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    shell_findings = [f for f in findings if "shell" in f.title.lower()]
    assert len(shell_findings) >= 1
    assert shell_findings[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_finds_hardcoded_secrets(fake_repo_path):
    analyzer = PatternAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    secret_findings = [f for f in findings if "secret" in f.title.lower() or "key" in f.title.lower() or "password" in f.title.lower()]
    assert len(secret_findings) >= 1


def test_finds_os_system(fake_repo_path):
    analyzer = PatternAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    os_findings = [f for f in findings if "os.system" in f.title.lower() or "os.popen" in f.title.lower()]
    assert len(os_findings) >= 1


def test_finds_unsafe_pickle(fake_repo_path):
    analyzer = PatternAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    pickle_findings = [f for f in findings if "pickle" in f.title.lower()]
    assert len(pickle_findings) >= 1


def test_finds_unsafe_yaml(fake_repo_path):
    analyzer = PatternAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    yaml_findings = [f for f in findings if "yaml" in f.title.lower()]
    assert len(yaml_findings) >= 1


def test_no_findings_on_clean_file(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1 + 2\nprint(x)\n")
    analyzer = PatternAnalyzer()
    findings = analyzer.analyze(tmp_path)
    assert findings == []
