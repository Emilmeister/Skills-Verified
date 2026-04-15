import json
from pathlib import Path

from skills_verified.analyzers.semgrep_analyzer import SemgrepAnalyzer
from skills_verified.core.models import Category


def test_name():
    analyzer = SemgrepAnalyzer()
    assert analyzer.name == "semgrep"


def test_is_available_when_installed(monkeypatch):
    monkeypatch.setattr("skills_verified.analyzers.semgrep_analyzer.find_tool", lambda cmd: "/usr/bin/semgrep" if cmd == "semgrep" else None)
    analyzer = SemgrepAnalyzer()
    assert analyzer.is_available() is True


def test_is_available_when_not_installed(monkeypatch):
    monkeypatch.setattr("skills_verified.analyzers.semgrep_analyzer.find_tool", lambda cmd: None)
    analyzer = SemgrepAnalyzer()
    assert analyzer.is_available() is False


def test_parse_semgrep_output():
    analyzer = SemgrepAnalyzer()
    semgrep_json = {
        "results": [
            {
                "check_id": "python.lang.security.audit.exec-detected",
                "path": "/tmp/repo/bad.py",
                "start": {"line": 10, "col": 1},
                "end": {"line": 10, "col": 20},
                "extra": {
                    "message": "Detected the use of exec(). This is dangerous.",
                    "severity": "WARNING",
                    "metadata": {},
                },
            }
        ]
    }
    findings = analyzer._parse_output(json.dumps(semgrep_json), Path("/tmp/repo"))
    assert len(findings) == 1
    assert findings[0].file_path == "bad.py"
    assert findings[0].line_number == 10
    assert findings[0].category == Category.CODE_SAFETY
