import json
from pathlib import Path

from skills_verified.analyzers.bandit_analyzer import BanditAnalyzer
from skills_verified.core.models import Category, Severity


def test_name():
    analyzer = BanditAnalyzer()
    assert analyzer.name == "bandit"


def test_is_available_when_installed(monkeypatch):
    monkeypatch.setattr("skills_verified.analyzers.bandit_analyzer.find_tool", lambda cmd: "/usr/bin/bandit" if cmd == "bandit" else None)
    analyzer = BanditAnalyzer()
    assert analyzer.is_available() is True


def test_is_available_when_not_installed(monkeypatch):
    monkeypatch.setattr("skills_verified.analyzers.bandit_analyzer.find_tool", lambda cmd: None)
    analyzer = BanditAnalyzer()
    assert analyzer.is_available() is False


def test_parse_bandit_output():
    analyzer = BanditAnalyzer()
    bandit_json = {
        "results": [
            {
                "test_id": "B307",
                "test_name": "eval",
                "issue_text": "Use of possibly insecure function - consider using safer ast.literal_eval.",
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "filename": "/tmp/repo/danger.py",
                "line_number": 5,
                "line_range": [5],
            },
            {
                "test_id": "B602",
                "test_name": "subprocess_popen_with_shell_equals_true",
                "issue_text": "subprocess call with shell=True",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "filename": "/tmp/repo/cmd.py",
                "line_number": 12,
                "line_range": [12],
            },
        ]
    }
    findings = analyzer._parse_output(json.dumps(bandit_json), Path("/tmp/repo"))
    assert len(findings) == 2
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].category == Category.CODE_SAFETY
    assert findings[0].file_path == "danger.py"
    assert findings[1].severity == Severity.HIGH
