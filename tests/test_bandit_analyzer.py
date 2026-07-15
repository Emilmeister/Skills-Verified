import json
import subprocess
from pathlib import Path

import pytest

from skills_verified.analyzers.bandit_analyzer import BanditAnalyzer
from skills_verified.core.models import Category, Severity


def test_name():
    analyzer = BanditAnalyzer()
    assert analyzer.name == "bandit"


def test_is_available_when_installed(monkeypatch):
    monkeypatch.setattr(
        "shutil.which",
        lambda cmd, path=None: "/usr/bin/bandit" if cmd == "bandit" else None,
    )
    analyzer = BanditAnalyzer()
    assert analyzer.is_available() is True


def test_is_available_when_not_installed(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd, path=None: None)
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
    assert findings[0].rule_id == "SV-BANDIT-B307"
    assert findings[0].confidence == 0.9
    assert findings[0].end_line == 5
    assert findings[1].severity == Severity.HIGH


@pytest.mark.parametrize("test_id", ["B101", "B403", "B405", "B408", "B603"])
def test_non_actionable_bandit_advisories_are_not_reported_as_vulnerabilities(
    test_id,
):
    bandit_json = {
        "results": [
            {
                "test_id": test_id,
                "test_name": "subprocess_without_shell_equals_true",
                "issue_text": "subprocess call - check for execution of untrusted input.",
                "issue_severity": "LOW",
                "issue_confidence": "HIGH",
                "filename": "/tmp/repo/client.py",
                "line_number": 5,
                "line_range": [5],
            }
        ]
    }

    findings = BanditAnalyzer()._parse_output(
        json.dumps(bandit_json), Path("/tmp/repo")
    )

    assert findings == []


def test_actionable_low_severity_bandit_finding_is_preserved():
    bandit_json = {
        "results": [
            {
                "test_id": "B113",
                "test_name": "request_without_timeout",
                "issue_text": "Call to requests without timeout.",
                "issue_severity": "LOW",
                "issue_confidence": "MEDIUM",
                "filename": "/tmp/repo/client.py",
                "line_number": 5,
                "line_range": [5],
            }
        ]
    }

    findings = BanditAnalyzer()._parse_output(
        json.dumps(bandit_json), Path("/tmp/repo")
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SV-BANDIT-B113"
    assert findings[0].severity == Severity.LOW


def test_weak_random_is_only_reported_in_security_context():
    base = {
        "test_id": "B311",
        "test_name": "blacklist",
        "issue_text": "Standard pseudo-random generators are not suitable for security.",
        "issue_severity": "LOW",
        "issue_confidence": "HIGH",
        "filename": "/tmp/repo/names.py",
        "line_number": 5,
        "line_range": [5],
    }
    bandit_json = {
        "results": [
            {**base, "code": "5 resource_name = random.choice(words)"},
            {
                **base,
                "filename": "/tmp/repo/tokens.py",
                "code": "5 session_token = random.choice(alphabet)",
            },
        ]
    }

    findings = BanditAnalyzer()._parse_output(
        json.dumps(bandit_json), Path("/tmp/repo")
    )

    assert len(findings) == 1
    assert findings[0].file_path == "tokens.py"


def test_execution_failure_is_not_a_clean_result(monkeypatch, tmp_path):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 2, "", "boom"),
    )

    with pytest.raises(RuntimeError, match="status 2"):
        BanditAnalyzer().analyze(tmp_path)


def test_command_ignores_repo_controlled_suppressions(monkeypatch, tmp_path):
    captured = {}

    def run(command, **kwargs):
        captured["command"] = command
        captured["cwd"] = kwargs["cwd"]
        return subprocess.CompletedProcess(command, 0, '{"results": []}', "")

    monkeypatch.setattr(subprocess, "run", run)

    assert BanditAnalyzer().analyze(tmp_path) == []
    assert "--ignore-nosec" in captured["command"]
    assert (
        captured["command"][captured["command"].index("--confidence-level") + 1]
        == "medium"
    )
    ini_path = Path(captured["command"][captured["command"].index("--ini") + 1])
    assert ini_path.parent == Path(captured["cwd"])
    assert Path(captured["cwd"]) != tmp_path
