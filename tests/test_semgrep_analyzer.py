import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from skills_verified.analyzers.semgrep_analyzer import SemgrepAnalyzer
from skills_verified.core.models import Category, DiagnosticLevel


@pytest.fixture(autouse=True)
def local_semgrep_rules(monkeypatch, tmp_path):
    rules = tmp_path / "pinned.yml"
    rules.write_text("rules: []\n")
    monkeypatch.setattr(
        SemgrepAnalyzer,
        "_materialize_pinned_configs",
        lambda _self, _directory: [rules],
    )


def test_name():
    analyzer = SemgrepAnalyzer()
    assert analyzer.name == "semgrep"


def test_is_available_when_installed(monkeypatch):
    monkeypatch.setattr(
        "shutil.which",
        lambda cmd, path=None: "/usr/bin/semgrep" if cmd == "semgrep" else None,
    )
    analyzer = SemgrepAnalyzer()
    assert analyzer.is_available() is True


def test_is_available_when_not_installed(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd, path=None: None)
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
    assert findings[0].end_line == 10
    assert findings[0].rule_id == "SV-SEMGREP-PYTHON-LANG-SECURITY-AUDIT-EXEC-DETECTED"
    assert findings[0].category == Category.CODE_SAFETY


def test_ignores_non_actionable_script_tag_registry_rule():
    analyzer = SemgrepAnalyzer()
    semgrep_json = {
        "results": [
            {
                "check_id": (
                    "javascript.lang.security.audit.unknown-value-with-script-tag."
                    "unknown-value-with-script-tag"
                ),
                "path": "/tmp/repo/test.ts",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"message": "no actionable flow", "severity": "WARNING"},
            }
        ]
    }

    assert analyzer._parse_output(json.dumps(semgrep_json), Path("/tmp/repo")) == []


def test_ignores_react_html_sink_sanitized_by_local_dompurify_helper(tmp_path):
    source = tmp_path / "Preview.tsx"
    source.write_text(
        "function renderSafe(source: string): string {\n"
        "  return DOMPurify.sanitize(marked.parse(source));\n"
        "}\n"
        "const previewHtml = renderSafe(file.content);\n"
        "const preview = <div dangerouslySetInnerHTML={{ __html: previewHtml }} />;\n"
    )
    payload = {
        "results": [
            {
                "check_id": (
                    "typescript.react.security.audit.react-dangerouslysetinnerhtml."
                    "react-dangerouslysetinnerhtml"
                ),
                "path": str(source),
                "start": {"line": 5},
                "end": {"line": 5},
                "extra": {"message": "XSS sink", "severity": "WARNING"},
            }
        ]
    }

    assert SemgrepAnalyzer()._parse_output(json.dumps(payload), tmp_path) == []


def test_keeps_unsanitized_react_html_sink(tmp_path):
    source = tmp_path / "Preview.tsx"
    source.write_text(
        "const previewHtml = marked.parse(file.content);\n"
        "const preview = <div dangerouslySetInnerHTML={{ __html: previewHtml }} />;\n"
    )
    payload = {
        "results": [
            {
                "check_id": (
                    "typescript.react.security.audit.react-dangerouslysetinnerhtml."
                    "react-dangerouslysetinnerhtml"
                ),
                "path": str(source),
                "start": {"line": 2},
                "end": {"line": 2},
                "extra": {"message": "XSS sink", "severity": "WARNING"},
            }
        ]
    }

    findings = SemgrepAnalyzer()._parse_output(json.dumps(payload), tmp_path)

    assert len(findings) == 1


def test_reported_analysis_error_is_exposed_as_diagnostic(monkeypatch, tmp_path):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, '{"results": [], "errors": [{"message": "bad config"}]}', ""
        ),
    )

    analyzer = SemgrepAnalyzer()
    assert analyzer.analyze(tmp_path) == []
    assert analyzer.diagnostics[0].code == "semgrep_analysis_error"


def test_partial_parse_errors_are_aggregated_with_relative_paths():
    analyzer = SemgrepAnalyzer()
    payload = {
        "results": [],
        "errors": [
            {
                "type": ["PartialParsing", []],
                "path": "/tmp/repo/a.ts",
                "message": "syntax error one",
            },
            {
                "type": ["PartialParsing", []],
                "path": "/tmp/repo/b.ts",
                "message": "syntax error two",
            },
        ],
    }

    analyzer._parse_output(json.dumps(payload), Path("/tmp/repo"))

    assert len(analyzer.diagnostics) == 1
    diagnostic = analyzer.diagnostics[0]
    assert diagnostic.code == "semgrep_partial_parsing"
    assert diagnostic.level == DiagnosticLevel.WARNING
    assert diagnostic.details == {
        "errors_total": 2,
        "files_total": 2,
        "paths": ["a.ts", "b.ts"],
    }


def test_command_ignores_repo_controlled_suppressions(monkeypatch, tmp_path):
    captured = {}

    def run(command, **kwargs):
        captured["command"] = command
        captured["cwd"] = kwargs["cwd"]
        captured["env"] = kwargs["env"]
        return subprocess.CompletedProcess(
            command,
            0,
            '{"version": "1.2.3", "results": [], "errors": []}',
            "",
        )

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "must-not-be-forwarded")
    analyzer = SemgrepAnalyzer()

    assert analyzer.analyze(tmp_path) == []
    assert {
        "--disable-nosem",
        "--no-git-ignore",
        "--x-ignore-semgrepignore-files",
        "--metrics=off",
        "--jobs=2",
        "--timeout=30",
        "--timeout-threshold=0",
    } <= set(captured["command"])
    assert Path(captured["cwd"]) != tmp_path
    assert "SEMGREP_APP_TOKEN" not in captured["env"]
    assert analyzer.version == "1.2.3"
    configs = [
        captured["command"][index + 1]
        for index, value in enumerate(captured["command"])
        if value == "--config"
    ]
    assert configs and all(not value.startswith("p/") for value in configs)
    assert all("/" not in value for value in configs)
    assert "--exclude-rule" in captured["command"]
    assert any(
        diagnostic.code == "semgrep_ruleset_provenance"
        and diagnostic.level == DiagnosticLevel.INFO
        for diagnostic in analyzer.diagnostics
    )
    assert not any(
        diagnostic.code == "semgrep_remote_ruleset_unpinned"
        for diagnostic in analyzer.diagnostics
    )


def test_command_targets_detected_skill_roots(monkeypatch, tmp_path):
    skill = tmp_path / "skills" / "demo"
    skill.mkdir(parents=True)
    product = tmp_path / "packages" / "app"
    product.mkdir(parents=True)
    captured = {}

    def run(command, **kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, '{"results":[],"errors":[]}', "")

    monkeypatch.setattr(subprocess, "run", run)
    context = SimpleNamespace(skill_roots=[Path("skills/demo")])

    SemgrepAnalyzer().analyze(tmp_path, context=context)

    assert str(skill) in captured["command"]
    assert str(product) not in captured["command"]
    assert str(tmp_path) not in captured["command"]


def test_bundled_rules_match_pinned_digests(monkeypatch, tmp_path):
    monkeypatch.undo()

    paths = SemgrepAnalyzer()._materialize_pinned_configs(tmp_path)

    assert {path.name for path in paths} == {"security-audit.yml", "python.yml"}


def test_pinned_rules_reject_changed_bundled_content(monkeypatch, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "changed.yml").write_text("rules: []\n")
    monkeypatch.undo()
    monkeypatch.setattr(
        "skills_verified.analyzers.semgrep_analyzer.PINNED_CONFIGS",
        (("test", "changed.yml", "0" * 64),),
    )
    monkeypatch.setattr(SemgrepAnalyzer, "_rules_directory", lambda _self: rules)

    with pytest.raises(RuntimeError, match="digest mismatch"):
        SemgrepAnalyzer()._materialize_pinned_configs(tmp_path)
