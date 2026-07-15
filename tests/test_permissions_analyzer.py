from skills_verified.analyzers.permissions_analyzer import PermissionsAnalyzer
from skills_verified.core.models import Category


def test_is_available():
    analyzer = PermissionsAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "permissions"


def test_finds_file_operations(fake_repo_path):
    analyzer = PermissionsAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    file_findings = [
        f
        for f in findings
        if "rmtree" in f.title.lower()
        or "delete" in f.title.lower()
        or "remove" in f.title.lower()
    ]
    assert len(file_findings) >= 1


def test_finds_process_operations(fake_repo_path):
    analyzer = PermissionsAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    proc_findings = [
        f
        for f in findings
        if "kill" in f.title.lower()
        or "process" in f.title.lower()
        or "popen" in f.title.lower()
    ]
    assert len(proc_findings) >= 1


def test_finds_network_operations(tmp_path):
    net_file = tmp_path / "net.py"
    net_file.write_text(
        "import requests\n"
        "import socket\n"
        "r = requests.get('http://example.com')\n"
        "s = socket.socket()\n"
    )
    analyzer = PermissionsAnalyzer()
    findings = analyzer.analyze(tmp_path)
    net_findings = [
        f
        for f in findings
        if "network" in f.title.lower() or "socket" in f.title.lower()
    ]
    assert len(net_findings) >= 1


def test_no_findings_on_clean_file(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1 + 2\nprint(x)\n")
    analyzer = PermissionsAnalyzer()
    findings = analyzer.analyze(tmp_path)
    assert findings == []


def test_all_findings_are_permissions_category(fake_repo_path):
    analyzer = PermissionsAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    for f in findings:
        assert f.category == Category.PERMISSIONS
