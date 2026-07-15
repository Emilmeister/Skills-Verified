from skills_verified.analyzers.reverse_shell_analyzer import ReverseShellAnalyzer
from skills_verified.core.models import Category, Severity


def test_is_available():
    analyzer = ReverseShellAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "reverse_shell"


def test_finds_bash_tcp(fake_repo_path):
    analyzer = ReverseShellAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    tcp_findings = [
        f for f in findings if "bash" in f.title.lower() and "tcp" in f.title.lower()
    ]
    assert len(tcp_findings) >= 1
    assert tcp_findings[0].severity == Severity.CRITICAL
    assert tcp_findings[0].category == Category.CODE_SAFETY


def test_finds_netcat(fake_repo_path):
    analyzer = ReverseShellAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    nc_findings = [
        f for f in findings if "netcat" in f.title.lower() or "nc" in f.title.lower()
    ]
    assert len(nc_findings) >= 1
    assert nc_findings[0].category == Category.CODE_SAFETY


def test_finds_python_socket_shell(fake_repo_path):
    analyzer = ReverseShellAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    socket_findings = [
        f
        for f in findings
        if "socket" in f.title.lower() and "subprocess" in f.title.lower()
    ]
    assert len(socket_findings) >= 1
    assert socket_findings[0].severity == Severity.CRITICAL
    assert socket_findings[0].category == Category.CODE_SAFETY


def test_finds_pty_spawn(fake_repo_path):
    analyzer = ReverseShellAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    pty_findings = [f for f in findings if "pty" in f.title.lower()]
    assert len(pty_findings) >= 1
    assert pty_findings[0].severity == Severity.CRITICAL
    assert pty_findings[0].category == Category.CODE_SAFETY


def test_no_findings_clean(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1 + 2\nprint(x)\n")
    analyzer = ReverseShellAnalyzer()
    findings = analyzer.analyze(tmp_path)
    assert findings == []


def test_socket_and_unrelated_subprocess_are_not_a_reverse_shell(tmp_path):
    source = tmp_path / "service.py"
    source.write_text(
        "import socket\nimport subprocess\n"
        "client = socket.socket()\nclient.connect(('127.0.0.1', 9000))\n"
        "subprocess.run(['soffice', '--headless'], check=True)\n"
    )

    assert ReverseShellAnalyzer().analyze(tmp_path) == []
