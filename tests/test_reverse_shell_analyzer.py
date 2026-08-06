from skills_verified.analyzers.reverse_shell_analyzer import ReverseShellAnalyzer


def test_is_available():
    analyzer = ReverseShellAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "reverse_shell"


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
