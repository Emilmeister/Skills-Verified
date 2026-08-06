from skills_verified.analyzers.obfuscation_analyzer import ObfuscationAnalyzer


def test_is_available():
    analyzer = ObfuscationAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "obfuscation"


def test_no_findings_clean(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1 + 2\nprint(x)\n")
    analyzer = ObfuscationAnalyzer()
    findings = analyzer.analyze(tmp_path)
    assert findings == []


def test_expose_function_api_is_not_function_constructor(tmp_path):
    source = tmp_path / "browser.ts"
    source.write_text('await page.exposeFunction("ready", callback);\n')

    assert ObfuscationAnalyzer().analyze(tmp_path) == []


def test_localized_text_is_not_a_homoglyph_identifier(tmp_path):
    source = tmp_path / "messages.py"
    source.write_text(
        "message = 'Получаю IAM токен'\n"
        "# Нет доступных групп\n"
        "value = getattr(args, 'project_id', None)\n"
    )

    findings = ObfuscationAnalyzer().analyze(tmp_path)

    assert not any(f.rule_id in {"OB006", "OB011"} for f in findings)


def test_finds_mixed_script_python_identifier(tmp_path):
    source = tmp_path / "trojan_source.py"
    source.write_text("p\u0430ssword = 'hidden'\n")

    findings = ObfuscationAnalyzer().analyze(tmp_path)

    finding = next(f for f in findings if f.rule_id == "OB006")
    assert finding.line_number == 1


def test_finds_constructed_dangerous_getattr(tmp_path):
    source = tmp_path / "loader.py"
    source.write_text("runner = getattr(__builtins__, 'ev' + 'al')\n")

    findings = ObfuscationAnalyzer().analyze(tmp_path)

    assert any(f.rule_id == "OB011" for f in findings)


def test_normal_short_string_concatenation_is_not_obfuscation(tmp_path):
    source = tmp_path / "formatting.py"
    source.write_text("layout = 'l' + 'c' * num_cols\n")

    assert ObfuscationAnalyzer().analyze(tmp_path) == []


def test_finds_split_dangerous_command(tmp_path):
    source = tmp_path / "loader.py"
    source.write_text("command = 'cu' + 'rl'\n")

    findings = ObfuscationAnalyzer().analyze(tmp_path)

    assert any(f.rule_id == "OB005" for f in findings)


def test_binary_header_and_control_character_regex_are_not_obfuscation(tmp_path):
    source = tmp_path / "binary.py"
    source.write_text(
        'png = b"\\x89PNG\\r\\n\\x1a\\n\\x00\\x00\\x00\\rIHDR"\n'
        "clean = re.sub(r'[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]', '', text)\n"
    )

    assert ObfuscationAnalyzer().analyze(tmp_path) == []
