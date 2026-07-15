from skills_verified.core.models import Category, Finding, Severity
from skills_verified.output.github_annotations import (
    format_annotations,
    print_annotations,
)


def _make_finding(
    severity: Severity,
    title: str = "Test issue",
    description: str = "Test desc",
    file_path: str | None = None,
    line_number: int | None = None,
) -> Finding:
    return Finding(
        title=title,
        description=description,
        severity=severity,
        category=Category.CODE_SAFETY,
        file_path=file_path,
        line_number=line_number,
        analyzer="test_analyzer",
    )


def test_critical_produces_error():
    finding = _make_finding(Severity.CRITICAL)
    lines = format_annotations([finding])
    assert len(lines) == 1
    assert lines[0].startswith("::error ")


def test_high_produces_error():
    finding = _make_finding(Severity.HIGH)
    lines = format_annotations([finding])
    assert len(lines) == 1
    assert lines[0].startswith("::error ")


def test_medium_produces_warning():
    finding = _make_finding(Severity.MEDIUM)
    lines = format_annotations([finding])
    assert len(lines) == 1
    assert lines[0].startswith("::warning ")


def test_low_produces_warning():
    finding = _make_finding(Severity.LOW)
    lines = format_annotations([finding])
    assert len(lines) == 1
    assert lines[0].startswith("::warning ")


def test_info_produces_notice():
    finding = _make_finding(Severity.INFO)
    lines = format_annotations([finding])
    assert len(lines) == 1
    assert lines[0].startswith("::notice ")


def test_unknown_produces_notice():
    finding = _make_finding(Severity.UNKNOWN)
    lines = format_annotations([finding])
    assert lines[0].startswith("::notice ")


def test_file_and_line_in_annotation():
    finding = _make_finding(Severity.HIGH, file_path="src/main.py", line_number=42)
    lines = format_annotations([finding])
    assert "file=src/main.py" in lines[0]
    assert "line=42" in lines[0]


def test_title_in_annotation():
    finding = _make_finding(Severity.HIGH, title="Bad key")
    lines = format_annotations([finding])
    assert "title=Bad key" in lines[0]


def test_description_after_separator():
    finding = _make_finding(Severity.CRITICAL, description="Found leak")
    lines = format_annotations([finding])
    assert lines[0].endswith("::Found leak")


def test_untrusted_workflow_command_fields_are_escaped():
    finding = _make_finding(
        Severity.HIGH,
        title="bad:title,field\nnext",
        description="line one\n::error::spoofed",
        file_path="src/file,name.py",
    )

    line = format_annotations([finding])[0]

    assert "title=bad%3Atitle%2Cfield%0Anext" in line
    assert "file=src/file%2Cname.py" in line
    assert line.endswith("::line one%0A::error::spoofed")


def test_finding_without_file():
    finding = _make_finding(Severity.MEDIUM, file_path=None)
    lines = format_annotations([finding])
    assert "file=" not in lines[0]


def test_multiple_findings():
    findings = [
        _make_finding(Severity.HIGH),
        _make_finding(Severity.LOW),
    ]
    lines = format_annotations(findings)
    assert len(lines) == 2


def test_print_annotations(capsys):
    findings = [
        _make_finding(Severity.CRITICAL, description="Found leak"),
        _make_finding(Severity.INFO, description="Just info"),
    ]
    print_annotations(findings)
    captured = capsys.readouterr()
    output_lines = captured.out.strip().split("\n")
    assert len(output_lines) == 2
    assert output_lines[0].startswith("::error ")
    assert output_lines[1].startswith("::notice ")
