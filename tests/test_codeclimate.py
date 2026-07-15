import json

import pytest

from skills_verified.core.models import Category, Finding, Severity
from skills_verified.output.codeclimate import generate_codeclimate, save_codeclimate


def make_finding(**kwargs) -> Finding:
    defaults = dict(
        title="Test Title",
        description="A test description",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="src/main.py",
        line_number=42,
        analyzer="test_analyzer",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Severity mapping tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity,expected",
    [
        (Severity.CRITICAL, "blocker"),
        (Severity.HIGH, "critical"),
        (Severity.MEDIUM, "major"),
        (Severity.LOW, "minor"),
        (Severity.INFO, "info"),
        (Severity.UNKNOWN, "info"),
    ],
)
def test_severity_mapping(severity, expected):
    finding = make_finding(severity=severity)
    issues = generate_codeclimate([finding])
    assert issues[0]["severity"] == expected


# ---------------------------------------------------------------------------
# Fingerprint tests
# ---------------------------------------------------------------------------


def test_fingerprint_is_hex_string():
    finding = make_finding()
    issues = generate_codeclimate([finding])
    fp = issues[0]["fingerprint"]
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp), f"Not a valid SHA256 hex: {fp}"
    assert fp == finding.fingerprint.removeprefix("sha256:")


def test_different_findings_get_different_fingerprints():
    f1 = make_finding(title="Title A", file_path="a.py", line_number=1)
    f2 = make_finding(title="Title B", file_path="b.py", line_number=2)
    issues = generate_codeclimate([f1, f2])
    assert issues[0]["fingerprint"] != issues[1]["fingerprint"]


# ---------------------------------------------------------------------------
# Location tests
# ---------------------------------------------------------------------------


def test_location_has_path_and_line():
    finding = make_finding(file_path="src/main.py", line_number=42)
    issues = generate_codeclimate([finding])
    loc = issues[0]["location"]
    assert loc["path"] == "src/main.py"
    assert loc["lines"]["begin"] == 42


def test_missing_file_path_defaults():
    finding = make_finding(file_path=None, line_number=None)
    issues = generate_codeclimate([finding])
    loc = issues[0]["location"]
    assert loc["path"] == "unknown"
    assert loc["lines"]["begin"] == 1


# ---------------------------------------------------------------------------
# Field presence tests
# ---------------------------------------------------------------------------


def test_check_name_is_analyzer():
    finding = make_finding(analyzer="test_analyzer")
    issues = generate_codeclimate([finding])
    assert issues[0]["check_name"] == "test_analyzer"


def test_description_present():
    finding = make_finding(description="A test description")
    issues = generate_codeclimate([finding])
    assert issues[0]["description"] == "A test description"


def test_type_is_issue():
    finding = make_finding()
    issues = generate_codeclimate([finding])
    assert issues[0]["type"] == "issue"


def test_categories_contains_security():
    finding = make_finding()
    issues = generate_codeclimate([finding])
    assert issues[0]["categories"] == ["Security"]


# ---------------------------------------------------------------------------
# save_codeclimate tests
# ---------------------------------------------------------------------------


def test_save_codeclimate(tmp_path):
    findings = [
        make_finding(title="F1", severity=Severity.CRITICAL),
        make_finding(
            title="F2", severity=Severity.LOW, file_path=None, line_number=None
        ),
    ]
    out_file = tmp_path / "codeclimate.json"
    save_codeclimate(findings, out_file)

    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["severity"] == "blocker"
    assert data[1]["location"]["path"] == "unknown"
