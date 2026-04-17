import json

from skills_verified.analyzers.container_analyzer import ContainerAnalyzer
from skills_verified.core.models import Category, Severity


def test_name():
    analyzer = ContainerAnalyzer()
    assert analyzer.name == "container"


def test_is_available_when_installed(monkeypatch):
    monkeypatch.setattr("skills_verified.analyzers.container_analyzer.find_tool", lambda cmd: "/usr/bin/grype" if cmd == "grype" else None)
    analyzer = ContainerAnalyzer()
    assert analyzer.is_available() is True


def test_is_available_when_not_installed(monkeypatch):
    monkeypatch.setattr("skills_verified.analyzers.container_analyzer.find_tool", lambda cmd: None)
    analyzer = ContainerAnalyzer()
    assert analyzer.is_available() is False


def test_parse_grype_output():
    analyzer = ContainerAnalyzer()
    grype_json = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-9999",
                    "severity": "High",
                    "description": "Remote code execution in libfoo",
                },
                "artifact": {
                    "name": "libfoo",
                    "version": "1.2.3",
                    "type": "python",
                    "locations": [{"path": "requirements.txt"}],
                },
            },
            {
                "vulnerability": {
                    "id": "GHSA-xxxx-yyyy",
                    "severity": "Critical",
                    "description": "SQL injection",
                },
                "artifact": {
                    "name": "badlib",
                    "version": "0.1.0",
                    "type": "npm",
                    "locations": [],
                },
            },
        ]
    }
    findings = analyzer._parse_output(json.dumps(grype_json))
    assert len(findings) == 2

    assert findings[0].severity == Severity.HIGH
    assert findings[0].cve_id == "CVE-2024-9999"
    assert findings[0].file_path == "requirements.txt"
    assert findings[0].category == Category.CVE

    assert findings[1].severity == Severity.CRITICAL
    assert findings[1].cve_id is None  # GHSA, not CVE
    assert findings[1].file_path is None


def test_parse_empty_output():
    analyzer = ContainerAnalyzer()
    findings = analyzer._parse_output("{}")
    assert findings == []


def test_parse_invalid_json():
    analyzer = ContainerAnalyzer()
    findings = analyzer._parse_output("not json")
    assert findings == []


def test_image_mode():
    analyzer = ContainerAnalyzer(image="python:3.11-slim")
    assert analyzer.image == "python:3.11-slim"


def test_all_findings_are_cve_category():
    analyzer = ContainerAnalyzer()
    grype_json = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2024-0001", "severity": "Low"},
                "artifact": {"name": "pkg", "version": "1.0", "locations": []},
            }
        ]
    }
    findings = analyzer._parse_output(json.dumps(grype_json))
    for f in findings:
        assert f.category == Category.CVE
        assert f.analyzer == "container"
