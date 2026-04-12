import json
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

from skills_verified.analyzers.cve_analyzer import CveAnalyzer
from skills_verified.core.models import Category, Severity


def test_name():
    analyzer = CveAnalyzer()
    assert analyzer.name == "cve"


def test_is_available_with_pip_audit(monkeypatch):
    monkeypatch.setattr(
        "shutil.which", lambda cmd: "/usr/bin/pip-audit" if cmd == "pip-audit" else None
    )
    analyzer = CveAnalyzer()
    assert analyzer.is_available() is True


def test_is_available_without_tools(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: None)
    analyzer = CveAnalyzer()
    assert analyzer.is_available() is False


def test_parse_pip_audit_output():
    analyzer = CveAnalyzer()
    pip_audit_json = [
        {
            "name": "flask",
            "version": "2.0.0",
            "vulns": [
                {
                    "id": "CVE-2023-30861",
                    "fix_versions": ["2.3.2"],
                    "description": "Session cookie vulnerability",
                }
            ],
        }
    ]
    findings = analyzer._parse_pip_audit(json.dumps(pip_audit_json), "requirements.txt")
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2023-30861"
    assert findings[0].category == Category.CVE
    assert "flask" in findings[0].title.lower()


def test_parse_npm_audit_output():
    analyzer = CveAnalyzer()
    npm_audit_json = {
        "vulnerabilities": {
            "lodash": {
                "name": "lodash",
                "severity": "high",
                "via": [
                    {
                        "source": 1234,
                        "name": "lodash",
                        "title": "Prototype Pollution",
                        "url": "https://github.com/advisories/GHSA-xxx",
                        "severity": "high",
                    }
                ],
                "effects": [],
                "range": "<4.17.21",
                "fixAvailable": True,
            }
        }
    }
    findings = analyzer._parse_npm_audit(json.dumps(npm_audit_json), "package.json")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].category == Category.CVE


def test_all_findings_are_cve_category():
    analyzer = CveAnalyzer()
    pip_audit_json = [
        {
            "name": "pkg",
            "version": "1.0",
            "vulns": [{"id": "CVE-2024-0001", "fix_versions": ["2.0"], "description": "vuln"}],
        }
    ]
    findings = analyzer._parse_pip_audit(json.dumps(pip_audit_json), "requirements.txt")
    for f in findings:
        assert f.category == Category.CVE
