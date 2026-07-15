from dataclasses import fields

import pytest

from skills_verified.core.models import (
    AnalyzerRun,
    AnalyzerRunStatus,
    Category,
    Diagnostic,
    DiagnosticLevel,
    Evidence,
    Finding,
    PlatformInfo,
    ScanInfo,
    ScannerInfo,
    ScanReport,
    ScanStatus,
    ScopeInfo,
    Severity,
    SourceInfo,
)


def test_security_enums_have_stable_wire_values():
    assert [severity.value for severity in Severity] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "unknown",
    ]
    assert Category.CODE_SAFETY.value == "code_safety"
    assert Category.CVE.value == "cve"
    assert Category.GUARDRAILS.value == "guardrails"
    assert Category.PERMISSIONS.value == "permissions"
    assert Category.SUPPLY_CHAIN.value == "supply_chain"


def test_execution_enums_have_stable_wire_values():
    assert [status.value for status in ScanStatus] == ["complete", "partial", "failed"]
    assert [status.value for status in AnalyzerRunStatus] == [
        "completed",
        "partial",
        "skipped",
        "failed",
    ]
    assert [level.value for level in DiagnosticLevel] == ["info", "warning", "error"]


def test_finding_derives_evidence_location_and_stable_identity():
    finding = Finding(
        title="Test finding",
        description="A test",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="foo.py",
        line_number=10,
        end_line=12,
        analyzer="test",
        evidence=Evidence(kind="source", snippet="dangerous_call()"),
    )
    duplicate = Finding(
        title="Test finding",
        description="A test",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="foo.py",
        line_number=10,
        end_line=12,
        analyzer="test",
        evidence=Evidence(kind="source", snippet="dangerous_call()"),
    )

    assert finding.location is not None
    assert (
        finding.location.path,
        finding.location.start_line,
        finding.location.end_line,
    ) == (
        "foo.py",
        10,
        12,
    )
    assert finding.rule_id == duplicate.rule_id
    assert finding.fingerprint == duplicate.fingerprint


def test_finding_without_file_has_no_location():
    finding = Finding(
        title="CVE found",
        description="desc",
        severity=Severity.CRITICAL,
        category=Category.CVE,
        file_path=None,
        line_number=None,
        analyzer="cve",
        cve_id="CVE-2024-1234",
        confidence=0.9,
    )

    assert finding.location is None
    assert finding.cve_id == "CVE-2024-1234"


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_finding_rejects_invalid_confidence(confidence: float):
    with pytest.raises(ValueError, match="confidence"):
        Finding(
            title="invalid confidence",
            description="desc",
            severity=Severity.INFO,
            category=Category.CODE_SAFETY,
            file_path=None,
            line_number=None,
            analyzer="test",
            confidence=confidence,
        )


def test_scan_report_is_policy_free():
    report = ScanReport(
        scan=ScanInfo(
            status=ScanStatus.COMPLETE,
            started_at="2026-07-13T12:00:00Z",
            duration_ms=15,
            scanner=ScannerInfo("skills-verified", "1.0.0", "2026.07.13"),
        ),
        source=SourceInfo("https://github.com/test/repo", "a" * 40, "b" * 64),
        scope=ScopeInfo(["skills/example"], 2, 0, 100),
        platforms=[PlatformInfo("agent_skills", 1.0, ["skills/example/SKILL.md"])],
        analyzer_runs=[
            AnalyzerRun("pattern", AnalyzerRunStatus.COMPLETED, 2, 0),
        ],
        findings=[],
        diagnostics=[Diagnostic("example", "diagnostic")],
    )

    assert report.schema_version == "1.0"
    assert report.scan.status == ScanStatus.COMPLETE
    assert {field.name for field in fields(report)}.isdisjoint(
        {"score", "grade", "publish", "allow", "deny", "verdict"}
    )
