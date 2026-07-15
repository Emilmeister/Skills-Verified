import json
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from skills_verified.core.models import (
    AnalyzerRun,
    AnalyzerRunStatus,
    Category,
    Diagnostic,
    Evidence,
    Finding,
    FindingVerification,
    PlatformInfo,
    ScanInfo,
    ScannerInfo,
    ScanReport,
    ScanStatus,
    ScopeInfo,
    Severity,
    SourceInfo,
    VerificationStatus,
)
from skills_verified.output.json_report import (
    report_to_dict,
    report_to_json,
    save_json_report,
)


def _make_report() -> ScanReport:
    return ScanReport(
        scan=ScanInfo(
            status=ScanStatus.PARTIAL,
            started_at="2026-07-13T12:00:00Z",
            duration_ms=125,
            scanner=ScannerInfo("skills-verified", "1.0.0", "2026.07.13"),
        ),
        source=SourceInfo("https://github.com/test/repo", "a" * 40, "b" * 64),
        scope=ScopeInfo(["skills/example"], 3, 1, 512),
        platforms=[PlatformInfo("agent_skills", 1.0, ["skills/example/SKILL.md"])],
        analyzer_runs=[
            AnalyzerRun("test", AnalyzerRunStatus.COMPLETED, 5, 1),
            AnalyzerRun("optional", AnalyzerRunStatus.SKIPPED, 0, 0, "not_available"),
        ],
        findings=[
            Finding(
                title="Test",
                description="desc",
                severity=Severity.HIGH,
                category=Category.CODE_SAFETY,
                file_path="skills/example/x.py",
                line_number=2,
                end_line=3,
                analyzer="test",
                evidence=Evidence(kind="source", snippet="dangerous()"),
                remediation="Remove the dangerous call.",
                references=["https://example.test/rule"],
                verification=FindingVerification(
                    candidate_id="sha256:" + "a" * 64,
                    status=VerificationStatus.CORROBORATED,
                    method="llm_adversarial_consensus",
                    attempts=3,
                    agreements=2,
                    disagreements=1,
                    inconclusive=0,
                    evidence_matched=True,
                    requested_model="test-model",
                    candidate_prompt_sha256="sha256:" + "c" * 64,
                    verification_prompt_sha256="sha256:" + "d" * 64,
                    generation_response_sha256="sha256:" + "e" * 64,
                    verification_response_sha256=["sha256:" + "f" * 64],
                    co_located_deterministic_rule_ids=["SV-PATTERN-EXAMPLE"],
                ),
            ),
        ],
        diagnostics=[
            Diagnostic("optional_skipped", "Optional analyzer was unavailable")
        ],
    )


def test_report_to_dict_matches_policy_free_contract():
    data = report_to_dict(_make_report())

    assert set(data) == {
        "schema_version",
        "scan",
        "source",
        "scope",
        "platforms",
        "analyzer_runs",
        "findings",
        "summary",
        "diagnostics",
    }
    assert data["schema_version"] == "1.0"
    assert data["scan"]["status"] == "partial"
    assert data["source"]["commit_sha"] == "a" * 40
    assert data["analyzer_runs"][1]["status"] == "skipped"
    assert data["analyzer_runs"][1]["reason"] == "not_available"
    assert data["summary"]["findings_total"] == 1
    assert data["summary"]["by_severity"]["high"] == 1
    assert "overall_score" not in data
    assert "overall_grade" not in data


def test_finding_serializes_location_evidence_and_identity():
    finding = report_to_dict(_make_report())["findings"][0]

    assert finding["severity"] == "high"
    assert finding["category"] == "code_safety"
    assert finding["location"] == {
        "path": "skills/example/x.py",
        "start_line": 2,
        "end_line": 3,
    }
    assert finding["evidence"] == {"kind": "source", "snippet": "dangerous()"}
    assert finding["rule_id"].startswith("SV-TEST-")
    assert finding["fingerprint"].startswith("sha256:")
    assert finding["verification"] == {
        "candidate_id": "sha256:" + "a" * 64,
        "status": "corroborated",
        "method": "llm_adversarial_consensus",
        "attempts": 3,
        "agreements": 2,
        "disagreements": 1,
        "inconclusive": 0,
        "evidence_matched": True,
        "requested_model": "test-model",
        "candidate_prompt_sha256": "sha256:" + "c" * 64,
        "verification_prompt_sha256": "sha256:" + "d" * 64,
        "generation_response_sha256": "sha256:" + "e" * 64,
        "verification_response_sha256": ["sha256:" + "f" * 64],
        "co_located_deterministic_rule_ids": ["SV-PATTERN-EXAMPLE"],
    }


def test_save_json_report_writes_valid_utf8_json(tmp_path: Path):
    out_path = tmp_path / "nested" / "report.json"
    out_path.parent.mkdir()

    save_json_report(_make_report(), out_path)

    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["source"]["input"] == "https://github.com/test/repo"
    assert out_path.read_bytes().endswith(b"\n")


def test_compact_json_is_single_line():
    rendered = report_to_json(_make_report(), pretty=False)

    assert "\n" not in rendered
    assert json.loads(rendered)["schema_version"] == "1.0"


def test_shipped_schema_declares_every_top_level_contract_field():
    schema = json.loads(
        files("skills_verified")
        .joinpath("report.schema.json")
        .read_text(encoding="utf-8")
    )

    assert set(schema["required"]) == set(report_to_dict(_make_report()))
    assert schema["properties"]["schema_version"]["const"] == "1.0"


def test_serialized_report_validates_against_shipped_schema():
    schema = json.loads(
        files("skills_verified")
        .joinpath("report.schema.json")
        .read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    validator.check_schema(schema)
    validator.validate(report_to_dict(_make_report()))


def test_schema_rejects_incomplete_summary_and_untyped_diagnostics():
    schema = json.loads(
        files("skills_verified")
        .joinpath("report.schema.json")
        .read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    data = report_to_dict(_make_report())
    del data["summary"]["by_severity"]["unknown"]

    assert not validator.is_valid(data)

    data = report_to_dict(_make_report())
    data["diagnostics"] = [{}]
    assert not validator.is_valid(data)


def test_schema_requires_non_null_verification_for_llm_findings():
    schema = json.loads(
        files("skills_verified")
        .joinpath("report.schema.json")
        .read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    data = report_to_dict(_make_report())
    data["findings"][0]["analyzer"] = "llm"
    data["findings"][0]["verification"] = None

    assert not validator.is_valid(data)


def test_golden_v1_report_is_schema_valid():
    schema = json.loads(
        files("skills_verified")
        .joinpath("report.schema.json")
        .read_text(encoding="utf-8")
    )
    golden_path = Path(__file__).parent / "fixtures" / "report-v1.golden.json"
    golden = json.loads(golden_path.read_text(encoding="utf-8"))

    Draft202012Validator(schema, format_checker=FormatChecker()).validate(golden)
    assert golden["schema_version"] == "1.0"
