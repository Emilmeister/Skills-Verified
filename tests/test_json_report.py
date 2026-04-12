import json
from pathlib import Path

from skills_verified.core.models import (
    Category, CategoryScore, Finding, Grade, Report, Severity,
)
from skills_verified.output.json_report import report_to_dict, save_json_report


def _make_report() -> Report:
    return Report(
        repo_url="https://github.com/test/repo",
        overall_score=82,
        overall_grade=Grade.B,
        categories=[
            CategoryScore(Category.CODE_SAFETY, 95, Grade.A, 2, 0, 1),
        ],
        findings=[
            Finding(
                title="Test",
                description="desc",
                severity=Severity.HIGH,
                category=Category.CODE_SAFETY,
                file_path="x.py",
                line_number=1,
                analyzer="test",
            ),
        ],
        analyzers_used=["test"],
        llm_used=False,
        scan_duration_seconds=1.0,
    )


def test_report_to_dict():
    report = _make_report()
    d = report_to_dict(report)
    assert d["overall_score"] == 82
    assert d["overall_grade"] == "B"
    assert d["repo_url"] == "https://github.com/test/repo"
    assert len(d["findings"]) == 1
    assert d["findings"][0]["severity"] == "high"
    assert d["findings"][0]["category"] == "code_safety"


def test_save_json_report(tmp_path):
    report = _make_report()
    out_path = tmp_path / "report.json"
    save_json_report(report, out_path)
    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert data["overall_grade"] == "B"
    assert len(data["categories"]) == 1


def test_json_is_valid(tmp_path):
    report = _make_report()
    out_path = tmp_path / "report.json"
    save_json_report(report, out_path)
    json.loads(out_path.read_text())
