from skills_verified.mcp_server import (
    VERSION,
    tool_aibom,
    tool_scan,
    tool_scan_file,
    tool_version,
)


def test_version():
    assert tool_version() == VERSION


def test_scan_returns_summary(fake_repo_path):
    summary = tool_scan(str(fake_repo_path), only=["pattern", "guardrails"])
    assert "overall_score" in summary
    assert "overall_grade" in summary
    assert "top_findings" in summary
    assert summary["findings_count"] > 0
    assert "pattern" in summary["analyzers_used"]


def test_scan_file(fake_repo_path):
    target = fake_repo_path / "dangerous.py"
    result = tool_scan_file(str(target), "pattern")
    assert "findings" in result
    assert all(f["file_path"] == "dangerous.py" for f in result["findings"])


def test_scan_file_unknown_analyzer(fake_repo_path):
    result = tool_scan_file(str(fake_repo_path), "does_not_exist")
    assert "error" in result


def test_aibom(fake_repo_path):
    bom = tool_aibom(str(fake_repo_path))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert len(bom["components"]) >= 1
    assert len(bom["services"]) >= 1


def test_scan_summary_contains_all_categories(fake_repo_path):
    summary = tool_scan(str(fake_repo_path), only=["pattern"])
    assert "code_safety" in summary["categories"]
    assert "ai_bom" in summary["categories"]
