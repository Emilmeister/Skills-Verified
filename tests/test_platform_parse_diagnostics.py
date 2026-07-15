import json
from pathlib import Path

import pytest

from skills_verified.analyzers.mcp_analyzer import MCPAnalyzer
from skills_verified.core.models import (
    AnalyzerRunStatus,
    DiagnosticLevel,
    ScanStatus,
)
from skills_verified.core.pipeline import Pipeline


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_codex_skill(root: Path, openai_yaml: str) -> None:
    skill = root / ".agents" / "skills" / "example"
    _write(
        skill / "SKILL.md",
        "---\nname: example\ndescription: Example Codex skill.\n---\n",
    )
    _write(skill / "agents" / "openai.yaml", openai_yaml)


@pytest.mark.parametrize(
    "relative_path",
    [
        ".mcp.json",
        ".claude/settings.json",
        ".cursor/mcp.json",
        "openclaw.plugin.json",
        ".codex-plugin/plugin.json",
    ],
)
def test_invalid_detected_platform_json_makes_scan_partial(
    tmp_path: Path, relative_path: str
):
    _write(tmp_path / relative_path, "{not valid json")

    report = Pipeline([MCPAnalyzer()]).run(tmp_path, repo_url=str(tmp_path))

    matching = [
        diagnostic
        for diagnostic in report.diagnostics
        if diagnostic.code == "platform_config_parse_failed"
        and diagnostic.path == relative_path
    ]
    assert matching
    assert all(item.level == DiagnosticLevel.WARNING for item in matching)
    assert all(item.analyzer.startswith("platform:") for item in matching)
    assert report.scan.status == ScanStatus.PARTIAL
    assert report.analyzer_runs[0].status == AnalyzerRunStatus.COMPLETED
    assert report.findings == []


def test_invalid_codex_openai_yaml_makes_scan_partial(tmp_path: Path):
    _write_codex_skill(tmp_path, "policy: [unterminated")

    report = Pipeline([MCPAnalyzer()]).run(tmp_path, repo_url=str(tmp_path))

    diagnostic = next(
        item
        for item in report.diagnostics
        if item.code == "platform_config_parse_failed"
        and item.analyzer == "platform:codex"
    )
    assert diagnostic.path == ".agents/skills/example/agents/openai.yaml"
    assert diagnostic.details["format"] == "yaml"
    assert report.scan.status == ScanStatus.PARTIAL


def test_valid_json_with_invalid_mcp_root_shape_is_diagnostic(tmp_path: Path):
    _write(tmp_path / "mcp.json", "[]")

    report = Pipeline([MCPAnalyzer()]).run(tmp_path, repo_url=str(tmp_path))

    diagnostic = next(
        item
        for item in report.diagnostics
        if item.code == "platform_config_schema_invalid"
    )
    assert diagnostic.path == "mcp.json"
    assert diagnostic.details["reason"] == "MCP manifest root must be an object"
    assert report.scan.status == ScanStatus.PARTIAL


def test_unparsed_openclaw_json5_is_explicitly_partial(tmp_path: Path):
    _write(tmp_path / ".openclaw/openclaw.json", "{unquoted: true,}")

    report = Pipeline([MCPAnalyzer()]).run(tmp_path, repo_url=str(tmp_path))

    diagnostic = next(
        item
        for item in report.diagnostics
        if item.code == "platform_config_parse_deferred"
    )
    assert diagnostic.path == ".openclaw/openclaw.json"
    assert diagnostic.details == {"format": "json5", "reason": "parser_unavailable"}
    assert report.scan.status == ScanStatus.PARTIAL


@pytest.mark.parametrize(
    ("relative_path", "content"),
    [
        (".mcp.json", {"mcpServers": {}}),
        (".claude/settings.json", {"mcpServers": {}}),
        (".cursor/mcp.json", {"mcpServers": {}}),
        (
            "openclaw.plugin.json",
            {"id": "example", "configSchema": {"type": "object"}, "skills": []},
        ),
        (
            ".codex-plugin/plugin.json",
            {"name": "example", "version": "1.0.0"},
        ),
    ],
)
def test_valid_platform_json_remains_complete(
    tmp_path: Path, relative_path: str, content: dict
):
    _write(tmp_path / relative_path, json.dumps(content))

    report = Pipeline([MCPAnalyzer()]).run(tmp_path, repo_url=str(tmp_path))

    assert report.scan.status == ScanStatus.COMPLETE
    assert report.analyzer_runs[0].status == AnalyzerRunStatus.COMPLETED
    assert not any(
        diagnostic.code.startswith("platform_config_")
        for diagnostic in report.diagnostics
    )


def test_valid_codex_openai_yaml_remains_complete(tmp_path: Path):
    _write_codex_skill(tmp_path, "policy:\n  allow_implicit_invocation: false\n")

    report = Pipeline([MCPAnalyzer()]).run(tmp_path, repo_url=str(tmp_path))

    assert report.scan.status == ScanStatus.COMPLETE
    assert not any(
        diagnostic.code.startswith("platform_config_")
        for diagnostic in report.diagnostics
    )
