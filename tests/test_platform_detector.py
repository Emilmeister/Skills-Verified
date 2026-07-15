import json
from pathlib import Path

from skills_verified.platforms.cursor import CursorProfile
from skills_verified.platforms.generic_mcp import GenericMCPProfile
from skills_verified.platforms.detector import PlatformDetector
from skills_verified.platforms.openclaw import OpenClawProfile


def _write_skill(path: Path, name: str, extra: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"---\nname: {name}\ndescription: Use {name} for its documented task.\n{extra}---\n"
    )


def test_root_skill_is_platform_neutral(tmp_path):
    _write_skill(tmp_path / "SKILL.md", tmp_path.name)

    detector = PlatformDetector()
    platforms = detector.detect(tmp_path)
    platform_names = [p.name for p in platforms]
    assert "agent_skills" in platform_names
    assert "claude_code" not in platform_names


def test_detects_claude_project_skill(tmp_path):
    _write_skill(tmp_path / ".claude" / "skills" / "my-skill" / "SKILL.md", "my-skill")

    names = [profile.name for profile in PlatformDetector().detect(tmp_path)]

    assert "agent_skills" in names
    assert "claude_code" in names


def test_detects_cursor(tmp_path):
    """.cursorrules triggers cursor platform detection."""
    cursorrules = tmp_path / ".cursorrules"
    cursorrules.write_text("You are a helpful assistant.\n")

    detector = PlatformDetector()
    platforms = detector.detect(tmp_path)
    platform_names = [p.name for p in platforms]
    assert "cursor" in platform_names


def test_detects_generic_mcp(tmp_path):
    """mcp.json triggers generic_mcp platform detection."""
    mcp_json = tmp_path / "mcp.json"
    mcp_json.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Reads a file.",
                        "inputSchema": {},
                    }
                ]
            }
        )
    )

    detector = PlatformDetector()
    platforms = detector.detect(tmp_path)
    platform_names = [p.name for p in platforms]
    assert "generic_mcp" in platform_names


def test_detects_multiple(tmp_path):
    """Repo with both SKILL.md and mcp.json detects both platforms."""
    _write_skill(tmp_path / "multi-platform" / "SKILL.md", "multi-platform")
    mcp_json = tmp_path / "mcp.json"
    mcp_json.write_text(json.dumps({"tools": []}))

    detector = PlatformDetector()
    platforms = detector.detect(tmp_path)
    platform_names = [p.name for p in platforms]
    assert "agent_skills" in platform_names
    assert "generic_mcp" in platform_names


def test_cursor_reads_mdc_rules_and_ignores_old_md_files(tmp_path):
    rules = tmp_path / "package" / ".cursor" / "rules"
    rules.mkdir(parents=True)
    (rules / "security.mdc").write_text("Always validate untrusted input.\n")
    (rules / "not-a-rule.md").write_text("Not an MDC rule.\n")

    profile = CursorProfile()
    configs = profile.get_config_files(tmp_path)

    assert profile.detect(tmp_path)
    assert [config.path for config in configs] == [
        Path("package/.cursor/rules/security.mdc")
    ]


def test_openclaw_uses_plugin_and_skill_metadata_not_node_red(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"node-red": {"nodes": {}}}))
    (tmp_path / "nodes").mkdir()
    assert not OpenClawProfile().detect(tmp_path)

    (tmp_path / "openclaw.plugin.json").write_text(
        json.dumps(
            {
                "id": "example",
                "configSchema": {"type": "object"},
                "skills": ["plugin-skills"],
            }
        )
    )
    _write_skill(
        tmp_path / "plugin-skills" / "plugin-skill" / "SKILL.md",
        "plugin-skill",
    )

    profile = OpenClawProfile()
    assert profile.detect(tmp_path)
    assert profile.discover_skill_roots(tmp_path) == [
        Path("plugin-skills/plugin-skill")
    ]
    assert profile.get_detection_evidence(tmp_path) == [
        Path("openclaw.plugin.json"),
        Path("plugin-skills/plugin-skill/SKILL.md"),
    ]


def test_detects_real_codex_gemini_and_copilot_artifacts(tmp_path):
    _write_skill(
        tmp_path / ".agents" / "skills" / "codex-skill" / "SKILL.md", "codex-skill"
    )
    openai_yaml = (
        tmp_path / ".agents" / "skills" / "codex-skill" / "agents" / "openai.yaml"
    )
    openai_yaml.parent.mkdir()
    openai_yaml.write_text("policy:\n  allow_implicit_invocation: false\n")
    _write_skill(
        tmp_path / ".gemini" / "skills" / "gemini-skill" / "SKILL.md", "gemini-skill"
    )
    _write_skill(
        tmp_path / ".github" / "skills" / "copilot-skill" / "SKILL.md", "copilot-skill"
    )

    names = {profile.name for profile in PlatformDetector().detect(tmp_path)}

    assert {"agent_skills", "codex", "gemini", "copilot"} <= names


def test_generic_mcp_supports_claude_manifest_and_async_tools(tmp_path):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {}}))
    server = tmp_path / "server.py"
    server.write_text(
        "from mcp.server import Server\n"
        "@server.tool()\n"
        "async def search_docs(query: str):\n"
        "    return query\n"
    )

    profile = GenericMCPProfile()
    definitions = profile.get_mcp_definitions(tmp_path)

    assert profile.detect(tmp_path)
    assert any(item.name == "search_docs" for item in definitions)


def test_empty_repo(tmp_path):
    """An empty repo detects no platforms."""
    detector = PlatformDetector()
    platforms = detector.detect(tmp_path)
    assert platforms == []
