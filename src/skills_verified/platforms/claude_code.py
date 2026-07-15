import json
import re
from pathlib import Path

from skills_verified.platforms.agent_skills import manifests_under, parse_skill_metadata
from skills_verified.platforms.base import (
    ConfigFile,
    MCPToolDefinition,
    PlatformProfile,
    SkillMetadata,
)
from skills_verified.repo.files import (
    RepositoryLimitError,
    UnsafeRepositoryPath,
    safe_read_text,
)

_DETECTION_MARKERS = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/config.json",
    ".claude-plugin/plugin.json",
    ".mcp.json",
    "CLAUDE.md",
)

_TOOL_DECORATOR_RE = re.compile(
    r"""@server\.(call_tool|tool)\s*\("""
    r"""|server\.tool\s*\("""
)


class ClaudeCodeProfile(PlatformProfile):
    name = "claude_code"

    # ------------------------------------------------------------------
    # detection
    # ------------------------------------------------------------------

    def detect(self, repo_path: Path) -> bool:
        return bool(self.get_detection_evidence(repo_path))

    def get_detection_evidence(self, repo_path: Path) -> list[Path]:
        root = repo_path.resolve()
        evidence = [
            Path(marker) for marker in _DETECTION_MARKERS if (root / marker).is_file()
        ]
        evidence.extend(
            path.relative_to(root)
            for path in manifests_under(root, (".claude", "skills"))
        )
        return sorted(set(evidence), key=Path.as_posix)

    # ------------------------------------------------------------------
    # config files
    # ------------------------------------------------------------------

    def get_config_files(self, repo_path: Path) -> list[ConfigFile]:
        root = repo_path.resolve()
        configs: list[ConfigFile] = []

        for relative_path in (
            ".claude/settings.json",
            ".claude/settings.local.json",
            ".claude/config.json",
            ".mcp.json",
        ):
            self._try_load_json(root / relative_path, root, "settings", configs)

        self._try_load_json(
            root / ".claude-plugin" / "plugin.json",
            root,
            "manifest",
            configs,
        )

        # CLAUDE.md
        claude_md = root / "CLAUDE.md"
        if claude_md.is_file():
            try:
                text = safe_read_text(claude_md, root)
                configs.append(
                    ConfigFile(
                        path=claude_md.relative_to(root),
                        platform=self.name,
                        config_type="rules",
                        content=text,
                    )
                )
            except (RepositoryLimitError, UnsafeRepositoryPath):
                pass

        return configs

    # ------------------------------------------------------------------
    # skill metadata
    # ------------------------------------------------------------------

    def get_skill_metadata(self, repo_path: Path) -> SkillMetadata | None:
        metadata = self.get_skill_metadata_all(repo_path)
        return metadata[0] if metadata else None

    def get_skill_metadata_all(self, repo_path: Path) -> list[SkillMetadata]:
        root = repo_path.resolve()
        return [
            parse_skill_metadata(root, manifest, platform=self.name)
            for manifest in manifests_under(root, (".claude", "skills"))
        ]

    def discover_skill_roots(self, repo_path: Path) -> list[Path]:
        root = repo_path.resolve()
        return [
            manifest.relative_to(root).parent
            for manifest in manifests_under(root, (".claude", "skills"))
        ]

    # ------------------------------------------------------------------
    # MCP definitions
    # ------------------------------------------------------------------

    def get_mcp_definitions(self, repo_path: Path) -> list[MCPToolDefinition]:
        root = repo_path.resolve()
        definitions: list[MCPToolDefinition] = []

        # From Claude settings and the team-shared .mcp.json file.
        for settings_path in (
            root / ".claude" / "settings.json",
            root / ".mcp.json",
        ):
            if not settings_path.is_file():
                continue
            try:
                text = safe_read_text(settings_path, root)
            except (RepositoryLimitError, UnsafeRepositoryPath) as exc:
                self._record_read_error(settings_path.relative_to(root), exc)
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                self._record_parse_error(settings_path.relative_to(root), exc)
                continue
            if not isinstance(data, dict):
                self._record_schema_error(
                    settings_path.relative_to(root),
                    "Claude settings root must be an object",
                )
                continue
            servers = data.get("mcpServers", {})
            if not isinstance(servers, dict):
                self._record_schema_error(
                    settings_path.relative_to(root), "mcpServers must be an object"
                )
                continue
            for server_name, server_cfg in servers.items():
                if not isinstance(server_cfg, dict):
                    continue
                definitions.append(
                    MCPToolDefinition(
                        name=server_name,
                        description=server_cfg.get("description", ""),
                        input_schema=server_cfg.get("inputSchema", {}),
                        source_file=settings_path.relative_to(root),
                        raw_definition=server_cfg,
                    )
                )

        # Scan Python files for tool decorators
        definitions.extend(self._scan_python_tools(root))

        return definitions

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _try_load_json(
        self,
        path: Path,
        repo_path: Path,
        config_type: str,
        out: list[ConfigFile],
    ) -> None:
        if not path.is_file():
            return
        try:
            text = safe_read_text(path, repo_path)
        except (RepositoryLimitError, UnsafeRepositoryPath) as exc:
            self._record_read_error(path.relative_to(repo_path), exc)
            return
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            self._record_parse_error(path.relative_to(repo_path), exc)
            return
        if not isinstance(data, dict):
            self._record_schema_error(
                path.relative_to(repo_path), "Configuration root must be an object"
            )
            return
        out.append(
            ConfigFile(
                path=path.relative_to(repo_path),
                platform=self.name,
                config_type=config_type,
                content=data,
            )
        )

    def _scan_python_tools(self, repo_path: Path) -> list[MCPToolDefinition]:
        """Scan .py files for ``@server.call_tool`` / ``server.tool()`` patterns."""
        definitions: list[MCPToolDefinition] = []
        for py_file in repo_path.rglob("*.py"):
            if not py_file.is_file():
                continue
            try:
                content = safe_read_text(py_file, repo_path)
            except (RepositoryLimitError, UnsafeRepositoryPath):
                continue

            for match in _TOOL_DECORATOR_RE.finditer(content):
                # Try to extract the function name on the next def line
                rest = content[match.end() :]
                func_name = self._extract_func_name(rest)
                definitions.append(
                    MCPToolDefinition(
                        name=func_name or "unknown",
                        description="",
                        input_schema={},
                        source_file=py_file.relative_to(repo_path),
                    )
                )
        return definitions

    @staticmethod
    def _extract_func_name(text_after_decorator: str) -> str | None:
        """Find the first ``def <name>`` after a decorator match."""
        for line in text_after_decorator.splitlines():
            stripped = line.strip()
            m = re.match(r"(?:async\s+)?def\s+(\w+)\s*\(", stripped)
            if m:
                return m.group(1)
            # Stop searching if we hit another decorator or class
            if stripped.startswith("@") or stripped.startswith("class "):
                break
        return None
