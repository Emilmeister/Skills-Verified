import json
from pathlib import Path

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


class CursorProfile(PlatformProfile):
    name = "cursor"

    # ------------------------------------------------------------------
    # detection
    # ------------------------------------------------------------------

    def detect(self, repo_path: Path) -> bool:
        return bool(self.get_detection_evidence(repo_path))

    def get_detection_evidence(self, repo_path: Path) -> list[Path]:
        root = repo_path.resolve()
        evidence = [path.relative_to(root) for path in self._rule_files(root)]
        for marker in (
            ".cursorrules",
            ".cursor/mcp.json",
            ".cursor-plugin/plugin.json",
        ):
            if (root / marker).is_file():
                evidence.append(Path(marker))
        return sorted(set(evidence), key=Path.as_posix)

    # ------------------------------------------------------------------
    # config files
    # ------------------------------------------------------------------

    def get_config_files(self, repo_path: Path) -> list[ConfigFile]:
        root = repo_path.resolve()
        configs: list[ConfigFile] = []

        # .cursorrules (text)
        cursorrules = root / ".cursorrules"
        if cursorrules.is_file():
            try:
                text = safe_read_text(cursorrules, root)
                configs.append(
                    ConfigFile(
                        path=cursorrules.relative_to(root),
                        platform=self.name,
                        config_type="rules",
                        content=text,
                    )
                )
            except (RepositoryLimitError, UnsafeRepositoryPath):
                pass

        # Project rules use MDC and may occur in nested monorepo packages.
        for mdc_file in self._rule_files(root):
            try:
                text = safe_read_text(mdc_file, root)
                configs.append(
                    ConfigFile(
                        path=mdc_file.relative_to(root),
                        platform=self.name,
                        config_type="rules",
                        content=text,
                    )
                )
            except (RepositoryLimitError, UnsafeRepositoryPath):
                pass

        # .cursor/mcp.json (JSON)
        mcp_json = root / ".cursor" / "mcp.json"
        if mcp_json.is_file():
            try:
                text = safe_read_text(mcp_json, root)
            except (RepositoryLimitError, UnsafeRepositoryPath) as exc:
                self._record_read_error(mcp_json.relative_to(root), exc)
            else:
                try:
                    data = json.loads(text)
                except json.JSONDecodeError as exc:
                    self._record_parse_error(mcp_json.relative_to(root), exc)
                else:
                    if isinstance(data, dict):
                        configs.append(
                            ConfigFile(
                                path=mcp_json.relative_to(root),
                                platform=self.name,
                                config_type="settings",
                                content=data,
                            )
                        )
                    else:
                        self._record_schema_error(
                            mcp_json.relative_to(root),
                            "Cursor MCP configuration root must be an object",
                        )

        plugin_manifest = root / ".cursor-plugin" / "plugin.json"
        if plugin_manifest.is_file():
            try:
                text = safe_read_text(plugin_manifest, root)
            except (RepositoryLimitError, UnsafeRepositoryPath) as exc:
                self._record_read_error(plugin_manifest.relative_to(root), exc)
            else:
                try:
                    data = json.loads(text)
                except json.JSONDecodeError as exc:
                    self._record_parse_error(plugin_manifest.relative_to(root), exc)
                else:
                    if isinstance(data, dict):
                        configs.append(
                            ConfigFile(
                                path=plugin_manifest.relative_to(root),
                                platform=self.name,
                                config_type="manifest",
                                content=data,
                            )
                        )
                    else:
                        self._record_schema_error(
                            plugin_manifest.relative_to(root),
                            "Cursor plugin manifest root must be an object",
                        )

        return configs

    # ------------------------------------------------------------------
    # skill metadata
    # ------------------------------------------------------------------

    def get_skill_metadata(self, repo_path: Path) -> SkillMetadata | None:
        return None

    # ------------------------------------------------------------------
    # MCP definitions
    # ------------------------------------------------------------------

    def get_mcp_definitions(self, repo_path: Path) -> list[MCPToolDefinition]:
        root = repo_path.resolve()
        definitions: list[MCPToolDefinition] = []

        mcp_json = root / ".cursor" / "mcp.json"
        if not mcp_json.is_file():
            return definitions

        try:
            text = safe_read_text(mcp_json, root)
        except (RepositoryLimitError, UnsafeRepositoryPath) as exc:
            self._record_read_error(mcp_json.relative_to(root), exc)
            return definitions
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            self._record_parse_error(mcp_json.relative_to(root), exc)
            return definitions

        if not isinstance(data, dict):
            self._record_schema_error(
                mcp_json.relative_to(root),
                "Cursor MCP configuration root must be an object",
            )
            return definitions

        servers = data.get("mcpServers", {})
        if not isinstance(servers, dict):
            self._record_schema_error(
                mcp_json.relative_to(root), "mcpServers must be an object"
            )
            return definitions

        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue
            definitions.append(
                MCPToolDefinition(
                    name=server_name,
                    description=server_cfg.get("description", ""),
                    input_schema=server_cfg.get("inputSchema", {}),
                    source_file=mcp_json.relative_to(root),
                    raw_definition=server_cfg,
                )
            )

        return definitions

    @staticmethod
    def _rule_files(repo_path: Path) -> list[Path]:
        root = repo_path.resolve()
        if not root.is_dir():
            return []

        rules: list[Path] = []
        for candidate in root.rglob("*.mdc"):
            if not candidate.is_file() or candidate.is_symlink():
                continue
            parts = candidate.relative_to(root).parts
            if any(
                parts[index : index + 2] == (".cursor", "rules")
                for index in range(len(parts))
            ):
                try:
                    resolved = candidate.resolve(strict=True)
                except OSError:
                    continue
                if resolved.is_relative_to(root):
                    rules.append(candidate)
        return sorted(rules, key=lambda path: path.relative_to(root).as_posix())
