"""Detection for current OpenClaw skills, configuration, and plugins."""

from __future__ import annotations

import json
from pathlib import Path

from skills_verified.platforms.agent_skills import (
    discover_skill_manifests,
    parse_skill_metadata,
)
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

_OPENCLAW_METADATA_KEYS = {"openclaw", "clawdbot", "clawdis"}


class OpenClawProfile(PlatformProfile):
    name = "openclaw"

    def detect(self, repo_path: Path) -> bool:
        return bool(self.get_detection_evidence(repo_path))

    def get_detection_evidence(self, repo_path: Path) -> list[Path]:
        root = repo_path.resolve()
        evidence: list[Path] = []
        for marker in ("openclaw.plugin.json", ".openclaw/openclaw.json"):
            if (root / marker).is_file():
                evidence.append(Path(marker))
        evidence.extend(
            metadata.manifest_path for metadata in self.get_skill_metadata_all(root)
        )
        return sorted(
            {path for path in evidence if path is not None}, key=Path.as_posix
        )

    def get_config_files(self, repo_path: Path) -> list[ConfigFile]:
        root = repo_path.resolve()
        configs: list[ConfigFile] = []
        for relative_path, config_type in (
            (Path("openclaw.plugin.json"), "manifest"),
            (Path(".openclaw/openclaw.json"), "settings"),
        ):
            path = root / relative_path
            if not path.is_file():
                continue
            try:
                text = safe_read_text(path, root)
            except (RepositoryLimitError, UnsafeRepositoryPath) as exc:
                self._record_read_error(relative_path, exc)
                continue
            try:
                content: dict | str = json.loads(text)
            except json.JSONDecodeError as exc:
                content = text
                if relative_path == Path("openclaw.plugin.json"):
                    self._record_parse_error(relative_path, exc)
                else:
                    # OpenClaw accepts JSON5. Preserve the raw config, but make
                    # the missing semantic parse explicit to report consumers.
                    self._add_diagnostic(
                        "platform_config_parse_deferred",
                        "OpenClaw JSON5 configuration was preserved but not parsed",
                        relative_path,
                        details={"format": "json5", "reason": "parser_unavailable"},
                    )
            if not isinstance(content, (dict, str)):
                self._record_schema_error(
                    relative_path, "OpenClaw configuration root must be an object"
                )
                continue
            configs.append(
                ConfigFile(
                    path=relative_path,
                    platform=self.name,
                    config_type=config_type,
                    content=content,
                )
            )
        return configs

    def get_skill_metadata(self, repo_path: Path) -> SkillMetadata | None:
        metadata = self.get_skill_metadata_all(repo_path)
        return metadata[0] if metadata else None

    def get_skill_metadata_all(self, repo_path: Path) -> list[SkillMetadata]:
        root = repo_path.resolve()
        manifests = set(self._plugin_skill_manifests(root))

        for manifest in discover_skill_manifests(root):
            metadata = parse_skill_metadata(root, manifest, platform=self.name)
            if _OPENCLAW_METADATA_KEYS.intersection(metadata.metadata):
                manifests.add(manifest)

        return [
            parse_skill_metadata(root, manifest, platform=self.name)
            for manifest in sorted(
                manifests, key=lambda path: path.relative_to(root).as_posix()
            )
        ]

    def discover_skill_roots(self, repo_path: Path) -> list[Path]:
        return [
            metadata.skill_root
            for metadata in self.get_skill_metadata_all(repo_path)
            if metadata.skill_root is not None
        ]

    def get_mcp_definitions(self, repo_path: Path) -> list[MCPToolDefinition]:
        # OpenClaw plugin tools are runtime registrations, not Node-RED nodes or
        # MCP definitions. The generic MCP profile handles actual MCP artifacts.
        return []

    def _plugin_skill_manifests(self, repo_path: Path) -> list[Path]:
        root = repo_path.resolve()
        manifest_path = root / "openclaw.plugin.json"
        if not manifest_path.is_file():
            return []
        try:
            text = safe_read_text(manifest_path, root)
        except (RepositoryLimitError, UnsafeRepositoryPath) as exc:
            self._record_read_error(manifest_path.relative_to(root), exc)
            return []
        try:
            plugin = json.loads(text)
        except json.JSONDecodeError as exc:
            self._record_parse_error(manifest_path.relative_to(root), exc)
            return []
        if not isinstance(plugin, dict):
            self._record_schema_error(
                manifest_path.relative_to(root),
                "OpenClaw plugin manifest root must be an object",
            )
            return []
        skills = plugin.get("skills", [])
        if not isinstance(skills, list):
            self._record_schema_error(
                manifest_path.relative_to(root), "skills must be an array"
            )
            return []

        all_manifests = discover_skill_manifests(root)
        declared_roots: list[Path] = []
        for item in skills:
            if not isinstance(item, str):
                continue
            try:
                declared = (root / item).resolve(strict=True)
            except OSError:
                continue
            if declared.is_dir() and declared.is_relative_to(root):
                declared_roots.append(declared)

        return [
            manifest
            for manifest in all_manifests
            if any(manifest.is_relative_to(declared) for declared in declared_roots)
        ]
