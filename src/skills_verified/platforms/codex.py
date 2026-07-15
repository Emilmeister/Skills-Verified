"""Codex-specific skill and plugin artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

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


class CodexProfile(PlatformProfile):
    name = "codex"

    def detect(self, repo_path: Path) -> bool:
        return bool(self.get_detection_evidence(repo_path))

    def get_detection_evidence(self, repo_path: Path) -> list[Path]:
        root = repo_path.resolve()
        evidence: list[Path] = []
        plugin = root / ".codex-plugin" / "plugin.json"
        if plugin.is_file():
            evidence.append(plugin.relative_to(root))
        evidence.extend(
            path.relative_to(root) for _, path in self._openai_metadata(root)
        )
        return sorted(set(evidence), key=Path.as_posix)

    def get_config_files(self, repo_path: Path) -> list[ConfigFile]:
        root = repo_path.resolve()
        configs: list[ConfigFile] = []
        plugin = root / ".codex-plugin" / "plugin.json"
        if plugin.is_file():
            try:
                text = safe_read_text(plugin, root)
            except (RepositoryLimitError, UnsafeRepositoryPath) as exc:
                self._record_read_error(plugin.relative_to(root), exc)
                content = None
            else:
                try:
                    content = json.loads(text)
                except json.JSONDecodeError as exc:
                    self._record_parse_error(plugin.relative_to(root), exc)
                    content = None
            if isinstance(content, dict):
                configs.append(
                    ConfigFile(
                        path=plugin.relative_to(root),
                        platform=self.name,
                        config_type="manifest",
                        content=content,
                    )
                )
            elif content is not None:
                self._record_schema_error(
                    plugin.relative_to(root),
                    "Codex plugin manifest root must be an object",
                )

        for _, openai_yaml in self._openai_metadata(root):
            try:
                text = safe_read_text(openai_yaml, root)
            except (RepositoryLimitError, UnsafeRepositoryPath) as exc:
                self._record_read_error(openai_yaml.relative_to(root), exc)
                continue
            try:
                content = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                self._record_parse_error(
                    openai_yaml.relative_to(root), exc, format_name="YAML"
                )
                continue
            if isinstance(content, dict):
                configs.append(
                    ConfigFile(
                        path=openai_yaml.relative_to(root),
                        platform=self.name,
                        config_type="manifest",
                        content=content,
                    )
                )
            else:
                self._record_schema_error(
                    openai_yaml.relative_to(root),
                    "Codex OpenAI metadata root must be an object",
                )
        return configs

    def get_skill_metadata(self, repo_path: Path) -> SkillMetadata | None:
        metadata = self.get_skill_metadata_all(repo_path)
        return metadata[0] if metadata else None

    def get_skill_metadata_all(self, repo_path: Path) -> list[SkillMetadata]:
        root = repo_path.resolve()
        return [
            parse_skill_metadata(root, manifest, platform=self.name)
            for manifest, _ in self._openai_metadata(root)
        ]

    def discover_skill_roots(self, repo_path: Path) -> list[Path]:
        root = repo_path.resolve()
        return [
            manifest.relative_to(root).parent
            for manifest, _ in self._openai_metadata(root)
        ]

    def get_mcp_definitions(self, repo_path: Path) -> list[MCPToolDefinition]:
        return []

    @staticmethod
    def _openai_metadata(repo_path: Path) -> list[tuple[Path, Path]]:
        pairs: list[tuple[Path, Path]] = []
        for manifest in discover_skill_manifests(repo_path):
            openai_yaml = manifest.parent / "agents" / "openai.yaml"
            if openai_yaml.is_file() and not openai_yaml.is_symlink():
                pairs.append((manifest, openai_yaml))
        return pairs
