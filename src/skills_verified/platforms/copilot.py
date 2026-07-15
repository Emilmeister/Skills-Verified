"""GitHub Copilot project skill discovery."""

from pathlib import Path

from skills_verified.platforms.agent_skills import manifests_under, parse_skill_metadata
from skills_verified.platforms.base import (
    ConfigFile,
    MCPToolDefinition,
    PlatformProfile,
    SkillMetadata,
)


class CopilotProfile(PlatformProfile):
    name = "copilot"

    def detect(self, repo_path: Path) -> bool:
        return bool(self.get_detection_evidence(repo_path))

    def get_detection_evidence(self, repo_path: Path) -> list[Path]:
        root = repo_path.resolve()
        return [
            path.relative_to(root)
            for path in manifests_under(root, (".github", "skills"))
        ]

    def get_config_files(self, repo_path: Path) -> list[ConfigFile]:
        return []

    def get_skill_metadata(self, repo_path: Path) -> SkillMetadata | None:
        metadata = self.get_skill_metadata_all(repo_path)
        return metadata[0] if metadata else None

    def get_skill_metadata_all(self, repo_path: Path) -> list[SkillMetadata]:
        root = repo_path.resolve()
        return [
            parse_skill_metadata(root, manifest, platform=self.name)
            for manifest in manifests_under(root, (".github", "skills"))
        ]

    def discover_skill_roots(self, repo_path: Path) -> list[Path]:
        root = repo_path.resolve()
        return [
            manifest.relative_to(root).parent
            for manifest in manifests_under(root, (".github", "skills"))
        ]

    def get_mcp_definitions(self, repo_path: Path) -> list[MCPToolDefinition]:
        return []
