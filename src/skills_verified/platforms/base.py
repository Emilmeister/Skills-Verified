from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skills_verified.core.models import Diagnostic, DiagnosticLevel


@dataclass
class ConfigFile:
    path: Path  # relative to repo root
    platform: str
    config_type: str  # "settings", "hooks", "rules", "manifest"
    content: dict | str  # parsed content


@dataclass
class SkillMetadata:
    name: str | None
    description: str | None
    author: str | None
    permissions_declared: list[str] = field(default_factory=list)
    entry_points: list[Path] = field(default_factory=list)
    platform: str = ""
    skill_root: Path | None = None
    manifest_path: Path | None = None
    license: str | None = None
    compatibility: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    allowed_tools: list[str] = field(default_factory=list)
    validation_errors: list[str] = field(default_factory=list)


@dataclass
class MCPToolDefinition:
    name: str
    description: str
    input_schema: dict
    source_file: Path
    raw_definition: dict = field(default_factory=dict)


class PlatformProfile(ABC):
    name: str = "base"

    @property
    def diagnostics(self) -> list[Diagnostic]:
        return list(getattr(self, "_diagnostics", []))

    def clear_diagnostics(self) -> None:
        self._diagnostics: list[Diagnostic] = []

    def _add_diagnostic(
        self,
        code: str,
        message: str,
        path: Path | str,
        *,
        level: DiagnosticLevel = DiagnosticLevel.WARNING,
        details: dict[str, Any] | None = None,
    ) -> None:
        diagnostic = Diagnostic(
            code=code,
            message=message,
            level=level,
            analyzer=f"platform:{self.name}",
            path=Path(path).as_posix(),
            details=details or {},
        )
        existing = getattr(self, "_diagnostics", [])
        if not any(
            item.code == diagnostic.code and item.path == diagnostic.path
            for item in existing
        ):
            existing.append(diagnostic)
        self._diagnostics = existing

    def _record_parse_error(
        self,
        path: Path | str,
        error: Exception,
        *,
        format_name: str = "JSON",
    ) -> None:
        details: dict[str, Any] = {
            "format": format_name.lower(),
            "error_type": type(error).__name__,
        }
        for attribute in ("lineno", "colno"):
            value = getattr(error, attribute, None)
            if isinstance(value, int):
                details[attribute] = value
        self._add_diagnostic(
            "platform_config_parse_failed",
            f"{self.name} configuration could not be parsed as {format_name}",
            path,
            details=details,
        )

    def _record_read_error(self, path: Path | str, error: Exception) -> None:
        self._add_diagnostic(
            "platform_config_read_failed",
            f"{self.name} configuration could not be read safely",
            path,
            details={"error_type": type(error).__name__},
        )

    def _record_schema_error(self, path: Path | str, reason: str) -> None:
        self._add_diagnostic(
            "platform_config_schema_invalid",
            f"{self.name} configuration has an invalid structure",
            path,
            details={"reason": reason},
        )

    @abstractmethod
    def detect(self, repo_path: Path) -> bool:
        """Check if repository belongs to this platform."""

    @abstractmethod
    def get_config_files(self, repo_path: Path) -> list[ConfigFile]:
        """Return all platform config files."""

    @abstractmethod
    def get_skill_metadata(self, repo_path: Path) -> SkillMetadata | None:
        """Extract skill/plugin metadata if present."""

    @abstractmethod
    def get_mcp_definitions(self, repo_path: Path) -> list[MCPToolDefinition]:
        """Extract MCP tool definitions if present."""

    def get_detection_evidence(self, repo_path: Path) -> list[Path]:
        """Return repository-relative artifacts that caused detection."""
        return []

    def discover_skill_roots(self, repo_path: Path) -> list[Path]:
        """Return repository-relative skill roots owned by this profile."""
        metadata = self.get_skill_metadata(repo_path)
        return [metadata.skill_root] if metadata and metadata.skill_root else []

    def get_skill_metadata_all(self, repo_path: Path) -> list[SkillMetadata]:
        """Extract metadata for every skill owned by this profile.

        The singular method remains for callers written before multi-skill
        repositories were supported.
        """
        metadata = self.get_skill_metadata(repo_path)
        return [metadata] if metadata else []
