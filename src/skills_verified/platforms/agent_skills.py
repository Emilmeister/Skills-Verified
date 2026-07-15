"""Platform-neutral support for the open Agent Skills specification."""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

import yaml

from skills_verified.platforms.base import (
    ConfigFile,
    MCPToolDefinition,
    PlatformProfile,
    SkillMetadata,
)
from skills_verified.repo.files import (
    DEFAULT_EXCLUDED_DIRS,
    RepositoryLimitError,
    UnsafeRepositoryPath,
    safe_read_text,
)

_MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_VALID_NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_TOOL_PERMISSION_CATEGORIES = {
    "bash": "shell",
    "edit": "filesystem",
    "glob": "filesystem",
    "grep": "filesystem",
    "notebookedit": "filesystem",
    "read": "filesystem",
    "shell": "shell",
    "terminal": "shell",
    "webfetch": "network",
    "websearch": "network",
    "write": "filesystem",
}


def _tool_permissions(allowed_tools: list[str]) -> list[str]:
    categories = []
    for tool in allowed_tools:
        name = tool.partition("(")[0].casefold()
        category = _TOOL_PERMISSION_CATEGORIES.get(name)
        if category and category not in categories:
            categories.append(category)
    return categories


def discover_skill_manifests(repo_path: Path) -> list[Path]:
    """Return contained ``SKILL.md`` files without following directory links."""
    root = repo_path.resolve()
    if not root.is_dir():
        return []

    manifests: list[Path] = []
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(
            directory
            for directory in dirs
            if directory not in DEFAULT_EXCLUDED_DIRS
            and not (current_path / directory).is_symlink()
        )
        if "SKILL.md" not in files:
            continue

        manifest = current_path / "SKILL.md"
        if manifest.is_symlink():
            continue
        try:
            resolved = manifest.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file() and resolved.is_relative_to(root):
            manifests.append(manifest)

    return sorted(manifests, key=lambda path: path.relative_to(root).as_posix())


def manifests_under(repo_path: Path, directory_parts: tuple[str, ...]) -> list[Path]:
    """Return manifests below a directory sequence such as ``.claude/skills``."""
    root = repo_path.resolve()
    matches: list[Path] = []
    for manifest in discover_skill_manifests(root):
        parts = manifest.relative_to(root).parts
        width = len(directory_parts)
        if any(
            parts[index : index + width] == directory_parts
            and index + width < len(parts) - 1
            for index in range(len(parts))
        ):
            matches.append(manifest)
    return matches


def parse_skill_metadata(
    repo_path: Path,
    manifest: Path,
    *,
    platform: str = "agent_skills",
) -> SkillMetadata:
    """Parse and validate one Agent Skills manifest without executing anything."""
    root = repo_path.resolve()
    relative_manifest = manifest.relative_to(root)
    skill_root = relative_manifest.parent
    errors: list[str] = []

    try:
        text = safe_read_text(manifest, root, max_bytes=_MAX_MANIFEST_BYTES)
    except (RepositoryLimitError, UnsafeRepositoryPath) as exc:
        return SkillMetadata(
            name=None,
            description=None,
            author=None,
            platform=platform,
            skill_root=skill_root,
            manifest_path=relative_manifest,
            validation_errors=[f"manifest_read_error: {exc.__class__.__name__}"],
        )

    frontmatter, parse_error = _parse_frontmatter(text)
    if parse_error:
        errors.append(parse_error)
    frontmatter = frontmatter or {}

    name = frontmatter.get("name")
    if not isinstance(name, str) or not name:
        errors.append("name_required")
        name = None
    else:
        if len(name) > 64 or not _VALID_NAME_RE.fullmatch(name):
            errors.append("name_invalid")
        # The transport directory name is not part of a root-level skill artifact
        # (remote clones and staging use generated directories). Nested skill
        # directories do have a stable artifact-relative name.
        if skill_root != Path(".") and name != manifest.parent.name:
            errors.append("name_must_match_directory")

    description = frontmatter.get("description")
    if not isinstance(description, str) or not description:
        errors.append("description_required")
        description = None
    elif len(description) > 1024:
        errors.append("description_too_long")

    license_name = frontmatter.get("license")
    if license_name is not None and not isinstance(license_name, str):
        errors.append("license_must_be_string")
        license_name = None

    compatibility = frontmatter.get("compatibility")
    if compatibility is not None:
        if not isinstance(compatibility, str) or not compatibility:
            errors.append("compatibility_must_be_non_empty_string")
            compatibility = None
        elif len(compatibility) > 500:
            errors.append("compatibility_too_long")

    extra_metadata = frontmatter.get("metadata", {})
    if not isinstance(extra_metadata, dict):
        errors.append("metadata_must_be_mapping")
        extra_metadata = {}

    allowed_tools_raw = frontmatter.get("allowed-tools")
    allowed_tools: list[str] = []
    if isinstance(allowed_tools_raw, str):
        allowed_tools = allowed_tools_raw.split()
    elif isinstance(allowed_tools_raw, list):
        # Copilot accepts the common vendor extension of a YAML string list.
        allowed_tools = [tool for tool in allowed_tools_raw if isinstance(tool, str)]
        if len(allowed_tools) != len(allowed_tools_raw):
            errors.append("allowed_tools_must_contain_strings")
    elif allowed_tools_raw is not None:
        errors.append("allowed_tools_must_be_space_separated_string")

    # Privilege analysis compares broad capability categories, not platform tool
    # spellings such as ``Bash(git:*)`` or ``Read``.
    permissions = _tool_permissions(allowed_tools)
    legacy_permissions = frontmatter.get("permissions", [])
    if isinstance(legacy_permissions, str):
        legacy_permissions = [legacy_permissions]
    if isinstance(legacy_permissions, list):
        permissions.extend(item for item in legacy_permissions if isinstance(item, str))
    permissions = list(dict.fromkeys(permissions))

    entry_points_raw = frontmatter.get("entry_points", [])
    if isinstance(entry_points_raw, str):
        entry_points_raw = [entry_points_raw]
    entry_points: list[Path] = []
    if isinstance(entry_points_raw, list):
        for item in entry_points_raw:
            if not isinstance(item, str):
                errors.append("entry_points_must_contain_strings")
                continue
            candidate = PurePosixPath(item)
            if (
                not item
                or "\x00" in item
                or "\\" in item
                or candidate.is_absolute()
                or ".." in candidate.parts
            ):
                errors.append("entry_point_must_be_relative")
                continue
            entry_points.append(skill_root.joinpath(*candidate.parts))
    else:
        errors.append("entry_points_must_be_string_or_list")

    author = extra_metadata.get("author", frontmatter.get("author"))
    if not isinstance(author, str):
        author = None

    return SkillMetadata(
        name=name,
        description=description,
        author=author,
        permissions_declared=permissions,
        entry_points=entry_points,
        platform=platform,
        skill_root=skill_root,
        manifest_path=relative_manifest,
        license=license_name,
        compatibility=compatibility,
        metadata=extra_metadata,
        allowed_tools=allowed_tools,
        validation_errors=errors,
    )


def _parse_frontmatter(text: str) -> tuple[dict | None, str | None]:
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return None, "yaml_frontmatter_required"

    for index, line in enumerate(lines[1:], start=1):
        if line.strip() != "---":
            continue
        try:
            parsed = yaml.safe_load("".join(lines[1:index]))
        except yaml.YAMLError:
            return None, "yaml_frontmatter_invalid"
        return (
            (parsed, None)
            if isinstance(parsed, dict)
            else (None, "yaml_frontmatter_mapping_required")
        )

    return None, "yaml_frontmatter_unterminated"


class AgentSkillsProfile(PlatformProfile):
    name = "agent_skills"

    def detect(self, repo_path: Path) -> bool:
        return bool(discover_skill_manifests(repo_path))

    def get_detection_evidence(self, repo_path: Path) -> list[Path]:
        root = repo_path.resolve()
        return [path.relative_to(root) for path in discover_skill_manifests(root)]

    def get_config_files(self, repo_path: Path) -> list[ConfigFile]:
        root = repo_path.resolve()
        configs: list[ConfigFile] = []
        for manifest in discover_skill_manifests(root):
            try:
                content = safe_read_text(manifest, root)
            except (RepositoryLimitError, UnsafeRepositoryPath):
                continue
            configs.append(
                ConfigFile(
                    path=manifest.relative_to(root),
                    platform=self.name,
                    config_type="rules",
                    content=content,
                )
            )
        return configs

    def get_skill_metadata(self, repo_path: Path) -> SkillMetadata | None:
        metadata = self.get_skill_metadata_all(repo_path)
        return metadata[0] if metadata else None

    def get_skill_metadata_all(self, repo_path: Path) -> list[SkillMetadata]:
        root = repo_path.resolve()
        return [
            parse_skill_metadata(root, manifest, platform=self.name)
            for manifest in discover_skill_manifests(root)
        ]

    def discover_skill_roots(self, repo_path: Path) -> list[Path]:
        root = repo_path.resolve()
        return [
            manifest.relative_to(root).parent
            for manifest in discover_skill_manifests(root)
        ]

    def get_mcp_definitions(self, repo_path: Path) -> list[MCPToolDefinition]:
        return []
