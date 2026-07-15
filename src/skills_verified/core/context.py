from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from skills_verified.core.models import Diagnostic, DiagnosticLevel, PlatformInfo
from skills_verified.platforms.base import ConfigFile, MCPToolDefinition, SkillMetadata
from skills_verified.platforms.detector import PlatformDetector
from skills_verified.repo import RepositoryLimitError, collect_safe_files
from skills_verified.repo.files import DEFAULT_MAX_TOTAL_BYTES


@dataclass
class ScanContext:
    repo_path: Path
    source_input: str | None = None
    profiles: list = field(default_factory=list)
    skill_roots: list[Path] = field(default_factory=list)
    metadata: list[SkillMetadata] = field(default_factory=list)
    configs: list[ConfigFile] = field(default_factory=list)
    mcp_definitions: list[MCPToolDefinition] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)
    skipped_files: int = 0
    bytes_scanned: int = 0
    inventory_complete: bool = True
    scope_degraded: bool = False
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def platforms(self) -> list[PlatformInfo]:
        infos: list[PlatformInfo] = []
        for profile in self.profiles:
            try:
                evidence = [
                    Path(path).as_posix()
                    for path in profile.get_detection_evidence(self.repo_path)
                ]
            except Exception:
                evidence = []
            infos.append(
                PlatformInfo(name=profile.name, confidence=1.0, evidence=evidence)
            )
        return infos


def analysis_roots(repo_path: Path, context: object | None) -> list[Path]:
    """Return the minimal in-repository roots selected by platform discovery."""
    repo_path = repo_path.resolve()
    configured = getattr(context, "skill_roots", None) or [Path(".")]
    candidates: list[Path] = []
    for root in configured:
        candidate = (repo_path / Path(root)).resolve()
        if candidate == repo_path or candidate.is_relative_to(repo_path):
            if candidate.exists():
                candidates.append(candidate)

    selected: list[Path] = []
    selected_set: set[Path] = set()
    for candidate in sorted(
        set(candidates), key=lambda path: (len(path.parts), str(path))
    ):
        if candidate in selected_set or any(
            parent in selected_set for parent in candidate.parents
        ):
            continue
        selected.append(candidate)
        selected_set.add(candidate)
    return selected or [repo_path]


def iter_analysis_files(repo_path: Path, context: object | None):
    """Yield inventory files that belong to a detected skill root."""
    roots = analysis_roots(repo_path, context)
    inventory = getattr(context, "files", None)
    candidates = inventory if inventory is not None else repo_path.rglob("*")
    root_set = set(roots)
    normalized: list[Path] = []
    for path in candidates:
        candidate = path if path.is_absolute() else repo_path / path
        if not candidate.is_file():
            continue
        absolute = candidate.absolute()
        if absolute in root_set or any(
            parent in root_set for parent in absolute.parents
        ):
            normalized.append(candidate)
    yield from sorted(set(normalized), key=lambda path: path.as_posix())


def _collect_files(context: ScanContext, *, max_total_bytes: int) -> None:
    try:
        inventory = collect_safe_files(
            context.repo_path,
            max_file_bytes=max_total_bytes,
            max_total_bytes=max_total_bytes,
        )
    except (RepositoryLimitError, OSError, ValueError) as exc:
        context.inventory_complete = False
        context.scope_degraded = True
        context.diagnostics.append(
            Diagnostic(
                code="repository_inventory_failed",
                message=f"Repository inventory failed: {type(exc).__name__}: {exc}",
                level=DiagnosticLevel.ERROR,
            )
        )
        return

    context.files = list(inventory.files)
    context.skipped_files = sum(
        skipped.reason not in {"excluded_directory", "internal_symlink_alias"}
        for skipped in inventory.skipped
    )
    context.bytes_scanned = inventory.total_bytes
    internal_aliases = []
    for skipped in inventory.skipped:
        if skipped.reason == "excluded_directory":
            continue
        if skipped.reason == "internal_symlink_alias":
            internal_aliases.append(skipped)
            continue
        context.scope_degraded = True
        context.diagnostics.append(
            Diagnostic(
                code="repository_path_skipped",
                message=f"Repository path was skipped: {skipped.reason}",
                path=skipped.path,
                details={
                    "reason": skipped.reason,
                    "size_bytes": skipped.size_bytes,
                    "target": skipped.target,
                },
            )
        )
    if internal_aliases:
        context.diagnostics.append(
            Diagnostic(
                code="repository_internal_symlink_alias",
                message=(
                    "Internal symlink content is covered through canonical targets"
                ),
                level=DiagnosticLevel.INFO,
                path=internal_aliases[0].path if len(internal_aliases) == 1 else None,
                details={
                    "reason": "internal_symlink_alias",
                    "count": len(internal_aliases),
                    "aliases": [
                        {"path": item.path, "target": item.target}
                        for item in internal_aliases[:100]
                    ],
                },
            )
        )


def build_inventory_context(
    repo_path: Path, *, max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
) -> ScanContext:
    """Inventory an untrusted repository without parsing its contents."""
    context = ScanContext(repo_path=repo_path.resolve())
    _collect_files(context, max_total_bytes=max_total_bytes)
    return context


def enrich_scan_context(context: ScanContext) -> ScanContext:
    """Parse platform data after the inventory has been copied into staging."""
    if not context.inventory_complete:
        return context

    try:
        context.profiles = PlatformDetector().detect(context.repo_path)
    except Exception as exc:
        context.diagnostics.append(
            Diagnostic(
                code="platform_detection_failed",
                message=f"Platform detection failed: {type(exc).__name__}: {exc}",
                level=DiagnosticLevel.ERROR,
            )
        )
        return context

    for profile in context.profiles:
        profile.clear_diagnostics()
        try:
            roots = (
                profile.discover_skill_roots(context.repo_path)
                if hasattr(profile, "discover_skill_roots")
                else []
            )
            context.skill_roots.extend(Path(root) for root in roots)

            metadata_items = (
                profile.get_skill_metadata_all(context.repo_path)
                if hasattr(profile, "get_skill_metadata_all")
                else [profile.get_skill_metadata(context.repo_path)]
            )
            context.metadata.extend(item for item in metadata_items if item is not None)
            context.configs.extend(profile.get_config_files(context.repo_path))
            context.mcp_definitions.extend(
                profile.get_mcp_definitions(context.repo_path)
            )
        except Exception as exc:
            context.scope_degraded = True
            context.diagnostics.append(
                Diagnostic(
                    code="platform_parse_failed",
                    message=f"{profile.name} profile failed: {type(exc).__name__}: {exc}",
                    level=DiagnosticLevel.ERROR,
                    analyzer=f"platform:{profile.name}",
                )
            )
        finally:
            profile_diagnostics = profile.diagnostics
            if any(
                diagnostic.level != DiagnosticLevel.INFO
                for diagnostic in profile_diagnostics
            ):
                context.scope_degraded = True
            context.diagnostics.extend(profile_diagnostics)

    canonical_metadata: dict[str, SkillMetadata] = {}
    metadata_without_manifest: list[SkillMetadata] = []
    for metadata in context.metadata:
        if metadata.manifest_path is None:
            metadata_without_manifest.append(metadata)
            continue
        canonical_metadata.setdefault(metadata.manifest_path.as_posix(), metadata)
    context.metadata = list(canonical_metadata.values()) + metadata_without_manifest

    unique_configs: dict[tuple[str, str], ConfigFile] = {}
    for config in context.configs:
        unique_configs.setdefault((config.platform, config.path.as_posix()), config)
    context.configs = list(unique_configs.values())

    for metadata in context.metadata:
        for error in metadata.validation_errors:
            context.scope_degraded = True
            context.diagnostics.append(
                Diagnostic(
                    code="skill_metadata_invalid",
                    message=error,
                    path=metadata.manifest_path.as_posix()
                    if metadata.manifest_path
                    else None,
                    details={
                        "platform": metadata.platform,
                        "skill_name": metadata.name,
                    },
                )
            )

    if not context.skill_roots:
        context.skill_roots = [Path(".")]
    context.skill_roots = sorted(set(context.skill_roots), key=str)
    return context


def build_scan_context(repo_path: Path) -> ScanContext:
    """Build a complete context for trusted callers outside the main pipeline."""
    return enrich_scan_context(build_inventory_context(repo_path))
