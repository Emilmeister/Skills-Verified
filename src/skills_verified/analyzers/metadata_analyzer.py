"""Detect prompt injection in skill metadata and repository documentation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Diagnostic, Finding, Severity
from skills_verified.platforms.base import PlatformProfile, SkillMetadata

# ---------------------------------------------------------------------------
# Prompt injection patterns (same set used across the platform-dependent
# analyzers for consistency)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|guidelines|rules)",
        re.IGNORECASE,
    ),
    re.compile(
        r"disregard\s+(your\s+)?(instructions|guidelines)",
        re.IGNORECASE,
    ),
    re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
]

# Files to scan for injection in repo-level documentation
_DOC_FILENAMES = {"SKILL.md", "README.md"}

_DOC_SCAN_EXTENSIONS = {".md"}


class MetadataAnalyzer(Analyzer):
    name = "metadata"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs: Any) -> list[Finding]:
        self.diagnostics = []
        platforms: list[PlatformProfile] = kwargs.get("platforms") or []
        if not platforms:
            return []

        context = kwargs.get("context")
        all_metadata: list[SkillMetadata] = list(
            kwargs.get("metadata") or getattr(context, "metadata", []) or []
        )
        if not all_metadata:
            for platform in platforms:
                meta = platform.get_skill_metadata(repo_path)
                if meta is not None:
                    all_metadata.append(meta)

        findings: list[Finding] = []

        if not all_metadata:
            # Even without metadata, still scan doc files for injection
            findings.extend(self._check_doc_files(repo_path))
            return findings if findings else []

        for meta in all_metadata:
            findings.extend(self._check_name_injection(meta))
            findings.extend(self._check_description_injection(meta))

        findings.extend(self._check_doc_files(repo_path))

        return findings

    # ------------------------------------------------------------------
    # Injection in name field
    # ------------------------------------------------------------------

    def _check_name_injection(self, meta: SkillMetadata) -> list[Finding]:
        findings: list[Finding] = []
        name = meta.name or ""
        if not name:
            return findings

        for pattern in _INJECTION_PATTERNS:
            if pattern.search(name):
                findings.append(
                    Finding(
                        title="Prompt injection in skill name",
                        description=(
                            f"Skill name '{name}' contains a prompt injection "
                            f"pattern: '{pattern.pattern}'. This is a critical "
                            f"attack vector as the name is often included in "
                            f"LLM context."
                        ),
                        severity=Severity.CRITICAL,
                        category=Category.CONFIG_INJECTION,
                        file_path=None,
                        line_number=None,
                        analyzer=self.name,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Injection in description field
    # ------------------------------------------------------------------

    def _check_description_injection(self, meta: SkillMetadata) -> list[Finding]:
        findings: list[Finding] = []
        desc = meta.description or ""
        if not desc:
            return findings

        for pattern in _INJECTION_PATTERNS:
            if pattern.search(desc):
                findings.append(
                    Finding(
                        title="Prompt injection in skill description",
                        description=(
                            f"Skill description contains a prompt injection "
                            f"pattern: '{pattern.pattern}'. "
                            f"Description: {desc[:200]}"
                        ),
                        severity=Severity.CRITICAL,
                        category=Category.CONFIG_INJECTION,
                        file_path=None,
                        line_number=None,
                        analyzer=self.name,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Doc file scanning — SKILL.md, README.md
    # ------------------------------------------------------------------

    def _check_doc_files(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        for doc_name in _DOC_FILENAMES:
            doc_path = repo_path / doc_name
            if not doc_path.is_file():
                continue
            try:
                content = doc_path.read_text(errors="ignore")
            except OSError as exc:
                self.diagnostics.append(
                    Diagnostic(
                        code="documentation_read_error",
                        message=(
                            f"Could not read documentation file: {type(exc).__name__}"
                        ),
                        analyzer=self.name,
                        path=str(doc_path.relative_to(repo_path)),
                    )
                )
                continue

            rel_path = str(doc_path.relative_to(repo_path))
            for line_number, line in enumerate(content.splitlines(), start=1):
                for pattern in _INJECTION_PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            Finding(
                                title=f"Prompt injection in {doc_name}",
                                description=(
                                    f"Documentation file {doc_name} contains "
                                    f"a prompt injection pattern: "
                                    f"'{pattern.pattern}'. "
                                    f"Line: {line.strip()[:150]}"
                                ),
                                severity=Severity.HIGH,
                                category=Category.CONFIG_INJECTION,
                                file_path=rel_path,
                                line_number=line_number,
                                analyzer=self.name,
                            )
                        )

        return findings
