import hashlib
import logging
import re
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from skills_verified.analyzers.shell_utils import detect_shell_dialect
from skills_verified.core.analyzer import Analyzer
from skills_verified.core.context import iter_analysis_files
from skills_verified.core.models import (
    Category,
    Diagnostic,
    Evidence,
    Finding,
    Severity,
)
from skills_verified.data.loader import SignatureLoader

logger = logging.getLogger(__name__)

CAMPAIGN_SCAN_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".sh",
    ".ps1",
    ".rb",
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
}

MAX_HASH_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


class KnownThreatsAnalyzer(Analyzer):
    name = "known_threats"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []
        loader = SignatureLoader()
        self._malicious_authors: list[dict] = loader.load_authors(
            "malicious_authors.yaml",
        )
        self._malicious_hashes: list[dict] = loader.load_hashes(
            "malicious_hashes.yaml",
        )
        self._campaigns: list[dict] = loader.load_campaigns(
            "campaign_signatures.yaml",
        )

        # Pre-build a lowercase set for fast author lookups.
        self._author_names_lower: dict[str, dict] = {
            entry["name"].lower(): entry
            for entry in self._malicious_authors
            if "name" in entry
        }

        # Pre-build a hash lookup dict.
        self._hash_lookup: dict[str, dict] = {
            entry["sha256"]: entry
            for entry in self._malicious_hashes
            if "sha256" in entry
        }

        # Pre-compile campaign patterns.
        self._compiled_campaigns: list[dict] = []
        for campaign in self._campaigns:
            compiled_patterns: list[dict] = []
            for pat_entry in campaign.get("patterns", []):
                try:
                    compiled = re.compile(pat_entry["pattern"])
                    compiled_patterns.append(
                        {
                            "regex": compiled,
                            "severity": getattr(
                                Severity,
                                pat_entry.get("severity", "HIGH"),
                            ),
                            "description": pat_entry.get("description", ""),
                            "standalone": pat_entry.get("standalone", False) is True,
                        }
                    )
                except re.error:
                    logger.warning(
                        "Failed to compile campaign pattern in %s: %s",
                        campaign.get("id", "?"),
                        pat_entry.get("pattern", "?"),
                    )
            self._compiled_campaigns.append(
                {
                    "id": campaign.get("id", ""),
                    "name": campaign.get("name", ""),
                    "patterns": compiled_patterns,
                    "indicators": campaign.get("indicators", {}),
                }
            )

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        self.diagnostics = []
        findings: list[Finding] = []

        context = kwargs.get("context")
        metadata = list(
            kwargs.get("metadata")
            or getattr(context, "metadata", [])
            or [
                item
                for item in (kwargs.get("platforms") or [])
                if hasattr(item, "author")
            ]
        )

        findings.extend(self._check_authors(metadata))
        findings.extend(
            self._check_source_repository(getattr(context, "source_input", None))
        )
        files = tuple(iter_analysis_files(repo_path, context))
        findings.extend(self._check_file_hashes(repo_path, files))
        findings.extend(self._check_campaigns(repo_path, files))

        return findings

    # ------------------------------------------------------------------
    # Author check
    # ------------------------------------------------------------------

    def _check_authors(self, metadata_items: list) -> list[Finding]:
        findings: list[Finding] = []
        for metadata in metadata_items:
            author = getattr(metadata, "author", None)
            if not author:
                continue

            author_lower = author.lower()
            if author_lower in self._author_names_lower:
                entry = self._author_names_lower[author_lower]
                findings.append(
                    Finding(
                        title=f"Known malicious author: {author}",
                        description=(
                            f"Author '{author}' is listed in the malicious authors database. "
                            f"Source: {entry.get('source', 'N/A')}. "
                            f"{entry.get('description', '')}"
                        ),
                        severity=Severity.CRITICAL,
                        category=Category.SUPPLY_CHAIN,
                        file_path=None,
                        line_number=None,
                        analyzer=self.name,
                        confidence=1.0,
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # Source repository check
    # ------------------------------------------------------------------

    def _check_source_repository(self, source: str | None) -> list[Finding]:
        if not source:
            return []
        namespaces = self._source_namespaces(source)
        findings: list[Finding] = []
        for namespace in namespaces:
            entry = self._author_names_lower.get(namespace.casefold())
            if entry is None:
                continue
            author = entry.get("name", namespace)
            findings.append(
                Finding(
                    title=f"Source namespace matches known malicious author: {author}",
                    description=(
                        f"Repository source namespace '{namespace}' exactly matches known "
                        f"malicious author '{author}'. Source: {entry.get('source', 'N/A')}."
                    ),
                    severity=Severity.HIGH,
                    category=Category.SUPPLY_CHAIN,
                    file_path=None,
                    line_number=None,
                    analyzer=self.name,
                    confidence=0.9,
                    rule_id="SV-KNOWN-THREATS-SOURCE-AUTHOR",
                    evidence=Evidence(kind="source", snippet=source[:500]),
                    remediation=(
                        "Verify repository provenance and the cited threat-intelligence "
                        "record before trusting artifacts from this namespace."
                    ),
                )
            )
        return findings

    @staticmethod
    def _source_namespaces(source: str) -> list[str]:
        scp_match = re.fullmatch(r"[^@\s]+@[^:\s]+:(?P<path>[^?#]+)", source)
        if scp_match:
            path = scp_match.group("path")
        else:
            try:
                parsed = urlsplit(source)
            except ValueError:
                return []
            if parsed.scheme not in {"https", "ssh"} or not parsed.hostname:
                return []
            path = parsed.path
        parts = [part for part in path.strip("/").split("/") if part]
        return parts[:-1] if len(parts) >= 2 else []

    # ------------------------------------------------------------------
    # File hash check
    # ------------------------------------------------------------------

    def _check_file_hashes(
        self, repo_path: Path, files: Iterable[Path]
    ) -> list[Finding]:
        if not self._hash_lookup:
            return []

        findings: list[Finding] = []
        for file_path in files:
            if not file_path.is_file():
                continue
            # Skip .git directory internals.
            try:
                rel = file_path.relative_to(repo_path)
            except ValueError:
                continue
            if rel.parts and rel.parts[0] == ".git":
                continue

            try:
                size = file_path.stat().st_size
            except OSError as exc:
                self._diagnostic(
                    "file_stat_error",
                    f"Could not stat file for hash lookup: {type(exc).__name__}",
                    str(rel),
                )
                continue
            if size > MAX_HASH_FILE_SIZE:
                continue

            file_hash = self._compute_sha256(file_path)
            if file_hash is None:
                self._diagnostic(
                    "file_hash_read_error",
                    "Could not read file for hash lookup",
                    str(rel),
                )
                continue

            if file_hash in self._hash_lookup:
                entry = self._hash_lookup[file_hash]
                findings.append(
                    Finding(
                        title=f"Known malicious file hash: {entry.get('name', file_hash[:16])}",
                        description=(
                            f"File '{rel}' matches SHA256 hash of known malicious file. "
                            f"Hash: {file_hash}. "
                            f"Severity: {entry.get('severity', 'CRITICAL')}."
                        ),
                        severity=getattr(
                            Severity,
                            entry.get("severity", "CRITICAL"),
                            Severity.CRITICAL,
                        ),
                        category=Category.SUPPLY_CHAIN,
                        file_path=str(rel),
                        line_number=None,
                        analyzer=self.name,
                        confidence=1.0,
                    )
                )
        return findings

    @staticmethod
    def _compute_sha256(file_path: Path) -> str | None:
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return None

    # ------------------------------------------------------------------
    # Campaign pattern check
    # ------------------------------------------------------------------

    def _check_campaigns(self, repo_path: Path, files: Iterable[Path]) -> list[Finding]:
        findings: list[Finding] = []
        files = tuple(files)

        for campaign in self._compiled_campaigns:
            campaign_id = campaign["id"]
            campaign_name = campaign["name"]
            indicators = campaign.get("indicators", {})
            expected_files = {
                filename.casefold(): filename
                for filename in indicators.get("files", [])
                if isinstance(filename, str) and filename
            }
            expected_strings = {
                value.casefold(): value
                for value in indicators.get("strings", [])
                if isinstance(value, str) and value
            }
            matched_files: set[str] = set()
            matched_strings_by_file: dict[str, dict[str, str]] = {}

            for file_path in files:
                if not file_path.is_file():
                    continue
                try:
                    rel = file_path.relative_to(repo_path)
                except ValueError:
                    continue
                if rel.parts and rel.parts[0] == ".git":
                    continue
                if file_path.name.casefold() in expected_files:
                    matched_files.add(str(rel))
                if (
                    file_path.suffix.lower() not in CAMPAIGN_SCAN_EXTENSIONS
                    and detect_shell_dialect(file_path) is None
                ):
                    continue

                try:
                    content = file_path.read_text(errors="ignore")
                except OSError as exc:
                    self._diagnostic(
                        "source_read_error",
                        f"Could not read source file: {type(exc).__name__}",
                        str(rel),
                    )
                    continue

                content_casefold = content.casefold()
                for normalized, original in expected_strings.items():
                    if normalized in content_casefold:
                        matched_strings_by_file.setdefault(str(rel), {})[original] = (
                            str(rel)
                        )

                rel_str = str(rel)
                for line_number, line in enumerate(content.splitlines(), start=1):
                    for pat in campaign["patterns"]:
                        if pat["standalone"] and pat["regex"].search(line):
                            findings.append(
                                Finding(
                                    title=f"Campaign match [{campaign_id}] {campaign_name}",
                                    description=(
                                        f"{pat['description']} "
                                        f"(Campaign: {campaign_name})"
                                    ),
                                    severity=pat["severity"],
                                    category=Category.SUPPLY_CHAIN,
                                    file_path=rel_str,
                                    line_number=line_number,
                                    analyzer=self.name,
                                    confidence=0.85,
                                    rule_id=(f"SV-KNOWN-THREATS-{campaign_id}-PATTERN"),
                                    evidence=Evidence(
                                        kind="source",
                                        snippet=line.strip()[:500],
                                    ),
                                    remediation=(
                                        "Quarantine the skill and review the matched "
                                        "behavior against the cited campaign before use."
                                    ),
                                )
                            )

            min_file_matches = indicators.get("min_file_matches", 1)
            min_string_matches = indicators.get("min_string_matches", 1)
            min_file_matches = (
                max(1, min_file_matches) if isinstance(min_file_matches, int) else 1
            )
            min_string_matches = (
                max(1, min_string_matches) if isinstance(min_string_matches, int) else 1
            )
            correlated_files = sorted(
                path
                for path in matched_files
                if len(matched_strings_by_file.get(path, {})) >= min_string_matches
            )
            if len(correlated_files) < min_file_matches:
                continue

            strings = sorted(
                {
                    value
                    for path in correlated_files
                    for value in matched_strings_by_file[path]
                },
                key=str.casefold,
            )
            string_evidence = ", ".join(
                f"{value}@{next(path for path in correlated_files if value in matched_strings_by_file[path])}"
                for value in strings
            )
            evidence = (
                f"files={', '.join(correlated_files)}; strings={string_evidence}"
            )[:500]
            findings.append(
                Finding(
                    title=(
                        f"Correlated campaign indicators [{campaign_id}] "
                        f"{campaign_name}"
                    ),
                    description=(
                        f"Repository contains independent filename and content "
                        f"indicators associated with campaign '{campaign_name}' "
                        f"({campaign_id})."
                    ),
                    severity=Severity.HIGH,
                    category=Category.SUPPLY_CHAIN,
                    file_path=correlated_files[0],
                    line_number=None,
                    analyzer=self.name,
                    confidence=0.8,
                    rule_id=(f"SV-KNOWN-THREATS-{campaign_id}-CORRELATED-INDICATORS"),
                    evidence=Evidence(kind="campaign_indicators", snippet=evidence),
                    remediation=(
                        "Quarantine the skill and verify the matched files and "
                        "strings against the campaign report before use."
                    ),
                )
            )

        return findings

    def _diagnostic(self, code: str, message: str, path: str) -> None:
        if any(
            diagnostic.code == code and diagnostic.path == path
            for diagnostic in self.diagnostics
        ):
            return
        self.diagnostics.append(
            Diagnostic(code=code, message=message, analyzer=self.name, path=path)
        )
