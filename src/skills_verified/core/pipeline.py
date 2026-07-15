from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit, urlunsplit

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.context import (
    ScanContext,
    build_inventory_context,
    enrich_scan_context,
)
from skills_verified.core.models import (
    AnalyzerRun,
    AnalyzerRunStatus,
    Diagnostic,
    DiagnosticLevel,
    Evidence,
    Finding,
    ScanInfo,
    ScannerInfo,
    ScanReport,
    ScanStatus,
    ScopeInfo,
    SourceInfo,
)
from skills_verified.repo import safe_read_bytes
from skills_verified.repo.files import DEFAULT_MAX_TOTAL_BYTES

logger = logging.getLogger(__name__)

RULESET_VERSION = "2026.07.15.3"
DEFAULT_ANALYZER_CONCURRENCY = 3
MAX_ANALYZER_CONCURRENCY = 18


def _safe_source_input(source: str) -> str:
    """Keep source provenance without echoing URL credentials or query secrets."""
    try:
        parsed = urlsplit(source)
    except ValueError:
        if source.lower().startswith(("http://", "https://", "ssh://")):
            scheme, separator, remainder = source.partition("://")
            remainder = remainder.split("#", 1)[0].split("?", 1)[0]
            remainder = remainder.rsplit("@", 1)[-1]
            return f"{scheme}{separator}{remainder}"
        return source
    if parsed.scheme not in {"http", "https", "ssh"} or not parsed.netloc:
        return source
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def _package_version() -> str:
    try:
        return version("skills-verified")
    except PackageNotFoundError:
        return "0+local"


def _analyzer_version(analyzer: Analyzer) -> str:
    """Return an explicit analyzer revision or its packaged implementation version."""
    declared = getattr(analyzer, "version", None)
    return str(declared) if declared else _package_version()


def _commit_sha(repo_path: Path) -> str | None:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            capture_output=True,
            check=True,
            env=environment,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None
    sha = result.stdout.strip()
    if len(sha) != 40 or not all(char in "0123456789abcdef" for char in sha.lower()):
        return None
    return sha


@contextmanager
def _sanitized_context(
    source: ScanContext,
    *,
    max_file_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> Iterator[tuple[ScanContext, str]]:
    """Copy inventoried regular files into a symlink-free analysis workspace."""
    digest = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix="sv-scan-") as temporary_dir:
        analysis_root = Path(temporary_dir).resolve()
        analysis_files: list[Path] = []
        bytes_scanned = 0
        for source_path in source.files:
            relative = source_path.relative_to(source.repo_path)
            try:
                data = safe_read_bytes(
                    source_path,
                    source.repo_path,
                    max_bytes=max_file_bytes,
                )
            except (OSError, ValueError) as exc:
                source.skipped_files += 1
                source.scope_degraded = True
                source.diagnostics.append(
                    Diagnostic(
                        code="repository_file_copy_failed",
                        message=f"File changed or could not be copied safely: {type(exc).__name__}",
                        path=relative.as_posix(),
                    )
                )
                continue

            destination = analysis_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            analysis_files.append(destination)
            bytes_scanned += len(data)
            relative_bytes = relative.as_posix().encode("utf-8")
            digest.update(len(relative_bytes).to_bytes(8, "big"))
            digest.update(relative_bytes)
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)

        analysis = replace(
            source,
            repo_path=analysis_root,
            files=analysis_files,
            bytes_scanned=bytes_scanned,
        )
        yield analysis, digest.hexdigest()


def _add_evidence(finding: Finding, context: ScanContext) -> None:
    if (
        finding.evidence is not None
        or finding.file_path is None
        or finding.line_number is None
    ):
        return
    candidate = context.repo_path / finding.file_path
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(context.repo_path)
        if candidate.is_symlink() or not resolved.is_file():
            return
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
        if 1 <= finding.line_number <= len(lines):
            finding.evidence = Evidence(
                kind="source",
                snippet=lines[finding.line_number - 1].strip()[:500],
            )
    except (OSError, ValueError):
        return


def _validate_finding_location(
    finding: Finding,
    context: ScanContext,
    known_files: set[Path],
) -> Diagnostic | None:
    if finding.file_path is None:
        return None
    raw_path = Path(finding.file_path)
    candidate = raw_path if raw_path.is_absolute() else context.repo_path / raw_path
    try:
        resolved = candidate.resolve(strict=False)
        relative = resolved.relative_to(context.repo_path)
    except (OSError, ValueError):
        rejected = finding.file_path
        finding.file_path = None
        finding.line_number = None
        finding.end_line = None
        return Diagnostic(
            code="finding_location_rejected",
            message="Analyzer returned a location outside the scan scope",
            analyzer=finding.analyzer,
            path=rejected,
        )

    if relative not in known_files:
        rejected = finding.file_path
        finding.file_path = None
        finding.line_number = None
        finding.end_line = None
        return Diagnostic(
            code="finding_location_unknown",
            message="Analyzer returned a location that was not in the scanned inventory",
            analyzer=finding.analyzer,
            path=rejected,
        )

    finding.file_path = relative.as_posix()
    if finding.line_number is not None and finding.line_number < 1:
        finding.line_number = None
        finding.end_line = None
        return Diagnostic(
            code="finding_line_invalid",
            message="Analyzer returned a line number below 1",
            analyzer=finding.analyzer,
            path=finding.file_path,
        )
    if finding.end_line is not None and (
        finding.end_line < 1
        or (finding.line_number is not None and finding.end_line < finding.line_number)
    ):
        finding.end_line = finding.line_number
        return Diagnostic(
            code="finding_end_line_invalid",
            message="Analyzer returned an end line before the finding start",
            analyzer=finding.analyzer,
            path=finding.file_path,
        )
    return None


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        key = finding.fingerprint or ""
        previous = unique.get(key)
        if previous is None or finding.confidence > previous.confidence:
            unique[key] = finding
    return list(unique.values())


def _line_overlap_ratio(
    left_start: int,
    left_end: int,
    right_start: int,
    right_end: int,
) -> float:
    overlap = max(0, min(left_end, right_end) - max(left_start, right_start) + 1)
    union = max(left_end, right_end) - min(left_start, right_start) + 1
    return overlap / union


def _add_co_located_deterministic_rules(findings: list[Finding]) -> None:
    deterministic = [
        finding
        for finding in findings
        if finding.analyzer != "llm"
        and finding.file_path is not None
        and finding.line_number is not None
    ]
    for candidate in findings:
        if (
            candidate.analyzer != "llm"
            or candidate.verification is None
            or candidate.file_path is None
            or candidate.line_number is None
        ):
            continue
        candidate_end = candidate.end_line or candidate.line_number
        matches = []
        for finding in deterministic:
            if (
                finding.file_path != candidate.file_path
                or finding.category != candidate.category
                or finding.rule_id is None
            ):
                continue
            finding_end = finding.end_line or finding.line_number
            if (
                _line_overlap_ratio(
                    candidate.line_number,
                    candidate_end,
                    finding.line_number,
                    finding_end,
                )
                >= 0.8
            ):
                matches.append(finding.rule_id)
        candidate.verification.co_located_deterministic_rule_ids = sorted(set(matches))


class Pipeline:
    def __init__(
        self,
        analyzers: list[Analyzer],
        *,
        concurrency: int = DEFAULT_ANALYZER_CONCURRENCY,
        progress: Callable[[str], None] | None = None,
    ):
        if not 1 <= concurrency <= MAX_ANALYZER_CONCURRENCY:
            raise ValueError(
                f"analyzer concurrency must be between 1 and {MAX_ANALYZER_CONCURRENCY}"
            )
        self.analyzers = analyzers
        self.concurrency = concurrency
        self.progress = progress

    def _progress(self, message: str) -> None:
        if self.progress is None:
            return
        try:
            self.progress(message)
        except Exception:
            logger.debug("Progress callback failed", exc_info=True)

    def run(
        self,
        repo_path: Path,
        repo_url: str,
        *,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        **_: object,
    ) -> ScanReport:
        started_at = datetime.now(timezone.utc)
        started = time.monotonic()
        source_context = build_inventory_context(
            repo_path, max_total_bytes=max_total_bytes
        )
        source_context.source_input = _safe_source_input(repo_url)
        commit_sha = _commit_sha(repo_path)

        if not source_context.inventory_complete:
            return self._inventory_failure(
                source_context,
                repo_url=repo_url,
                commit_sha=commit_sha,
                started_at=started_at,
                started=started,
            )

        with _sanitized_context(
            source_context,
            max_file_bytes=max_total_bytes,
        ) as (context, artifact_sha256):
            context = enrich_scan_context(context)
            return self._execute(
                context,
                repo_url=repo_url,
                commit_sha=commit_sha,
                artifact_sha256=artifact_sha256,
                started_at=started_at,
                started=started,
            )

    def input_failure(self, repo_url: str, error: Exception) -> ScanReport:
        """Build a schema-valid report when repository acquisition fails."""
        return self._failure_report(
            repo_url,
            error,
            code="source_fetch_failed",
            reason="source_fetch_failed",
        )

    def execution_failure(self, repo_url: str, error: Exception) -> ScanReport:
        """Build a schema-valid report for an unexpected orchestration failure."""
        return self._failure_report(
            repo_url,
            error,
            code="scan_execution_failed",
            reason="scan_execution_failed",
        )

    def _failure_report(
        self,
        repo_url: str,
        error: Exception,
        *,
        code: str,
        reason: str,
    ) -> ScanReport:
        started_at = datetime.now(timezone.utc)
        started = time.monotonic()
        safe_input = _safe_source_input(repo_url)
        error_message = str(error).replace(repo_url, safe_input)[:1000]
        return ScanReport(
            scan=self._scan_info(ScanStatus.FAILED, started_at, started),
            source=SourceInfo(safe_input, None, hashlib.sha256().hexdigest()),
            scope=ScopeInfo([], 0, 0, 0),
            platforms=[],
            analyzer_runs=[
                AnalyzerRun(
                    name=analyzer.name,
                    status=AnalyzerRunStatus.SKIPPED,
                    duration_ms=0,
                    findings_count=0,
                    reason=reason,
                    version=_analyzer_version(analyzer),
                )
                for analyzer in self.analyzers
            ],
            findings=[],
            diagnostics=[
                Diagnostic(
                    code=code,
                    message=f"{type(error).__name__}: {error_message}",
                    level=DiagnosticLevel.ERROR,
                )
            ],
        )

    def _execute(
        self,
        context: ScanContext,
        *,
        repo_url: str,
        commit_sha: str | None,
        artifact_sha256: str,
        started_at: datetime,
        started: float,
    ) -> ScanReport:
        diagnostics = list(context.diagnostics)
        findings: list[Finding] = []
        analyzer_runs: list[AnalyzerRun] = []
        known_files = {path.relative_to(context.repo_path) for path in context.files}

        if not self.analyzers:
            diagnostics.append(
                Diagnostic(
                    code="no_analyzers_selected",
                    message="No analyzers were selected for this scan",
                    level=DiagnosticLevel.ERROR,
                )
            )

        def run_analyzer(
            index: int, analyzer: Analyzer
        ) -> tuple[list[Finding], list[Diagnostic], AnalyzerRun]:
            run_started = time.monotonic()
            self._progress(f"[{index}/{len(self.analyzers)}] {analyzer.name}: started")
            try:
                available = analyzer.is_available()
            except Exception as exc:
                run = AnalyzerRun(
                    name=analyzer.name,
                    status=AnalyzerRunStatus.FAILED,
                    duration_ms=round((time.monotonic() - run_started) * 1000),
                    findings_count=0,
                    reason=f"availability_check_failed:{type(exc).__name__}",
                    version=_analyzer_version(analyzer),
                )
                analyzer_diagnostics = [
                    Diagnostic(
                        code="analyzer_availability_failed",
                        message=f"Analyzer {analyzer.name} availability check failed: {exc}",
                        level=DiagnosticLevel.ERROR,
                        analyzer=analyzer.name,
                    )
                ]
                self._progress(
                    f"[{index}/{len(self.analyzers)}] {analyzer.name}: "
                    f"failed in {run.duration_ms / 1000:.2f}s"
                )
                return [], analyzer_diagnostics, run

            if not available:
                run = AnalyzerRun(
                    name=analyzer.name,
                    status=AnalyzerRunStatus.SKIPPED,
                    duration_ms=round((time.monotonic() - run_started) * 1000),
                    findings_count=0,
                    reason="not_available",
                    version=_analyzer_version(analyzer),
                )
                self._progress(
                    f"[{index}/{len(self.analyzers)}] {analyzer.name}: skipped"
                )
                return [], [], run

            try:
                produced = analyzer.analyze(
                    context.repo_path,
                    context=context,
                    platforms=context.profiles,
                    metadata=context.metadata,
                    configs=context.configs,
                    mcp_definitions=context.mcp_definitions,
                    progress=self._progress,
                )
                finding_diagnostics: list[Diagnostic] = []
                for finding in produced:
                    location_diagnostic = _validate_finding_location(
                        finding, context, known_files
                    )
                    if location_diagnostic is not None:
                        finding_diagnostics.append(location_diagnostic)
                    _add_evidence(finding, context)
                    finding.refresh_fingerprint()
                analyzer_diagnostics = finding_diagnostics + list(
                    getattr(analyzer, "diagnostics", []) or []
                )
                analyzer_degraded = any(
                    diagnostic.level != DiagnosticLevel.INFO
                    for diagnostic in analyzer_diagnostics
                )
                run = AnalyzerRun(
                    name=analyzer.name,
                    status=(
                        AnalyzerRunStatus.PARTIAL
                        if analyzer_degraded
                        else AnalyzerRunStatus.COMPLETED
                    ),
                    duration_ms=round((time.monotonic() - run_started) * 1000),
                    findings_count=len(produced),
                    reason=(
                        "analyzer_reported_diagnostics" if analyzer_degraded else None
                    ),
                    version=_analyzer_version(analyzer),
                )
                self._progress(
                    f"[{index}/{len(self.analyzers)}] {analyzer.name}: "
                    f"{run.status.value} in {run.duration_ms / 1000:.2f}s "
                    f"({len(produced)} findings)"
                )
                return produced, analyzer_diagnostics, run
            except Exception as exc:
                logger.exception("Analyzer %s crashed", analyzer.name)
                analyzer_diagnostics = list(getattr(analyzer, "diagnostics", []) or [])
                analyzer_diagnostics.append(
                    Diagnostic(
                        code="analyzer_failed",
                        message=f"Analyzer {analyzer.name} failed: {type(exc).__name__}: {exc}",
                        level=DiagnosticLevel.ERROR,
                        analyzer=analyzer.name,
                    )
                )
                run = AnalyzerRun(
                    name=analyzer.name,
                    status=AnalyzerRunStatus.FAILED,
                    duration_ms=round((time.monotonic() - run_started) * 1000),
                    findings_count=0,
                    reason=f"analyzer_crashed:{type(exc).__name__}",
                    version=_analyzer_version(analyzer),
                )
                self._progress(
                    f"[{index}/{len(self.analyzers)}] {analyzer.name}: "
                    f"failed in {run.duration_ms / 1000:.2f}s"
                )
                return [], analyzer_diagnostics, run

        results: dict[int, tuple[list[Finding], list[Diagnostic], AnalyzerRun]] = {}
        with ThreadPoolExecutor(
            max_workers=min(self.concurrency, max(1, len(self.analyzers))),
            thread_name_prefix="skills-verified",
        ) as executor:
            future_indexes = {
                executor.submit(run_analyzer, index, analyzer): index
                for index, analyzer in enumerate(self.analyzers, start=1)
            }
            for future in as_completed(future_indexes):
                results[future_indexes[future]] = future.result()

        for index in range(1, len(self.analyzers) + 1):
            produced, analyzer_diagnostics, run = results[index]
            findings.extend(produced)
            diagnostics.extend(analyzer_diagnostics)
            analyzer_runs.append(run)

        findings = _deduplicate(findings)
        _add_co_located_deterministic_rules(findings)
        analyzers_ran = sum(
            run.status in {AnalyzerRunStatus.COMPLETED, AnalyzerRunStatus.PARTIAL}
            for run in analyzer_runs
        )
        degraded = any(
            run.status != AnalyzerRunStatus.COMPLETED for run in analyzer_runs
        )
        degraded = (
            degraded
            or context.scope_degraded
            or any(
                diagnostic.level == DiagnosticLevel.ERROR for diagnostic in diagnostics
            )
        )
        if analyzers_ran == 0:
            status = ScanStatus.FAILED
        elif degraded:
            status = ScanStatus.PARTIAL
        else:
            status = ScanStatus.COMPLETE

        return ScanReport(
            scan=self._scan_info(status, started_at, started),
            source=SourceInfo(
                _safe_source_input(repo_url), commit_sha, artifact_sha256
            ),
            scope=ScopeInfo(
                skill_roots=[path.as_posix() for path in context.skill_roots],
                files_scanned=len(context.files),
                files_skipped=context.skipped_files,
                bytes_scanned=context.bytes_scanned,
            ),
            platforms=context.platforms,
            analyzer_runs=analyzer_runs,
            findings=findings,
            diagnostics=diagnostics,
        )

    def _inventory_failure(
        self,
        context: ScanContext,
        *,
        repo_url: str,
        commit_sha: str | None,
        started_at: datetime,
        started: float,
    ) -> ScanReport:
        runs = [
            AnalyzerRun(
                name=analyzer.name,
                status=AnalyzerRunStatus.SKIPPED,
                duration_ms=0,
                findings_count=0,
                reason="repository_inventory_failed",
                version=_analyzer_version(analyzer),
            )
            for analyzer in self.analyzers
        ]
        return ScanReport(
            scan=self._scan_info(ScanStatus.FAILED, started_at, started),
            source=SourceInfo(
                _safe_source_input(repo_url),
                commit_sha,
                hashlib.sha256().hexdigest(),
            ),
            scope=ScopeInfo([], 0, context.skipped_files, 0),
            platforms=[],
            analyzer_runs=runs,
            findings=[],
            diagnostics=context.diagnostics,
        )

    @staticmethod
    def _scan_info(
        status: ScanStatus, started_at: datetime, started: float
    ) -> ScanInfo:
        return ScanInfo(
            status=status,
            started_at=started_at.isoformat().replace("+00:00", "Z"),
            duration_ms=round((time.monotonic() - started) * 1000),
            scanner=ScannerInfo(
                name="skills-verified",
                version=_package_version(),
                ruleset_version=RULESET_VERSION,
            ),
        )
