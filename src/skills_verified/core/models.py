from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class Category(Enum):
    CODE_SAFETY = "code_safety"
    CVE = "cve"
    GUARDRAILS = "guardrails"
    PERMISSIONS = "permissions"
    SUPPLY_CHAIN = "supply_chain"
    MCP_SECURITY = "mcp_security"
    CONFIG_INJECTION = "config_injection"
    OBFUSCATION = "obfuscation"
    EXFILTRATION = "exfiltration"


class ScanStatus(Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class AnalyzerRunStatus(Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"


class DiagnosticLevel(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class VerificationStatus(Enum):
    CORROBORATED = "corroborated"
    DISPUTED = "disputed"
    UNVERIFIED = "unverified"


@dataclass
class Location:
    path: str
    start_line: int | None = None
    end_line: int | None = None


@dataclass
class Evidence:
    kind: str
    snippet: str


@dataclass
class FindingVerification:
    candidate_id: str
    status: VerificationStatus
    method: str
    attempts: int
    agreements: int
    disagreements: int
    inconclusive: int
    evidence_matched: bool
    requested_model: str
    candidate_prompt_sha256: str
    verification_prompt_sha256: str
    generation_response_sha256: str
    verification_response_sha256: list[str] = field(default_factory=list)
    co_located_deterministic_rule_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        counts = (
            self.attempts,
            self.agreements,
            self.disagreements,
            self.inconclusive,
        )
        if any(type(value) is not int or value < 0 for value in counts):
            raise ValueError("verification counts must be non-negative integers")
        if self.agreements + self.disagreements + self.inconclusive != self.attempts:
            raise ValueError("verification outcomes must equal attempts")
        if self.status == VerificationStatus.CORROBORATED and not self.evidence_matched:
            raise ValueError("corroborated verification requires matched evidence")


def _default_rule_id(analyzer: str, title: str) -> str:
    analyzer_part = re.sub(r"[^A-Z0-9]+", "-", analyzer.upper()).strip("-") or "UNKNOWN"
    digest = hashlib.sha256(title.encode("utf-8")).hexdigest()[:8].upper()
    return f"SV-{analyzer_part}-{digest}"


def _default_fingerprint(
    rule_id: str,
    file_path: str | None,
    line_number: int | None,
    evidence: Evidence | None,
    title: str,
    fingerprint_context: str | None,
) -> str:
    identity = evidence.snippet if evidence is not None else title
    components = [rule_id, file_path, line_number, identity]
    if fingerprint_context is not None:
        components.append(fingerprint_context)
    raw = json.dumps(
        components,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    category: Category
    file_path: str | None
    line_number: int | None
    analyzer: str
    cve_id: str | None = None
    confidence: float = 1.0
    rule_id: str | None = None
    end_line: int | None = None
    evidence: Evidence | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    fingerprint: str | None = None
    verification: FindingVerification | None = None
    fingerprint_context: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("finding confidence must be between 0.0 and 1.0")
        if self.rule_id is None:
            self.rule_id = _default_rule_id(self.analyzer, self.title)
        if self.fingerprint is None:
            self.refresh_fingerprint()

    def refresh_fingerprint(self) -> None:
        """Rebuild the identity after central location/evidence normalization."""
        if self.rule_id is None:  # guarded by __post_init__, useful to type checkers
            raise ValueError("finding rule_id must not be empty")
        self.fingerprint = _default_fingerprint(
            self.rule_id,
            self.file_path,
            self.line_number,
            self.evidence,
            self.title,
            self.fingerprint_context,
        )

    @property
    def location(self) -> Location | None:
        if self.file_path is None:
            return None
        return Location(
            self.file_path, self.line_number, self.end_line or self.line_number
        )


@dataclass
class AnalyzerRun:
    name: str
    status: AnalyzerRunStatus
    duration_ms: int
    findings_count: int
    reason: str | None = None
    version: str | None = None


@dataclass
class Diagnostic:
    code: str
    message: str
    level: DiagnosticLevel = DiagnosticLevel.WARNING
    analyzer: str | None = None
    path: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScannerInfo:
    name: str
    version: str
    ruleset_version: str


@dataclass
class ScanInfo:
    status: ScanStatus
    started_at: str
    duration_ms: int
    scanner: ScannerInfo


@dataclass
class SourceInfo:
    input: str
    commit_sha: str | None
    artifact_sha256: str


@dataclass
class ScopeInfo:
    skill_roots: list[str]
    files_scanned: int
    files_skipped: int
    bytes_scanned: int = 0


@dataclass
class PlatformInfo:
    name: str
    confidence: float
    evidence: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    scan: ScanInfo
    source: SourceInfo
    scope: ScopeInfo
    platforms: list[PlatformInfo]
    analyzer_runs: list[AnalyzerRun]
    findings: list[Finding]
    diagnostics: list[Diagnostic]
    schema_version: str = "1.0"


# Public name retained for analyzer integrations importing Report. The shape is
# intentionally the new policy-free contract; this is not a legacy score report.
Report = ScanReport
