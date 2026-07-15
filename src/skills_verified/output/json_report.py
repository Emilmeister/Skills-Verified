from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skills_verified.core.models import Finding, ScanReport, Severity


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    location = finding.location
    return {
        "rule_id": finding.rule_id,
        "fingerprint": finding.fingerprint,
        "title": finding.title,
        "description": finding.description,
        "category": finding.category.value,
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "analyzer": finding.analyzer,
        "location": (
            {
                "path": location.path,
                "start_line": location.start_line,
                "end_line": location.end_line,
            }
            if location is not None
            else None
        ),
        "evidence": (
            {"kind": finding.evidence.kind, "snippet": finding.evidence.snippet}
            if finding.evidence is not None
            else None
        ),
        "remediation": finding.remediation,
        "references": finding.references,
        "cve_id": finding.cve_id,
        "verification": (
            {
                "candidate_id": finding.verification.candidate_id,
                "status": finding.verification.status.value,
                "method": finding.verification.method,
                "attempts": finding.verification.attempts,
                "agreements": finding.verification.agreements,
                "disagreements": finding.verification.disagreements,
                "inconclusive": finding.verification.inconclusive,
                "evidence_matched": finding.verification.evidence_matched,
                "requested_model": finding.verification.requested_model,
                "candidate_prompt_sha256": finding.verification.candidate_prompt_sha256,
                "verification_prompt_sha256": finding.verification.verification_prompt_sha256,
                "generation_response_sha256": finding.verification.generation_response_sha256,
                "verification_response_sha256": finding.verification.verification_response_sha256,
                "co_located_deterministic_rule_ids": (
                    finding.verification.co_located_deterministic_rule_ids
                ),
            }
            if finding.verification is not None
            else None
        ),
    }


def report_to_dict(report: ScanReport) -> dict[str, Any]:
    severity_counts = {severity.value: 0 for severity in Severity}
    for finding in report.findings:
        severity_counts[finding.severity.value] += 1

    return {
        "schema_version": report.schema_version,
        "scan": {
            "status": report.scan.status.value,
            "started_at": report.scan.started_at,
            "duration_ms": report.scan.duration_ms,
            "scanner": {
                "name": report.scan.scanner.name,
                "version": report.scan.scanner.version,
                "ruleset_version": report.scan.scanner.ruleset_version,
            },
        },
        "source": {
            "input": report.source.input,
            "commit_sha": report.source.commit_sha,
            "artifact_sha256": report.source.artifact_sha256,
        },
        "scope": {
            "skill_roots": report.scope.skill_roots,
            "files_scanned": report.scope.files_scanned,
            "files_skipped": report.scope.files_skipped,
            "bytes_scanned": report.scope.bytes_scanned,
        },
        "platforms": [
            {
                "name": platform.name,
                "confidence": platform.confidence,
                "evidence": platform.evidence,
            }
            for platform in report.platforms
        ],
        "analyzer_runs": [
            {
                "name": run.name,
                "status": run.status.value,
                "duration_ms": run.duration_ms,
                "findings_count": run.findings_count,
                "reason": run.reason,
                "version": run.version,
            }
            for run in report.analyzer_runs
        ],
        "findings": [_finding_to_dict(finding) for finding in report.findings],
        "summary": {
            "findings_total": len(report.findings),
            "by_severity": severity_counts,
        },
        "diagnostics": [
            {
                "code": diagnostic.code,
                "message": diagnostic.message,
                "level": diagnostic.level.value,
                "analyzer": diagnostic.analyzer,
                "path": diagnostic.path,
                "details": diagnostic.details,
            }
            for diagnostic in report.diagnostics
        ],
    }


def report_to_json(report: ScanReport, *, pretty: bool = True) -> str:
    return json.dumps(
        report_to_dict(report),
        indent=2 if pretty else None,
        ensure_ascii=False,
        sort_keys=True,
    )


def save_json_report(report: ScanReport, path: Path, *, pretty: bool = True) -> None:
    path.write_text(report_to_json(report, pretty=pretty) + "\n", encoding="utf-8")
