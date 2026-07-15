import json
from pathlib import Path

from skills_verified.core.models import Finding, Severity

_SEVERITY_MAP = {
    Severity.CRITICAL: "blocker",
    Severity.HIGH: "critical",
    Severity.MEDIUM: "major",
    Severity.LOW: "minor",
    Severity.INFO: "info",
    Severity.UNKNOWN: "info",
}


def generate_codeclimate(findings: list[Finding]) -> list[dict]:
    issues = []
    for f in findings:
        path = f.file_path if f.file_path is not None else "unknown"
        line = f.line_number if f.line_number is not None else 1
        issues.append(
            {
                "type": "issue",
                "check_name": f.analyzer,
                "description": f.description,
                "categories": ["Security"],
                "severity": _SEVERITY_MAP[f.severity],
                "fingerprint": (f.fingerprint or "").removeprefix("sha256:"),
                "location": {
                    "path": path,
                    "lines": {"begin": line},
                },
            }
        )
    return issues


def save_codeclimate(findings: list[Finding], path: Path) -> None:
    data = generate_codeclimate(findings)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
