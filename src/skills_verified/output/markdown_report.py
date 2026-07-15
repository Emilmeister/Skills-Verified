from __future__ import annotations

import html
from pathlib import Path

from skills_verified.core.models import ScanReport, Severity

_SEVERITY_ORDER = {severity: index for index, severity in enumerate(Severity)}


def _cell(value: object) -> str:
    return html.escape(str(value), quote=True).replace("|", "&#124;").replace("\n", " ")


def generate_markdown(report: ScanReport, style: str = "full") -> str:
    counts = {severity: 0 for severity in Severity}
    for finding in report.findings:
        counts[finding.severity] += 1

    lines = [
        "## Skills Verified — Scan Report",
        "",
        f"**Source:** `{_cell(report.source.input)}`  ",
        f"**Execution status:** `{report.scan.status.value}`  ",
        f"**Duration:** {report.scan.duration_ms}ms  ",
        f"**Scope:** {report.scope.files_scanned} scanned, {report.scope.files_skipped} skipped",
        "",
        "### Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    lines.extend(
        f"| {severity.value.upper()} | {counts[severity]} |" for severity in Severity
    )
    lines.extend(
        [
            "",
            "### Analyzer execution",
            "",
            "| Analyzer | Status | Findings | Reason |",
            "| --- | --- | ---: | --- |",
        ]
    )
    for run in report.analyzer_runs:
        lines.append(
            f"| {_cell(run.name)} | {run.status.value} | {run.findings_count} | {_cell(run.reason or '')} |"
        )

    if style == "full" and report.findings:
        lines.extend(
            [
                "",
                "### Findings",
                "",
                "| Severity | Rule | Title | Location | Confidence |",
                "| --- | --- | --- | --- | ---: |",
            ]
        )
        for finding in sorted(
            report.findings, key=lambda item: _SEVERITY_ORDER[item.severity]
        ):
            location = finding.file_path or "N/A"
            if finding.line_number is not None:
                location += f":{finding.line_number}"
            lines.append(
                f"| {finding.severity.value.upper()} | {_cell(finding.rule_id)} | "
                f"{_cell(finding.title)} | {_cell(location)} | {finding.confidence:.2f} |"
            )
    elif style != "full":
        lines.extend(["", f"> {len(report.findings)} findings reported."])

    return "\n".join(lines) + "\n"


def save_markdown(report: ScanReport, style: str, path: Path) -> None:
    path.write_text(generate_markdown(report, style=style), encoding="utf-8")
