from rich.console import Console
from rich.table import Table

from skills_verified.core.models import ScanReport, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
    Severity.UNKNOWN: "magenta",
}


def render_report(report: ScanReport, console: Console | None = None) -> None:
    """Render a human-readable view without making a policy decision."""
    console = console or Console()
    console.print("Skills Verified — Security Analyzer")
    console.print(f"Source: {report.source.input}", markup=False)
    console.print(f"Execution status: {report.scan.status.value}", markup=False)
    console.print(
        f"Scope: {report.scope.files_scanned} files scanned, "
        f"{report.scope.files_skipped} skipped",
        markup=False,
    )

    runs = Table("Analyzer", "Status", "Findings", "Reason")
    for run in report.analyzer_runs:
        runs.add_row(
            run.name, run.status.value, str(run.findings_count), run.reason or ""
        )
    console.print(runs)

    for finding in report.findings:
        location = finding.file_path or ""
        if finding.line_number is not None:
            location += f":{finding.line_number}"
        console.print(
            f"[{finding.severity.value.upper()}] {finding.title} ({finding.rule_id})",
            style=SEVERITY_COLORS[finding.severity],
            markup=False,
        )
        if location:
            console.print(f"  {location}", markup=False)
        console.print(f"  {finding.description}", markup=False)

    console.print(f"Scan duration: {report.scan.duration_ms}ms", markup=False)
