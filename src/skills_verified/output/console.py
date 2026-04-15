from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from skills_verified.core.models import Grade, Report, Severity

GRADE_COLORS = {
    Grade.A: "green",
    Grade.B: "blue",
    Grade.C: "yellow",
    Grade.D: "dark_orange",
    Grade.F: "red",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_report(report: Report, console: Console | None = None) -> None:
    console = console or Console()

    console.print()
    console.print(
        Panel(
            "[bold]Skills Verified — AI Agent Trust Scanner[/bold]",
            style="blue",
        )
    )

    console.print(f"\n  Repository: [bold]{report.repo_url}[/bold]")
    console.print(f"  Analyzers:  {', '.join(report.analyzers_used)}")
    if not report.llm_used:
        console.print("  [dim]LLM analyzer: skipped[/dim]")
    console.print()

    grade_color = GRADE_COLORS.get(report.overall_grade, "white")
    console.print(
        Panel(
            f"  TRUST SCORE:  [{grade_color} bold]{report.overall_grade.value}[/{grade_color} bold]  ({report.overall_score}/100)",
            style=grade_color,
        )
    )

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Category", style="bold")
    table.add_column("Grade")
    table.add_column("Findings", justify="right")
    for cs in report.categories:
        cat_color = GRADE_COLORS.get(cs.grade, "white")
        cat_name = cs.category.value.replace("_", " ").title()
        table.add_row(
            cat_name,
            f"[{cat_color}]{cs.grade.value}[/{cat_color}] ({cs.score})",
            f"{cs.findings_count} findings",
        )
    console.print(table)
    console.print()

    critical = sum(1 for f in report.findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in report.findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in report.findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in report.findings if f.severity == Severity.LOW)
    console.print(
        f"  [red]CRITICAL ({critical})[/red] | "
        f"[red]HIGH ({high})[/red] | "
        f"[yellow]MEDIUM ({medium})[/yellow] | "
        f"[cyan]LOW ({low})[/cyan]"
    )
    console.print()

    sorted_findings = sorted(
        report.findings,
        key=lambda f: list(Severity).index(f.severity),
    )
    for finding in sorted_findings:
        sev_color = SEVERITY_COLORS.get(finding.severity, "white")
        location = ""
        if finding.file_path:
            location = finding.file_path
            if finding.line_number:
                location += f":{finding.line_number}"
        console.print(
            f"  [{sev_color}][{finding.severity.value.upper()}][/{sev_color}] "
            f"{finding.title}"
        )
        if location:
            console.print(f"    [dim]{finding.analyzer} | {location}[/dim]")
        console.print(f"    {finding.description}")
        console.print()

    console.print(f"  [dim]Scan completed in {report.scan_duration_seconds}s[/dim]")
    console.print()
