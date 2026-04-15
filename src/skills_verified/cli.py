import sys
from pathlib import Path

import click
from rich.console import Console

from skills_verified.analyzers.bandit_analyzer import BanditAnalyzer
from skills_verified.analyzers.container_analyzer import ContainerAnalyzer
from skills_verified.analyzers.cve_analyzer import CveAnalyzer
from skills_verified.analyzers.guardrails_analyzer import GuardrailsAnalyzer
from skills_verified.analyzers.llm_analyzer import LlmAnalyzer, LlmConfig
from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.analyzers.permissions_analyzer import PermissionsAnalyzer
from skills_verified.analyzers.semgrep_analyzer import SemgrepAnalyzer
from skills_verified.analyzers.supply_chain_analyzer import SupplyChainAnalyzer
from skills_verified.core.models import Grade, Report, Severity
from skills_verified.core.pipeline import Pipeline
from skills_verified.output.console import render_report
from skills_verified.output.json_report import save_json_report
from skills_verified.repo.fetcher import fetch_repo

console = Console()


@click.command("skills-verified")
@click.argument("source")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save JSON report to file")
@click.option("--skip", type=str, default=None, help="Comma-separated analyzer names to skip")
@click.option("--only", type=str, default=None, help="Comma-separated analyzer names to run exclusively")
@click.option("--llm-url", type=str, default=None, envvar="SV_LLM_URL", help="OpenAI-compatible API base URL")
@click.option("--llm-model", type=str, default=None, envvar="SV_LLM_MODEL", help="LLM model name")
@click.option("--llm-key", type=str, default=None, envvar="SV_LLM_KEY", help="LLM API key")
@click.option("--llm-passes", type=int, default=1, envvar="SV_LLM_PASSES", help="Number of LLM passes for consensus (default 1, recommended 3 for CI/CD)")
@click.option("--image", type=str, default=None, help="Docker image to scan with grype (e.g. python:3.11-slim)")
@click.option("--branch", "-b", type=str, default=None, help="Git branch to clone (e.g. main, security-fixes)")
@click.option(
    "--fail-on",
    type=click.Choice(["strict", "standard", "relaxed"], case_sensitive=False),
    default=None,
    help="Exit with code 1 if skill fails the chosen policy (strict: < A or any CRITICAL; standard: < C or any CRITICAL; relaxed: F or > 2 CRITICAL)",
)
def main(
    source: str,
    output: str | None,
    skip: str | None,
    only: str | None,
    llm_url: str | None,
    llm_model: str | None,
    llm_key: str | None,
    llm_passes: int,
    image: str | None,
    branch: str | None,
    fail_on: str | None,
) -> None:
    """Skills Verified — AI Agent Trust Scanner.

    Analyze a repository for vulnerabilities and compute a Trust Score.

    SOURCE can be a GitHub URL or a local path.
    """
    llm_config = None
    if llm_url and llm_model and llm_key:
        llm_config = LlmConfig(url=llm_url, model=llm_model, key=llm_key)

    all_analyzers = [
        PatternAnalyzer(),
        CveAnalyzer(),
        BanditAnalyzer(),
        SemgrepAnalyzer(),
        GuardrailsAnalyzer(),
        PermissionsAnalyzer(),
        SupplyChainAnalyzer(),
        ContainerAnalyzer(image=image),
        LlmAnalyzer(config=llm_config, passes=llm_passes),
    ]

    skip_set = set(skip.split(",")) if skip else set()
    only_set = set(only.split(",")) if only else None

    analyzers = []
    for a in all_analyzers:
        if a.name in skip_set:
            continue
        if only_set is not None and a.name not in only_set:
            continue
        analyzers.append(a)

    try:
        repo_path = fetch_repo(source, branch=branch)
    except (ValueError, Exception) as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    pipeline = Pipeline(analyzers=analyzers)
    report = pipeline.run(
        repo_path=repo_path,
        repo_url=source,
        llm_used=llm_config is not None,
    )

    render_report(report, console=console)

    if output:
        save_json_report(report, Path(output))
        console.print(f"  [dim]JSON report saved to {output}[/dim]\n")

    if fail_on:
        _apply_gate(report, fail_on, console)


def _apply_gate(report: Report, policy: str, console: Console) -> None:
    grade = report.overall_grade
    criticals = sum(1 for f in report.findings if f.severity == Severity.CRITICAL)

    blocked = False
    reason = ""

    if policy == "strict":
        # Grade must be A, zero CRITICALs
        if grade != Grade.A:
            blocked, reason = True, f"Grade {grade.value} is below A"
        elif criticals > 0:
            blocked, reason = True, f"{criticals} critical finding(s)"
    elif policy == "standard":
        # Grade must be C or above, zero CRITICALs
        if grade in (Grade.D, Grade.F):
            blocked, reason = True, f"Grade {grade.value} is below C"
        elif criticals > 0:
            blocked, reason = True, f"{criticals} critical finding(s)"
    elif policy == "relaxed":
        # Only block on F or > 2 CRITICALs
        if grade == Grade.F:
            blocked, reason = True, "Grade F"
        elif criticals > 2:
            blocked, reason = True, f"{criticals} critical findings (> 2)"

    if blocked:
        console.print(f"  [red bold]BLOCKED ({policy}):[/red bold] {reason}\n")
        sys.exit(1)
