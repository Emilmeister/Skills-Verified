import sys
from pathlib import Path

import click
from rich.console import Console

from skills_verified.analyzers.bandit_analyzer import BanditAnalyzer
from skills_verified.analyzers.cve_analyzer import CveAnalyzer
from skills_verified.analyzers.guardrails_analyzer import GuardrailsAnalyzer
from skills_verified.analyzers.llm_analyzer import LlmAnalyzer, LlmConfig
from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.analyzers.permissions_analyzer import PermissionsAnalyzer
from skills_verified.analyzers.semgrep_analyzer import SemgrepAnalyzer
from skills_verified.analyzers.supply_chain_analyzer import SupplyChainAnalyzer
from skills_verified.core.pipeline import Pipeline
from skills_verified.output.console import render_report
from skills_verified.output.json_report import save_json_report
from skills_verified.repo.fetcher import fetch_repo, is_git_url

console = Console()


@click.command("skills-verified")
@click.argument("source")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save JSON report to file")
@click.option("--skip", type=str, default=None, help="Comma-separated analyzer names to skip")
@click.option("--only", type=str, default=None, help="Comma-separated analyzer names to run exclusively")
@click.option("--llm-url", type=str, default=None, envvar="SV_LLM_URL", help="OpenAI-compatible API base URL")
@click.option("--llm-model", type=str, default=None, envvar="SV_LLM_MODEL", help="LLM model name")
@click.option("--llm-key", type=str, default=None, envvar="SV_LLM_KEY", help="LLM API key")
def main(
    source: str,
    output: str | None,
    skip: str | None,
    only: str | None,
    llm_url: str | None,
    llm_model: str | None,
    llm_key: str | None,
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
        LlmAnalyzer(config=llm_config),
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
        repo_path = fetch_repo(source)
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
