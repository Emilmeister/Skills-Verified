import sys
from pathlib import Path

import click
from rich.console import Console

from skills_verified.analyzers.llm_analyzer import LlmConfig
from skills_verified.core.models import Grade, Report, Severity
from skills_verified.core.runner import ScanOptions, run_scan
from skills_verified.output.aibom_export import inventory_to_cyclonedx
from skills_verified.output.console import render_report
from skills_verified.output.json_report import save_json_report

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
@click.option("--llm-reduce", is_flag=True, default=False, envvar="SV_LLM_REDUCE", help="Minimise LLM context via CodeReduce — send only vulnerable skeletons around seed findings")
@click.option("--llm-verify", is_flag=True, default=False, envvar="SV_LLM_VERIFY", help="Closed-loop verify LLM findings by generating a patch and re-running static analyzers")
@click.option("--aibom-strict", is_flag=True, default=False, help="Raise AI-BOM shadow-component findings (unpinned models, MCP without auth) from INFO to LOW")
@click.option("--image", type=str, default=None, help="Docker image to scan with grype (e.g. python:3.11-slim)")
@click.option("--branch", "-b", type=str, default=None, help="Git branch to clone (e.g. main, security-fixes)")
@click.option(
    "--fail-on",
    type=str,
    default=None,
    help="Exit with code 1 if the report fails the policy. Accepts 'strict', 'standard', 'relaxed', or a free-form NL policy (requires --llm-*).",
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
    llm_reduce: bool,
    llm_verify: bool,
    aibom_strict: bool,
    image: str | None,
    branch: str | None,
    fail_on: str | None,
) -> None:
    """Skills Verified — AI Agent Trust Scanner.

    Scan a repository (URL or local path) and print a Trust Score report.
    Use `skills-verified mcp` to run as an MCP stdio server instead.
    """
    llm_config = None
    if llm_url and llm_model and llm_key:
        llm_config = LlmConfig(url=llm_url, model=llm_model, key=llm_key)

    opts = ScanOptions(
        llm_config=llm_config,
        llm_passes=llm_passes,
        llm_reduce=llm_reduce,
        llm_verify=llm_verify,
        aibom_strict=aibom_strict,
        image=image,
        skip=set(skip.split(",")) if skip else set(),
        only=set(only.split(",")) if only else None,
        branch=branch,
    )

    try:
        report, aibom_analyzer, _ = run_scan(source, opts)
    except (ValueError, Exception) as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    render_report(report, console=console)

    if output:
        aibom_dict = None
        if aibom_analyzer.last_inventory is not None:
            repo_name = Path(source).name or "repo"
            aibom_dict = inventory_to_cyclonedx(aibom_analyzer.last_inventory, repo_name=repo_name)
        save_json_report(report, Path(output), aibom=aibom_dict)
        console.print(f"  [dim]Report saved to {output}[/dim]\n")

    if fail_on:
        _apply_gate(report, fail_on, console, llm_config)


def _apply_gate(
    report: Report,
    policy: str,
    console: Console,
    llm_config: LlmConfig | None,
) -> None:
    policy_normalized = policy.strip().lower()
    if policy_normalized in {"strict", "standard", "relaxed"}:
        blocked, reason = _apply_builtin_gate(report, policy_normalized)
    else:
        from skills_verified.core.policy_engine import PolicyEngine, PolicyError
        try:
            engine = PolicyEngine(llm_config)
            rule = engine.parse(policy)
            passed, eval_reason = engine.evaluate(rule, report)
            blocked, reason = (not passed), eval_reason
        except PolicyError as e:
            console.print(f"  [red bold]POLICY ERROR:[/red bold] {e}\n")
            sys.exit(2)

    if blocked:
        console.print(f"  [red bold]BLOCKED ({policy}):[/red bold] {reason}\n")
        sys.exit(1)


def _apply_builtin_gate(report: Report, policy: str) -> tuple[bool, str]:
    grade = report.overall_grade
    criticals = sum(1 for f in report.findings if f.severity == Severity.CRITICAL)
    if policy == "strict":
        if grade != Grade.A:
            return True, f"Grade {grade.value} is below A"
        if criticals > 0:
            return True, f"{criticals} critical finding(s)"
    elif policy == "standard":
        if grade in (Grade.D, Grade.F):
            return True, f"Grade {grade.value} is below C"
        if criticals > 0:
            return True, f"{criticals} critical finding(s)"
    elif policy == "relaxed":
        if grade == Grade.F:
            return True, "Grade F"
        if criticals > 2:
            return True, f"{criticals} critical findings (> 2)"
    return False, ""


def cli_entry() -> None:
    """Real entry point: routes `skills-verified mcp` to the MCP server,
    everything else to the scan command. Keeps scan-CLI backward-compatible."""
    argv = sys.argv[1:]
    if argv and argv[0] == "mcp":
        from skills_verified.mcp_server import serve_stdio
        serve_stdio()
        return
    main()


if __name__ == "__main__":
    cli_entry()
