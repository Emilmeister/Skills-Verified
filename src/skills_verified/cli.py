from __future__ import annotations

import sys
import threading
from collections.abc import Callable
from pathlib import Path

import click

from skills_verified.analyzers.bandit_analyzer import BanditAnalyzer
from skills_verified.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skills_verified.analyzers.config_injection_analyzer import ConfigInjectionAnalyzer
from skills_verified.analyzers.cve_analyzer import CveAnalyzer
from skills_verified.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from skills_verified.analyzers.guardrails_analyzer import GuardrailsAnalyzer
from skills_verified.analyzers.known_threats_analyzer import KnownThreatsAnalyzer
from skills_verified.analyzers.llm_analyzer import (
    DEFAULT_LLM_CONCURRENCY,
    DEFAULT_LLM_TIMEOUT_SECONDS,
    MAX_COMPLETION_TOKENS,
    MAX_LLM_CONCURRENCY,
    MAX_LLM_VERIFICATION_RUNS,
    LlmAnalyzer,
    LlmConfig,
)
from skills_verified.analyzers.mcp_analyzer import MCPAnalyzer
from skills_verified.analyzers.metadata_analyzer import MetadataAnalyzer
from skills_verified.analyzers.obfuscation_analyzer import ObfuscationAnalyzer
from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.analyzers.permissions_analyzer import PermissionsAnalyzer
from skills_verified.analyzers.privilege_analyzer import PrivilegeAnalyzer
from skills_verified.analyzers.reverse_shell_analyzer import ReverseShellAnalyzer
from skills_verified.analyzers.semgrep_analyzer import SemgrepAnalyzer
from skills_verified.analyzers.shellcheck_analyzer import ShellCheckAnalyzer
from skills_verified.analyzers.supply_chain_analyzer import SupplyChainAnalyzer
from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import (
    Diagnostic,
    DiagnosticLevel,
    Finding,
    ScanStatus,
)
from skills_verified.core.pipeline import (
    DEFAULT_ANALYZER_CONCURRENCY,
    MAX_ANALYZER_CONCURRENCY,
    Pipeline,
)
from skills_verified.output.json_report import report_to_json, save_json_report
from skills_verified.repo.fetcher import (
    DEFAULT_CLONE_TIMEOUT_SECONDS,
    DEFAULT_MAX_CLONE_BYTES,
    fetched_repo,
)
from skills_verified.repo.files import DEFAULT_MAX_TOTAL_BYTES


class _BrokenAnalyzer(Analyzer):
    def __init__(self, name: str, error: Exception) -> None:
        self.name = name
        self.error = error

    def is_available(self) -> bool:
        raise RuntimeError(
            f"initialization failed: {type(self.error).__name__}: {self.error}"
        )

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        raise AssertionError("a broken analyzer must never run")


def _all_analyzers(llm_config: LlmConfig | None) -> list[Analyzer]:
    factories: list[tuple[str, Callable[[], Analyzer]]] = [
        ("pattern", PatternAnalyzer),
        ("cve", CveAnalyzer),
        ("bandit", BanditAnalyzer),
        ("shellcheck", ShellCheckAnalyzer),
        ("semgrep", SemgrepAnalyzer),
        ("guardrails", GuardrailsAnalyzer),
        ("permissions", PermissionsAnalyzer),
        ("supply_chain", SupplyChainAnalyzer),
        ("llm", lambda: LlmAnalyzer(config=llm_config)),
        ("obfuscation", ObfuscationAnalyzer),
        ("reverse_shell", ReverseShellAnalyzer),
        ("exfiltration", ExfiltrationAnalyzer),
        ("behavioral", BehavioralAnalyzer),
        ("mcp", MCPAnalyzer),
        ("config_injection", ConfigInjectionAnalyzer),
        ("metadata", MetadataAnalyzer),
        ("known_threats", KnownThreatsAnalyzer),
        ("privilege", PrivilegeAnalyzer),
    ]
    analyzers: list[Analyzer] = []
    for name, factory in factories:
        try:
            analyzers.append(factory())
        except Exception as exc:
            analyzers.append(_BrokenAnalyzer(name, exc))
    return analyzers


def _parse_names(raw: str | None) -> set[str]:
    if raw is None:
        return set()
    return {name.strip() for name in raw.split(",") if name.strip()}


def _select_analyzers(
    analyzers: list[Analyzer],
    *,
    only: str | None,
    skip: str | None,
) -> list[Analyzer]:
    names = {analyzer.name for analyzer in analyzers}
    only_names = _parse_names(only)
    skip_names = _parse_names(skip)
    unknown = (only_names | skip_names) - names
    if unknown:
        raise click.BadParameter(
            f"unknown analyzer name(s): {', '.join(sorted(unknown))}",
            param_hint="--only/--skip",
        )
    if only_names and skip_names:
        overlap = only_names & skip_names
        if overlap:
            raise click.BadParameter(
                f"analyzer(s) present in both --only and --skip: {', '.join(sorted(overlap))}",
                param_hint="--only/--skip",
            )
    selected = [
        analyzer
        for analyzer in analyzers
        if (not only_names or analyzer.name in only_names)
        and analyzer.name not in skip_names
    ]
    if not selected:
        raise click.BadParameter(
            "selection contains no analyzers", param_hint="--only/--skip"
        )
    return selected


@click.command("skills-verified")
@click.argument("source")
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Also save the JSON report to this file.",
)
@click.option(
    "--skip", type=str, default=None, help="Comma-separated analyzer names to skip."
)
@click.option(
    "--only", type=str, default=None, help="Run only these comma-separated analyzers."
)
@click.option(
    "--analyzer-concurrency",
    type=click.IntRange(min=1, max=MAX_ANALYZER_CONCURRENCY),
    default=DEFAULT_ANALYZER_CONCURRENCY,
    envvar="SV_ANALYZER_CONCURRENCY",
    show_default=True,
    help="Maximum analyzers running concurrently.",
)
@click.option(
    "--progress/--no-progress",
    default=None,
    help="Show analyzer progress on stderr (default: enabled for a TTY).",
)
@click.option(
    "--max-clone-mib",
    type=click.IntRange(min=1, max=4096),
    default=DEFAULT_MAX_CLONE_BYTES // (1024 * 1024),
    envvar="SV_MAX_CLONE_MIB",
    show_default=True,
    help="Maximum estimated disk usage for a remote shallow clone.",
)
@click.option(
    "--clone-timeout",
    type=click.FloatRange(min=0, min_open=True),
    default=DEFAULT_CLONE_TIMEOUT_SECONDS,
    envvar="SV_CLONE_TIMEOUT",
    show_default=True,
    help="Maximum seconds allowed for remote repository acquisition.",
)
@click.option(
    "--max-scan-mib",
    type=click.IntRange(min=1, max=1024),
    default=DEFAULT_MAX_TOTAL_BYTES // (1024 * 1024),
    envvar="SV_MAX_SCAN_MIB",
    show_default=True,
    help="Maximum total size of regular files admitted to scan inventory.",
)
@click.option("--llm-url", type=str, default=None, envvar="SV_LLM_URL")
@click.option("--llm-model", type=str, default=None, envvar="SV_LLM_MODEL")
@click.option(
    "--llm-key",
    type=str,
    default=None,
    envvar="SV_LLM_KEY",
    help="LLM API key; prefer SV_LLM_KEY to keep it out of process arguments.",
)
@click.option(
    "--llm-timeout",
    type=click.FloatRange(min=0, min_open=True),
    default=DEFAULT_LLM_TIMEOUT_SECONDS,
    envvar="SV_LLM_TIMEOUT",
    show_default=True,
    help="Wall-clock timeout in seconds for each LLM request.",
)
@click.option(
    "--llm-total-timeout",
    type=click.FloatRange(min=0, min_open=True),
    default=None,
    envvar="SV_LLM_TOTAL_TIMEOUT",
    help="Optional wall-clock budget in seconds for all LLM batches.",
)
@click.option(
    "--llm-max-tokens",
    type=click.IntRange(min=1),
    default=MAX_COMPLETION_TOKENS,
    envvar="SV_LLM_MAX_TOKENS",
    show_default=True,
    help="Maximum completion tokens requested for each LLM batch.",
)
@click.option(
    "--llm-token-parameter",
    type=click.Choice(["max_completion_tokens", "max_tokens"]),
    default="max_tokens",
    envvar="SV_LLM_TOKEN_PARAMETER",
    show_default=True,
    help="Token-limit field supported by the configured endpoint.",
)
@click.option(
    "--llm-reasoning-effort",
    type=click.Choice(["minimal", "low", "medium", "high"]),
    default=None,
    envvar="SV_LLM_REASONING_EFFORT",
    help="Optional OpenAI-compatible reasoning effort sent to every LLM request.",
)
@click.option(
    "--llm-concurrency",
    type=click.IntRange(min=1, max=MAX_LLM_CONCURRENCY),
    default=DEFAULT_LLM_CONCURRENCY,
    envvar="SV_LLM_CONCURRENCY",
    show_default=True,
    help="Maximum concurrent LLM requests.",
)
@click.option(
    "--llm-max-batches",
    type=click.IntRange(min=1),
    default=None,
    envvar="SV_LLM_MAX_BATCHES",
    help="Optional maximum repository batches sent to the LLM.",
)
@click.option(
    "--llm-verification-runs",
    type=click.IntRange(min=0, max=MAX_LLM_VERIFICATION_RUNS),
    default=3,
    envvar="SV_LLM_VERIFICATION_RUNS",
    show_default=True,
    help="Adversarial verification attempts for each candidate batch; 0 disables.",
)
@click.option(
    "--llm-structured-output/--no-llm-structured-output",
    default=True,
    envvar="SV_LLM_STRUCTURED_OUTPUT",
    show_default=True,
    help="Request strict OpenAI-compatible JSON Schema output from the LLM endpoint.",
)
@click.option(
    "--compact", is_flag=True, help="Emit compact JSON instead of indented JSON."
)
def main(
    source: str,
    output: Path | None,
    skip: str | None,
    only: str | None,
    analyzer_concurrency: int,
    progress: bool | None,
    max_clone_mib: int,
    clone_timeout: float,
    max_scan_mib: int,
    llm_url: str | None,
    llm_model: str | None,
    llm_key: str | None,
    llm_timeout: float,
    llm_total_timeout: float | None,
    llm_max_tokens: int,
    llm_token_parameter: str,
    llm_reasoning_effort: str | None,
    llm_concurrency: int,
    llm_max_batches: int | None,
    llm_verification_runs: int,
    llm_structured_output: bool,
    compact: bool,
) -> None:
    """Analyze a local directory or Git repository and emit a policy-free JSON report."""
    llm_values = (llm_url, llm_model, llm_key)
    if any(llm_values) and not all(llm_values):
        raise click.UsageError(
            "--llm-url, --llm-model and --llm-key must be provided together"
        )
    try:
        llm_config = (
            LlmConfig(
                url=llm_url,
                model=llm_model,
                key=llm_key,
                structured_output=llm_structured_output,
                timeout_seconds=llm_timeout,
                total_timeout_seconds=llm_total_timeout,
                max_completion_tokens=llm_max_tokens,
                token_parameter=llm_token_parameter,
                reasoning_effort=llm_reasoning_effort,
                concurrency=llm_concurrency,
                max_batches=llm_max_batches,
                verification_runs=llm_verification_runs,
            )
            if llm_url and llm_model and llm_key
            else None
        )
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--llm-url") from exc
    analyzers = _select_analyzers(
        _all_analyzers(llm_config),
        only=only,
        skip=skip,
    )

    show_progress = progress if progress is not None else sys.stderr.isatty()
    progress_lock = threading.Lock()

    def emit_progress(message: str) -> None:
        with progress_lock:
            click.echo(message, err=True)

    pipeline = Pipeline(
        analyzers=analyzers,
        concurrency=analyzer_concurrency,
        progress=emit_progress if show_progress else None,
    )
    exit_code = 0
    try:
        with fetched_repo(
            source,
            timeout=clone_timeout,
            max_clone_bytes=max_clone_mib * 1024 * 1024,
        ) as repo_path:
            try:
                report = pipeline.run(
                    repo_path=repo_path,
                    repo_url=source,
                    max_total_bytes=max_scan_mib * 1024 * 1024,
                )
            except Exception as exc:
                report = pipeline.execution_failure(source, exc)
                exit_code = 3
    except Exception as exc:
        report = pipeline.input_failure(source, exc)
        exit_code = 2
    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            save_json_report(report, output, pretty=not compact)
        except OSError as exc:
            report.diagnostics.append(
                Diagnostic(
                    code="output_write_failed",
                    message=f"Could not write --output file: {type(exc).__name__}",
                    level=DiagnosticLevel.ERROR,
                    path=str(output),
                )
            )
            if exit_code == 0:
                exit_code = 3

    rendered = report_to_json(report, pretty=not compact)
    click.echo(rendered)

    if exit_code:
        sys.exit(exit_code)
    if report.scan.status == ScanStatus.FAILED:
        sys.exit(3)


if __name__ == "__main__":
    main()
