"""Shared scan-orchestration helpers, reused by CLI and MCP server."""
from dataclasses import dataclass, field
from pathlib import Path

from skills_verified.analyzers.aibom_analyzer import AibomAnalyzer
from skills_verified.analyzers.bandit_analyzer import BanditAnalyzer
from skills_verified.analyzers.container_analyzer import ContainerAnalyzer
from skills_verified.analyzers.cve_analyzer import CveAnalyzer
from skills_verified.analyzers.guardrails_analyzer import GuardrailsAnalyzer
from skills_verified.analyzers.llm_analyzer import LlmAnalyzer, LlmConfig
from skills_verified.analyzers.llm_verifier import LlmVerifier
from skills_verified.analyzers.model_risk import ModelRiskRegistry
from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.analyzers.permissions_analyzer import PermissionsAnalyzer
from skills_verified.analyzers.semgrep_analyzer import SemgrepAnalyzer
from skills_verified.analyzers.supply_chain_analyzer import SupplyChainAnalyzer
from skills_verified.analyzers.taint_analyzer import TaintAnalyzer
from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Report
from skills_verified.core.pipeline import Pipeline
from skills_verified.repo.fetcher import fetch_repo


@dataclass
class ScanOptions:
    llm_config: LlmConfig | None = None
    llm_passes: int = 1
    llm_reduce: bool = False
    llm_verify: bool = False
    aibom_strict: bool = False
    model_risk_enrichment: bool = True
    image: str | None = None
    skip: set[str] = field(default_factory=set)
    only: set[str] | None = None
    branch: str | None = None


def build_analyzers(opts: ScanOptions) -> tuple[list[Analyzer], AibomAnalyzer]:
    """Return filtered analyzer list and the AibomAnalyzer instance (for post-scan BOM export)."""
    verifier = None
    if opts.llm_verify and opts.llm_config is not None:
        verifier = LlmVerifier(
            static_analyzers=[PatternAnalyzer(), BanditAnalyzer(), SemgrepAnalyzer()],
            config=opts.llm_config,
        )

    registry = ModelRiskRegistry() if opts.model_risk_enrichment else None
    aibom = AibomAnalyzer(strict=opts.aibom_strict, risk_registry=registry)
    all_analyzers: list[Analyzer] = [
        PatternAnalyzer(),
        TaintAnalyzer(),
        CveAnalyzer(),
        BanditAnalyzer(),
        SemgrepAnalyzer(),
        GuardrailsAnalyzer(),
        PermissionsAnalyzer(),
        SupplyChainAnalyzer(),
        ContainerAnalyzer(image=opts.image),
        aibom,
        LlmAnalyzer(
            config=opts.llm_config,
            passes=opts.llm_passes,
            reduce=opts.llm_reduce,
            verifier=verifier,
        ),
    ]

    selected: list[Analyzer] = []
    for a in all_analyzers:
        if a.name in opts.skip:
            continue
        if opts.only is not None and a.name not in opts.only:
            continue
        selected.append(a)
    return selected, aibom


def run_scan(source: str, opts: ScanOptions | None = None) -> tuple[Report, AibomAnalyzer, Path]:
    """Fetch source, run pipeline, return (report, aibom_analyzer, repo_path)."""
    opts = opts or ScanOptions()
    analyzers, aibom = build_analyzers(opts)
    repo_path = fetch_repo(source, branch=opts.branch)
    pipeline = Pipeline(analyzers=analyzers)
    report = pipeline.run(
        repo_path=repo_path,
        repo_url=source,
        llm_used=opts.llm_config is not None,
    )
    return report, aibom, repo_path
