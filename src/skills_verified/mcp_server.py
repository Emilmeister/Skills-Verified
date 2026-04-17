"""MCP stdio server that exposes skills-verified scanning over the Model Context
Protocol. Reuses `core.runner.run_scan` so all analyzer wiring stays in one place."""
import logging
import sys
from collections import Counter
from pathlib import Path

from skills_verified.analyzers.aibom_analyzer import AibomAnalyzer
from skills_verified.core.models import Finding, Report
from skills_verified.core.runner import ScanOptions, build_analyzers, run_scan
from skills_verified.output.aibom_export import inventory_to_cyclonedx

VERSION = "0.1.0"

logger = logging.getLogger("skills_verified.mcp")


def _report_to_summary(report: Report, top_n: int = 10) -> dict:
    severity_counter: Counter[str] = Counter(f.severity.value for f in report.findings)
    category_counter: Counter[str] = Counter(f.category.value for f in report.findings)
    top = sorted(
        report.findings,
        key=lambda f: (_severity_rank(f.severity.value), -(f.confidence or 0)),
    )[:top_n]
    return {
        "overall_score": report.overall_score,
        "overall_grade": report.overall_grade.value,
        "categories": {
            c.category.value: {
                "score": c.score,
                "grade": c.grade.value,
                "findings_count": c.findings_count,
            }
            for c in report.categories
        },
        "findings_count": len(report.findings),
        "findings_by_severity": dict(severity_counter),
        "findings_by_category": dict(category_counter),
        "top_findings": [_finding_to_dict(f) for f in top],
        "analyzers_used": report.analyzers_used,
        "scan_duration_seconds": report.scan_duration_seconds,
    }


def _severity_rank(severity_value: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity_value, 5)


def _finding_to_dict(f: Finding) -> dict:
    return {
        "title": f.title,
        "severity": f.severity.value,
        "category": f.category.value,
        "file_path": f.file_path,
        "line_number": f.line_number,
        "analyzer": f.analyzer,
        "confidence": f.confidence,
    }


def tool_scan(path: str, skip: list[str] | None = None, only: list[str] | None = None) -> dict:
    """Run the full scan pipeline against `path`; return a summary dict."""
    opts = ScanOptions(
        skip=set(skip or []),
        only=set(only) if only else None,
    )
    report, _, _ = run_scan(path, opts)
    return _report_to_summary(report)


def tool_scan_file(path: str, analyzer_name: str) -> dict:
    """Run one analyzer against a single file (or small repo-path). Useful for
    in-IDE feedback loops where full scan would be too slow."""
    opts = ScanOptions(only={analyzer_name})
    analyzers, _ = build_analyzers(opts)
    if not analyzers:
        return {"error": f"unknown analyzer: {analyzer_name}"}
    target = Path(path)
    analyzer = analyzers[0]
    if not analyzer.is_available():
        return {"error": f"analyzer '{analyzer_name}' not available in this environment"}
    if target.is_file():
        repo_path = target.parent
    else:
        repo_path = target
    findings = analyzer.analyze(repo_path)
    if target.is_file():
        rel = str(target.relative_to(repo_path))
        findings = [f for f in findings if f.file_path == rel]
    return {
        "analyzer": analyzer_name,
        "path": str(target),
        "findings": [_finding_to_dict(f) for f in findings],
    }


def tool_aibom(path: str) -> dict:
    """Run only the AI-BOM analyzer and return the CycloneDX 1.6 JSON document."""
    analyzer = AibomAnalyzer()
    analyzer.analyze(Path(path))
    inv = analyzer.last_inventory
    if inv is None:
        return {"error": "no inventory collected"}
    return inventory_to_cyclonedx(inv, repo_name=Path(path).name or "repo")


def tool_version() -> str:
    return VERSION


def serve_stdio() -> None:
    """Start the MCP stdio server. Requires `mcp>=1.0` (install via `.[mcp]`)."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "mcp package not installed. Install with: pip install 'skills-verified[mcp]'",
            file=sys.stderr,
        )
        sys.exit(2)

    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    server = FastMCP("skills-verified")

    @server.tool()
    def skills_verified_scan(
        path: str,
        skip: list[str] | None = None,
        only: list[str] | None = None,
    ) -> dict:
        """Full pipeline scan; returns trust-score summary and top findings."""
        return tool_scan(path, skip=skip, only=only)

    @server.tool()
    def skills_verified_scan_file(path: str, analyzer: str) -> dict:
        """Run a single named analyzer on a file or small directory."""
        return tool_scan_file(path, analyzer)

    @server.tool()
    def skills_verified_aibom(path: str) -> dict:
        """Generate a CycloneDX 1.6 AI-BOM for the given path."""
        return tool_aibom(path)

    @server.tool()
    def skills_verified_version() -> str:
        """Return the skills-verified version string."""
        return tool_version()

    server.run()
