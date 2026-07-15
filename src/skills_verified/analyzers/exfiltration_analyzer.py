import logging
import re
from pathlib import Path

from skills_verified.analyzers.behavioral_analyzer import analyze_sensitive_flows
from skills_verified.analyzers.shell_utils import detect_shell_dialect
from skills_verified.core.analyzer import Analyzer
from skills_verified.core.context import iter_analysis_files
from skills_verified.core.models import (
    Category,
    Diagnostic,
    Evidence,
    Finding,
    Severity,
)
from skills_verified.core.python_ast import parse_python
from skills_verified.data.loader import SignatureLoader

logger = logging.getLogger(__name__)

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".rb", ".sh"}


class ExfiltrationAnalyzer(Analyzer):
    name = "exfiltration"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []
        self._yaml_patterns: list[dict] = []
        loader = SignatureLoader()
        sigs = loader.load_signatures("exfiltration_patterns.yaml")
        for sig in sigs:
            try:
                compiled = re.compile(sig["pattern"])
                self._yaml_patterns.append(
                    {
                        "id": sig["id"],
                        "title": sig.get("title", sig["id"]),
                        "pattern": compiled,
                        "severity": getattr(Severity, sig["severity"]),
                        "description": sig.get("description", ""),
                    }
                )
            except re.error:
                logger.warning(
                    "Failed to compile exfiltration signature %s: %s",
                    sig.get("id", "?"),
                    sig["pattern"],
                )

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        self.diagnostics = []
        findings: list[Finding] = []
        for file_path in iter_analysis_files(repo_path, kwargs.get("context")):
            if (
                file_path.suffix not in SCAN_EXTENSIONS
                and detect_shell_dialect(file_path) is None
            ):
                continue
            rel_path = str(file_path.relative_to(repo_path))
            try:
                content = file_path.read_text(errors="ignore")
            except OSError as exc:
                self._diagnostic(
                    "source_read_error",
                    f"Could not read source file: {type(exc).__name__}",
                    rel_path,
                )
                continue
            if file_path.suffix == ".py":
                try:
                    parse_python(content)
                except SyntaxError as exc:
                    location = f" at line {exc.lineno}" if exc.lineno else ""
                    self._diagnostic(
                        "python_parse_error",
                        f"Could not parse Python source{location}: {exc.msg}",
                        rel_path,
                        details={"line": exc.lineno, "offset": exc.offset},
                    )
                else:
                    findings.extend(
                        analyze_sensitive_flows(
                            content,
                            rel_path,
                            self.name,
                            category=Category.EXFILTRATION,
                            network_only=True,
                        )
                    )
            for line_number, line in enumerate(content.splitlines(), start=1):
                for pat in self._yaml_patterns:
                    if pat["pattern"].search(line):
                        findings.append(
                            Finding(
                                title=pat["title"],
                                description=pat["description"],
                                severity=pat["severity"],
                                category=Category.EXFILTRATION,
                                file_path=rel_path,
                                line_number=line_number,
                                analyzer=self.name,
                                rule_id=pat["id"],
                                evidence=Evidence(
                                    kind="source",
                                    snippet=line.strip()[:500],
                                ),
                            )
                        )
        return findings

    def _diagnostic(
        self,
        code: str,
        message: str,
        path: str,
        *,
        details: dict | None = None,
    ) -> None:
        self.diagnostics.append(
            Diagnostic(
                code=code,
                message=message,
                analyzer=self.name,
                path=path,
                details=details or {},
            )
        )
