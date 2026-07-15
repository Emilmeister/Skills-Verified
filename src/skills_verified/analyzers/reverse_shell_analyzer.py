import logging
import re
from pathlib import Path

from skills_verified.analyzers.shell_utils import detect_shell_dialect
from skills_verified.core.analyzer import Analyzer
from skills_verified.core.context import iter_analysis_files
from skills_verified.core.models import Category, Diagnostic, Finding, Severity
from skills_verified.data.loader import SignatureLoader

logger = logging.getLogger(__name__)

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".rb", ".sh", ".ps1", ".pl", ".php"}

# File-level patterns matched against the entire file content (multiline awareness)
BUILTIN_FILE_PATTERNS = [
    {
        "title": "Python socket + subprocess reverse shell",
        "pattern": re.compile(
            r"\.connect\s*\([^)]*\)[\s\S]{0,2000}?"
            r"subprocess\.(?:call|run|Popen)\s*\([\s\S]{0,1000}?"
            r"(?:stdin|stdout|stderr)\s*=\s*\w+\.fileno\s*\(",
            re.DOTALL,
        ),
        "severity": Severity.CRITICAL,
        "description": "Python socket.socket combined with subprocess to establish a reverse shell.",
    },
]


class ReverseShellAnalyzer(Analyzer):
    name = "reverse_shell"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []
        self._yaml_patterns: list[dict] = []
        loader = SignatureLoader()
        sigs = loader.load_signatures("reverse_shell_signatures.yaml")
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
                    "Failed to compile reverse_shell signature %s: %s",
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
                self.diagnostics.append(
                    Diagnostic(
                        code="source_read_error",
                        message=f"Could not read source file: {type(exc).__name__}",
                        analyzer=self.name,
                        path=rel_path,
                    )
                )
                continue

            # Line-level scanning (built-in + YAML)
            for line_number, line in enumerate(content.splitlines(), start=1):
                for pat in self._yaml_patterns:
                    if pat["pattern"].search(line):
                        findings.append(
                            Finding(
                                title=pat["title"],
                                description=pat["description"],
                                severity=pat["severity"],
                                category=Category.CODE_SAFETY,
                                file_path=rel_path,
                                line_number=line_number,
                                analyzer=self.name,
                                rule_id=pat["id"],
                            )
                        )

            # File-level scanning for multiline patterns
            for pat in BUILTIN_FILE_PATTERNS:
                match = pat["pattern"].search(content)
                if match:
                    findings.append(
                        Finding(
                            title=pat["title"],
                            description=pat["description"],
                            severity=pat["severity"],
                            category=Category.CODE_SAFETY,
                            file_path=rel_path,
                            line_number=content.count("\n", 0, match.start()) + 1,
                            analyzer=self.name,
                            rule_id="SV-REVERSE-SHELL-PYTHON-SOCKET",
                        )
                    )
        return findings
