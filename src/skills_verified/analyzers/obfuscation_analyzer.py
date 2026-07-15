import ast
import logging
import re
from pathlib import Path

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

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".rb", ".sh", ".ps1"}

_STRUCTURED_RULE_IDS = {"OB001", "OB006", "OB011"}
_DANGEROUS_DYNAMIC_NAMES = {
    "__import__",
    "bash",
    "compile",
    "curl",
    "eval",
    "exec",
    "popen",
    "powershell",
    "system",
    "wget",
}


class ObfuscationAnalyzer(Analyzer):
    name = "obfuscation"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []
        self._yaml_patterns: list[dict] = []
        self._structured_patterns: dict[str, dict] = {}
        loader = SignatureLoader()
        sigs = loader.load_signatures("obfuscation_signatures.yaml")
        for sig in sigs:
            if sig["id"] in {"OB001", "OB005"}:
                self._structured_patterns[sig["id"]] = {
                    "title": sig.get("title", sig["id"]),
                    "severity": getattr(Severity, sig["severity"]),
                    "description": sig.get("description", ""),
                }
                continue
            if sig["id"] in _STRUCTURED_RULE_IDS:
                self._structured_patterns[sig["id"]] = {
                    "title": sig.get("title", sig["id"]),
                    "severity": getattr(Severity, sig["severity"]),
                    "description": sig.get("description", ""),
                }
                continue
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
                    "Failed to compile obfuscation signature %s: %s",
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
            if file_path.suffix == ".py":
                findings.extend(self._analyze_python(content, rel_path))
            for line_number, line in enumerate(content.splitlines(), start=1):
                findings.extend(self._hex_escape_findings(line, rel_path, line_number))
                for pat in self._yaml_patterns:
                    if pat["pattern"].search(line):
                        findings.append(
                            Finding(
                                title=pat["title"],
                                description=pat["description"],
                                severity=pat["severity"],
                                category=Category.OBFUSCATION,
                                file_path=rel_path,
                                line_number=line_number,
                                analyzer=self.name,
                                rule_id=pat["id"],
                            )
                        )
        return findings

    def _hex_escape_findings(
        self, line: str, rel_path: str, line_number: int
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in re.finditer(r"(?:\\x[0-9a-fA-F]{2}){4,}", line):
            decoded = bytes.fromhex(match.group().replace("\\x", "")).decode("latin-1")
            if sum(char.isprintable() for char in decoded) / len(decoded) < 0.8:
                continue
            if not any(
                marker in decoded.casefold()
                for marker in (
                    *_DANGEROUS_DYNAMIC_NAMES,
                    "http://",
                    "https://",
                    "/bin/",
                )
            ):
                continue
            findings.append(
                self._structured_finding("OB001", rel_path, line_number, match.group())
            )
        return findings

    def _analyze_python(self, content: str, rel_path: str) -> list[Finding]:
        try:
            tree = parse_python(content)
        except SyntaxError:
            return []

        findings: list[Finding] = []
        seen_identifiers: set[tuple[str, int]] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                joined = self._joined_string(node)
                if (
                    joined is not None
                    and not isinstance(node.left, ast.BinOp)
                    and joined.casefold() in _DANGEROUS_DYNAMIC_NAMES
                ):
                    findings.append(
                        self._structured_finding(
                            "OB005", rel_path, node.lineno, ast.unparse(node)[:500]
                        )
                    )

            identifier = self._identifier(node)
            if identifier and self._is_mixed_script(identifier):
                key = (identifier, node.lineno)
                if key not in seen_identifiers:
                    seen_identifiers.add(key)
                    findings.append(
                        self._structured_finding(
                            "OB006", rel_path, node.lineno, identifier
                        )
                    )

            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in {"getattr", "setattr"} or len(node.args) < 2:
                continue
            attribute_node = node.args[1]
            attribute = self._joined_string(attribute_node)
            if (
                attribute is not None
                and not isinstance(attribute_node, ast.Constant)
                and attribute.lower() in _DANGEROUS_DYNAMIC_NAMES
            ):
                findings.append(
                    self._structured_finding(
                        "OB011", rel_path, node.lineno, ast.unparse(node)[:500]
                    )
                )
        return findings

    @staticmethod
    def _identifier(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.arg):
            return node.arg
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return node.name
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    @staticmethod
    def _is_mixed_script(identifier: str) -> bool:
        return bool(re.search(r"[A-Za-z]", identifier)) and bool(
            re.search(r"[\u0400-\u04FF]", identifier)
        )

    @classmethod
    def _joined_string(cls, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = cls._joined_string(node.left)
            right = cls._joined_string(node.right)
            if left is not None and right is not None:
                return left + right
        return None

    def _structured_finding(
        self, rule_id: str, rel_path: str, line_number: int, evidence: str
    ) -> Finding:
        rule = self._structured_patterns[rule_id]
        return Finding(
            title=rule["title"],
            description=rule["description"],
            severity=rule["severity"],
            category=Category.OBFUSCATION,
            file_path=rel_path,
            line_number=line_number,
            analyzer=self.name,
            rule_id=rule_id,
            evidence=Evidence(kind="source", snippet=evidence),
        )
