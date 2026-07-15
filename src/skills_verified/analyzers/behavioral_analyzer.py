import ast
import logging
import re
from pathlib import Path

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

logger = logging.getLogger(__name__)

SCAN_EXTENSIONS_AST = {".py"}

# --- AST analysis configuration ---

# Source functions/attributes that read sensitive data
SENSITIVE_SOURCE_CALLS = {
    "input",
    "os.getenv",
    "sys.stdin.read",
}

# Sink functions that send data externally or execute commands
NETWORK_SINKS = {
    "aiohttp.request",
    "httpx.post",
    "requests.post",
    "socket.getaddrinfo",
    "socket.gethostbyname",
    "socket.send",
    "socket.sendall",
    "urllib.request.Request",
    "urllib.request.urlopen",
}

DNS_SINKS = {"socket.getaddrinfo", "socket.gethostbyname"}

EXECUTION_SINKS = {
    "eval",
    "exec",
    "os.popen",
    "os.system",
    "subprocess.call",
    "subprocess.check_output",
    "subprocess.run",
    "subprocess.Popen",
}

DANGEROUS_SINKS = NETWORK_SINKS | EXECUTION_SINKS

# ---------------------------------------------------------------------------
# AST visitor: lightweight source-to-sink taint detection within a function
# or at module level.
# ---------------------------------------------------------------------------


class _TaintVisitor(ast.NodeVisitor):
    """Conservative intra-scope source-to-sink tracking for Python."""

    def __init__(
        self,
        rel_path: str,
        analyzer_name: str,
        source_text: str,
        *,
        category: Category = Category.CODE_SAFETY,
        line_offset: int = 0,
        network_only: bool = False,
        safe_command_builders: frozenset[str] = frozenset(),
    ) -> None:
        self.rel_path = rel_path
        self.analyzer_name = analyzer_name
        self.source_text = source_text
        self.category = category
        self.line_offset = line_offset
        self.network_only = network_only
        self.safe_command_builders = safe_command_builders
        self.findings: list[Finding] = []
        self._scope_taints: list[dict[str, tuple[str, int]]] = [{}]
        self._scope_safe_commands: list[set[str]] = [set()]

    @staticmethod
    def _attr_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = _TaintVisitor._attr_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
        return None

    @property
    def _current_taints(self) -> dict[str, tuple[str, int]]:
        return self._scope_taints[-1]

    @property
    def _current_safe_commands(self) -> set[str]:
        return self._scope_safe_commands[-1]

    def _call_name(self, node: ast.Call) -> str | None:
        return self._attr_name(node.func)

    @staticmethod
    def _open_reads(node: ast.Call) -> bool:
        mode: ast.AST | None = node.args[1] if len(node.args) > 1 else None
        for keyword in node.keywords:
            if keyword.arg == "mode":
                mode = keyword.value
        return not (
            isinstance(mode, ast.Constant)
            and isinstance(mode.value, str)
            and any(flag in mode.value for flag in "wax+")
        )

    def _source_call(self, node: ast.Call) -> str | None:
        name = self._call_name(node)
        if not name:
            return None
        if name in SENSITIVE_SOURCE_CALLS:
            return name
        if name in {
            "os.environ.copy",
            "os.environ.items",
            "os.environ.keys",
            "os.environ.values",
        }:
            return "os.environ"
        if name.startswith("os.environ."):
            return "os.getenv"
        if name == "open" and self._open_reads(node):
            return "file read"
        if name in {"Path.read_bytes", "Path.read_text"}:
            return "file read"
        if name == "os.listdir":
            return "filesystem listing"
        if name in {"httpx.get", "requests.get", "urllib.request.urlopen"}:
            return "network response"
        return None

    def _expression_taint(self, node: ast.AST | None) -> tuple[str, int] | None:
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return self._current_taints.get(node.id)
        if (
            isinstance(node, ast.Subscript)
            and self._attr_name(node.value) == "os.environ"
        ):
            return "os.getenv", getattr(node, "lineno", 0) + self.line_offset
        if isinstance(node, ast.Call):
            source = self._source_call(node)
            if source:
                return source, node.lineno + self.line_offset
        if self._attr_name(node) == "os.environ":
            return "os.environ", getattr(node, "lineno", 0) + self.line_offset
        for child in ast.iter_child_nodes(node):
            taint = self._expression_taint(child)
            if taint:
                return taint
        return None

    def _assign_target(
        self,
        target: ast.AST,
        taint: tuple[str, int] | None,
    ) -> None:
        if isinstance(target, ast.Name):
            if taint:
                self._current_taints[target.id] = taint
            else:
                self._current_taints.pop(target.id, None)
            return
        if isinstance(target, (ast.List, ast.Tuple)):
            for item in target.elts:
                self._assign_target(item, taint)
            return
        if isinstance(target, ast.Subscript) and taint:
            root = target.value
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name):
                self._current_taints[root.id] = taint

    @staticmethod
    def _uses_network_utility(node: ast.Call) -> bool:
        return any(
            isinstance(candidate, ast.Constant)
            and isinstance(candidate.value, str)
            and candidate.value in {"curl", "nc", "ncat", "wget"}
            for candidate in ast.walk(node)
        )

    def _sink_name(self, node: ast.Call) -> str | None:
        name = self._call_name(node)
        if not name:
            return None
        if name in NETWORK_SINKS:
            return name
        if name in EXECUTION_SINKS:
            if not self.network_only or self._uses_network_utility(node):
                return name
        return None

    def _sink_values(self, node: ast.Call, sink_name: str) -> list[ast.AST]:
        if sink_name in EXECUTION_SINKS:
            values: list[ast.AST] = []
            if node.args:
                command = node.args[0]
                if self.network_only and self._uses_network_utility(node):
                    if isinstance(command, (ast.List, ast.Tuple)):
                        values.extend(command.elts[1:])
                    else:
                        values.append(command)
                    return values
                shell_enabled = any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
                if (
                    sink_name.startswith("subprocess.")
                    and isinstance(command, (ast.List, ast.Tuple))
                    and not shell_enabled
                ):
                    values.extend(command.elts[:1])
                elif (
                    sink_name.startswith("subprocess.")
                    and isinstance(command, ast.Name)
                    and command.id in self._current_safe_commands
                    and not shell_enabled
                ):
                    pass
                else:
                    values.append(command)
            values.extend(
                keyword.value
                for keyword in node.keywords
                if keyword.arg in {"args", "executable"}
            )
            return values
        if sink_name in DNS_SINKS or sink_name.startswith("socket."):
            return [*node.args, *(keyword.value for keyword in node.keywords)]
        values = list(node.args[1:])
        values.extend(
            keyword.value
            for keyword in node.keywords
            if keyword.arg not in {"auth", "cookies", "headers", "timeout"}
        )
        return values

    @staticmethod
    def _is_auth_endpoint(node: ast.Call) -> bool:
        if not node.args:
            return False
        try:
            rendered = ast.unparse(node.args[0]).casefold()
        except Exception:
            return False
        return bool(re.search(r"/(?:auth|login|oauth|token)(?:[/_'\"]|$)", rendered))

    def _evidence(self, node: ast.AST) -> str:
        segment = ast.get_source_segment(self.source_text, node)
        if segment:
            return " ".join(segment.split())[:500]
        lines = self.source_text.splitlines()
        line = getattr(node, "lineno", 0)
        return lines[line - 1].strip()[:500] if 1 <= line <= len(lines) else ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope_taints.append({})
        self._scope_safe_commands.append(set())
        self.generic_visit(node)
        self._scope_safe_commands.pop()
        self._scope_taints.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Assign(self, node: ast.Assign) -> None:
        taint = self._expression_taint(node.value)
        for target in node.targets:
            self._assign_target(target, taint)
            self._assign_safe_command(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._assign_target(node.target, self._expression_taint(node.value))
        if node.value is not None:
            self._assign_safe_command(node.target, node.value)
        self.generic_visit(node)

    def _assign_safe_command(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Name):
            return
        call_name = self._call_name(value) if isinstance(value, ast.Call) else None
        if _has_static_command_head(value) or call_name in self.safe_command_builders:
            self._current_safe_commands.add(target.id)
        else:
            self._current_safe_commands.discard(target.id)

    def visit_For(self, node: ast.For) -> None:
        self._assign_target(node.target, self._expression_taint(node.iter))
        self.generic_visit(node)

    visit_AsyncFor = visit_For  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:
        sink_name = self._sink_name(node)
        taint = None
        if sink_name:
            for value in self._sink_values(node, sink_name):
                taint = self._expression_taint(value)
                if taint:
                    break
        if (
            sink_name in NETWORK_SINKS
            and taint is not None
            and taint[0] in {"os.getenv", "input"}
            and self._is_auth_endpoint(node)
        ):
            taint = None
        if sink_name and taint:
            source_name, source_line = taint
            is_network = sink_name in NETWORK_SINKS or self._uses_network_utility(node)
            if sink_name in DNS_SINKS:
                rule_id = "SV-DATAFLOW-SENSITIVE-DNS"
                title = "Sensitive data reaches a DNS resolution sink"
            elif is_network:
                rule_id = "SV-DATAFLOW-SENSITIVE-NETWORK"
                title = "Sensitive data reaches an outbound network sink"
            else:
                rule_id = "SV-DATAFLOW-SENSITIVE-EXECUTION"
                title = "Sensitive data reaches an execution sink"
            self.findings.append(
                Finding(
                    title=title,
                    description=(
                        f"Data originating from {source_name} at line {source_line} "
                        f"reaches {sink_name}."
                    ),
                    severity=Severity.HIGH,
                    category=self.category,
                    file_path=self.rel_path,
                    line_number=node.lineno + self.line_offset,
                    end_line=(node.end_lineno or node.lineno) + self.line_offset,
                    analyzer=self.analyzer_name,
                    rule_id=rule_id,
                    evidence=Evidence(kind="source", snippet=self._evidence(node)),
                    remediation=(
                        "Remove the data transfer or restrict it to explicitly declared, "
                        "non-sensitive fields and an approved destination."
                    ),
                    confidence=0.95,
                )
            )
        self.generic_visit(node)


def analyze_sensitive_flows(
    content: str,
    rel_path: str,
    analyzer_name: str,
    *,
    category: Category = Category.CODE_SAFETY,
    network_only: bool = False,
) -> list[Finding]:
    """Analyze normal Python plus generated Python stored in assigned strings."""
    try:
        tree = parse_python(content)
    except SyntaxError:
        return []

    safe_command_builders = _find_safe_command_builders(tree)

    visitors = [
        _TaintVisitor(
            rel_path,
            analyzer_name,
            content,
            category=category,
            network_only=network_only,
            safe_command_builders=safe_command_builders,
        )
    ]
    visitors[0].visit(tree)

    embedded_values: dict[int, tuple[ast.Constant, bool]] = {}
    for assignment in ast.walk(tree):
        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
            continue
        if assignment.value is None:
            continue
        formatted = (
            isinstance(assignment.value, ast.Call)
            and isinstance(assignment.value.func, ast.Attribute)
            and assignment.value.func.attr == "format"
        )
        for value in ast.walk(assignment.value):
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                embedded_values[id(value)] = (value, formatted)

    for value, formatted in embedded_values.values():
        embedded_source = (
            value.value.replace("{{", "{").replace("}}", "}")
            if formatted
            else value.value
        )
        if not (
            "\n" in embedded_source
            and any(
                marker in embedded_source
                for marker in ("os.environ", "os.getenv", "os.listdir", "open(")
            )
            and any(
                marker in embedded_source
                for marker in (
                    "requests.post",
                    "subprocess.",
                    "urllib.request",
                    "httpx.post",
                )
            )
        ):
            continue
        try:
            embedded_tree = parse_python(embedded_source)
        except SyntaxError:
            continue
        visitor = _TaintVisitor(
            rel_path,
            analyzer_name,
            embedded_source,
            category=category,
            line_offset=value.lineno - 1,
            network_only=network_only,
            safe_command_builders=_find_safe_command_builders(embedded_tree),
        )
        visitor.visit(embedded_tree)
        visitors.append(visitor)

    unique: dict[tuple[str | None, int | None, str], Finding] = {}
    for visitor in visitors:
        for finding in visitor.findings:
            key = (
                finding.rule_id,
                finding.line_number,
                finding.evidence.snippet if finding.evidence else "",
            )
            unique.setdefault(key, finding)
    return list(unique.values())


def _find_safe_command_builders(tree: ast.AST) -> frozenset[str]:
    """Find local helpers whose returned command always has a static executable."""
    builders: set[str] = set()
    for function in (
        node
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ):
        assignments: dict[str, ast.AST] = {}
        returns: list[ast.AST] = []
        for node in function.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(
                node.value, (ast.List, ast.Tuple)
            ):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = node.value
            if isinstance(node, ast.Return) and node.value is not None:
                returns.append(node.value)
        resolved = [
            assignments.get(value.id, value) if isinstance(value, ast.Name) else value
            for value in returns
        ]
        if resolved and all(_has_static_command_head(value) for value in resolved):
            builders.add(function.name)
    return frozenset(builders)


def _has_static_command_head(value: ast.AST) -> bool:
    if not isinstance(value, (ast.List, ast.Tuple)) or not value.elts:
        return False
    head = value.elts[0]
    return (
        isinstance(head, ast.Constant)
        and isinstance(head.value, str)
        or _TaintVisitor._attr_name(head) == "sys.executable"
    )


class BehavioralAnalyzer(Analyzer):
    name = "behavioral"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        self.diagnostics = []
        findings: list[Finding] = []
        for file_path in iter_analysis_files(repo_path, kwargs.get("context")):
            suffix = file_path.suffix
            if suffix not in SCAN_EXTENSIONS_AST:
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

            # AST-based analysis for Python files
            if suffix in SCAN_EXTENSIONS_AST:
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
                    findings.extend(self._analyze_ast(content, rel_path))

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

    def _analyze_ast(self, content: str, rel_path: str) -> list[Finding]:
        """Run AST-based taint analysis on Python source."""
        findings = analyze_sensitive_flows(content, rel_path, self.name)
        findings.extend(self._check_python_startup_persistence(content, rel_path))
        return findings

    def _check_python_startup_persistence(
        self,
        content: str,
        rel_path: str,
    ) -> list[Finding]:
        if not re.search(
            r"(?:\bopen\s*\([^)]*['\"](?:w|a|x)|"
            r"\.write_(?:text|bytes)\s*\(|"
            r"\b(?:copy|copyfile|move|replace)\s*\()",
            content,
        ):
            return []

        match = re.search(
            r"\b(?:sitecustomize|usercustomize)\.py\b",
            content,
            re.IGNORECASE,
        )
        if not match:
            return []
        line_number = content.count("\n", 0, match.start()) + 1
        line = content.splitlines()[line_number - 1].strip()
        return [
            Finding(
                title="Python startup hook persistence",
                description=(
                    "Creates a Python startup hook that is imported automatically "
                    "by future interpreter processes."
                ),
                severity=Severity.HIGH,
                category=Category.CODE_SAFETY,
                file_path=rel_path,
                line_number=line_number,
                analyzer=self.name,
                rule_id="SV-BEHAVIOR-PYTHON-STARTUP-PERSISTENCE",
                evidence=Evidence(kind="source", snippet=line[:500]),
                remediation=(
                    "Do not modify sitecustomize.py or usercustomize.py; use an "
                    "explicit, scoped entry point that the user invokes."
                ),
                confidence=0.98,
            )
        ]
