"""AST-based taint analysis for Python: track source→sink data flow with
sanitizer awareness. Pure-Python, no external dependencies."""
import ast
import logging
from dataclasses import dataclass
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

SOURCE_CALLS = {
    "input",
    "os.environ.get",
    "os.getenv",
    "sys.argv",
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.headers.get",
    "request.json",
    "request.cookies.get",
}
SOURCE_ATTRS = {"os.environ", "sys.argv", "request.args", "request.form"}

HANDLER_DECORATORS = {
    "app.get", "app.post", "app.put", "app.delete", "app.patch", "app.route",
    "router.get", "router.post", "router.put", "router.delete", "router.patch",
}


@dataclass(frozen=True)
class SinkRule:
    qualified: str
    severity: Severity
    category: Category
    title: str
    description: str


SINKS: list[SinkRule] = [
    SinkRule("subprocess.run", Severity.HIGH, Category.CODE_SAFETY,
             "Command injection via subprocess.run", "Tainted input flows into subprocess.run"),
    SinkRule("subprocess.call", Severity.HIGH, Category.CODE_SAFETY,
             "Command injection via subprocess.call", "Tainted input flows into subprocess.call"),
    SinkRule("subprocess.Popen", Severity.HIGH, Category.CODE_SAFETY,
             "Command injection via subprocess.Popen", "Tainted input flows into subprocess.Popen"),
    SinkRule("os.system", Severity.HIGH, Category.CODE_SAFETY,
             "Command injection via os.system", "Tainted input flows into os.system"),
    SinkRule("os.popen", Severity.HIGH, Category.CODE_SAFETY,
             "Command injection via os.popen", "Tainted input flows into os.popen"),
    SinkRule("eval", Severity.CRITICAL, Category.CODE_SAFETY,
             "Code injection via eval", "Tainted input flows into eval()"),
    SinkRule("exec", Severity.CRITICAL, Category.CODE_SAFETY,
             "Code injection via exec", "Tainted input flows into exec()"),
    SinkRule("pickle.loads", Severity.HIGH, Category.CODE_SAFETY,
             "Unsafe deserialization", "Tainted input flows into pickle.loads"),
    SinkRule("pickle.load", Severity.HIGH, Category.CODE_SAFETY,
             "Unsafe deserialization", "Tainted input flows into pickle.load"),
    SinkRule("urllib.request.urlopen", Severity.HIGH, Category.CODE_SAFETY,
             "SSRF via urllib.request.urlopen", "Tainted input flows into urlopen"),
    SinkRule("requests.get", Severity.HIGH, Category.CODE_SAFETY,
             "SSRF via requests.get", "Tainted input flows into requests.get"),
    SinkRule("requests.post", Severity.HIGH, Category.CODE_SAFETY,
             "SSRF via requests.post", "Tainted input flows into requests.post"),
    SinkRule("open", Severity.MEDIUM, Category.CODE_SAFETY,
             "Path traversal via open", "Tainted input flows into open()"),
]
SINK_INDEX: dict[str, SinkRule] = {s.qualified: s for s in SINKS}

SANITIZERS = {
    "shlex.quote",
    "os.path.abspath",
    "os.path.normpath",
    "werkzeug.utils.secure_filename",
    "secure_filename",
    "urllib.parse.quote",
    "html.escape",
}


class TaintAnalyzer(Analyzer):
    name = "taint"
    MAX_LINES = 10_000

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in repo_path.rglob("*.py"):
            if not file_path.is_file():
                continue
            try:
                source = file_path.read_text(errors="ignore")
            except OSError:
                continue
            if source.count("\n") > self.MAX_LINES:
                logger.warning("skipping %s: over %d lines", file_path, self.MAX_LINES)
                continue
            try:
                tree = ast.parse(source, filename=str(file_path))
            except SyntaxError:
                continue
            rel = str(file_path.relative_to(repo_path))
            findings.extend(self._analyze_module(tree, rel))
        return findings

    def _analyze_module(self, tree: ast.AST, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._analyze_function(node, rel_path))
        findings.extend(self._analyze_top_level(tree, rel_path))
        return findings

    def _analyze_function(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef, rel_path: str
    ) -> list[Finding]:
        tainted: set[str] = set()
        if _is_handler(func):
            for arg in func.args.args:
                tainted.add(arg.arg)
        visitor = _TaintVisitor(tainted, rel_path, self.name)
        visitor.visit(func)
        return visitor.findings

    def _analyze_top_level(self, tree: ast.AST, rel_path: str) -> list[Finding]:
        tainted: set[str] = set()
        visitor = _TaintVisitor(tainted, rel_path, self.name)
        for node in tree.body if isinstance(tree, ast.Module) else []:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            visitor.visit(node)
        return visitor.findings


def _is_handler(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in func.decorator_list:
        name = _qualified_name(dec.func if isinstance(dec, ast.Call) else dec)
        if name in HANDLER_DECORATORS:
            return True
    return False


def _qualified_name(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class _TaintVisitor(ast.NodeVisitor):
    def __init__(self, tainted: set[str], rel_path: str, analyzer_name: str):
        self.tainted = set(tainted)
        self.findings: list[Finding] = []
        self.rel_path = rel_path
        self.analyzer_name = analyzer_name

    def visit_Assign(self, node: ast.Assign) -> None:
        value_tainted = self._is_expr_tainted(node.value)
        if value_tainted:
            for target in node.targets:
                for name in _assigned_names(target):
                    self.tainted.add(name)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if self._is_expr_tainted(node.value) or self._is_expr_tainted(node.target):
            for name in _assigned_names(node.target):
                self.tainted.add(name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        qual = _qualified_name(node.func)
        if qual in SINK_INDEX:
            for arg in node.args:
                if self._is_expr_tainted(arg):
                    rule = SINK_INDEX[qual]
                    self.findings.append(Finding(
                        title=rule.title,
                        description=f"{rule.description} at {self.rel_path}:{node.lineno}",
                        severity=rule.severity,
                        category=rule.category,
                        file_path=self.rel_path,
                        line_number=node.lineno,
                        analyzer=self.analyzer_name,
                        confidence=0.85,
                    ))
                    break
        self.generic_visit(node)

    def _is_expr_tainted(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Attribute):
            qual = _qualified_name(node)
            if qual in SOURCE_ATTRS:
                return True
            return self._is_expr_tainted(node.value)
        if isinstance(node, ast.Subscript):
            qual = _qualified_name(node.value)
            if qual in SOURCE_ATTRS:
                return True
            return self._is_expr_tainted(node.value) or self._is_expr_tainted(node.slice)
        if isinstance(node, ast.Call):
            qual = _qualified_name(node.func)
            if qual in SANITIZERS:
                return False
            if qual in SOURCE_CALLS or qual == "input":
                return True
            # Propagate taint from arguments for transformations (str, .format, etc)
            for arg in node.args:
                if self._is_expr_tainted(arg):
                    return True
            for kw in node.keywords:
                if self._is_expr_tainted(kw.value):
                    return True
            return False
        if isinstance(node, ast.BinOp):
            return self._is_expr_tainted(node.left) or self._is_expr_tainted(node.right)
        if isinstance(node, ast.JoinedStr):  # f-string
            return any(self._is_expr_tainted(v) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._is_expr_tainted(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_expr_tainted(e) for e in node.elts)
        if isinstance(node, ast.IfExp):
            return self._is_expr_tainted(node.body) or self._is_expr_tainted(node.orelse)
        return False


def _assigned_names(target: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_assigned_names(elt))
    return names
