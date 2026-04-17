"""Natural-language policy engine for --fail-on. Parses a free-form policy via
LLM into a bounded boolean AST, then evaluates it in a sandbox — never eval()."""
import ast
import logging
from dataclasses import dataclass
from types import SimpleNamespace

from skills_verified.core.models import Report, Severity

logger = logging.getLogger(__name__)


class PolicyError(Exception):
    pass


_ALLOWED_NODES: tuple[type, ...] = (
    ast.Expression,
    ast.BoolOp, ast.UnaryOp,
    ast.Compare, ast.Name, ast.Attribute, ast.Constant, ast.Subscript,
    ast.And, ast.Or, ast.Not,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.Load,
    # tuple/list literals for membership-style comparisons
    ast.Tuple, ast.List,
    ast.In, ast.NotIn,
    ast.USub, ast.UAdd,
)


@dataclass
class PolicyRule:
    expression: str  # original expression text (for diagnostics)
    _tree: ast.Expression  # pre-parsed & validated AST

    @property
    def tree(self) -> ast.Expression:
        return self._tree


_BUILTIN_RULES: dict[str, str] = {
    "strict": "report.overall_grade == 'A' and report.criticals == 0",
    "standard": "report.overall_grade in ('A','B','C') and report.criticals == 0",
    "relaxed": "report.overall_grade != 'F' and report.criticals <= 2",
}


class PolicyEngine:
    def __init__(self, llm_config=None):
        self.llm_config = llm_config

    def parse(self, policy_text: str) -> PolicyRule:
        normalized = policy_text.strip().lower()
        if normalized in _BUILTIN_RULES:
            return self._compile(_BUILTIN_RULES[normalized])
        expr = self._translate_nl(policy_text)
        return self._compile(expr)

    def evaluate(self, rule: PolicyRule, report: Report) -> tuple[bool, str]:
        namespace = {"report": _report_namespace(report)}
        try:
            result = _SafeEvaluator(namespace).visit(rule.tree.body)
        except PolicyError:
            raise
        except Exception as e:
            raise PolicyError(f"policy evaluation failed: {e}") from e
        return bool(result), f"policy `{rule.expression}` → {bool(result)}"

    def _translate_nl(self, policy_text: str) -> str:
        if self.llm_config is None:
            raise PolicyError(
                "free-form policies require an LLM: pass --llm-url/--llm-model/--llm-key"
            )
        try:
            from openai import OpenAI
        except ImportError as e:
            raise PolicyError("openai package required for NL policies") from e
        client = OpenAI(base_url=self.llm_config.url, api_key=self.llm_config.key)
        system = (
            "You translate a natural-language CI gate policy into a single Python "
            "boolean expression. Output ONLY the expression, no markdown, no quotes, "
            "no explanation.\n\n"
            "Available fields:\n"
            "  report.overall_score      int, 0-100\n"
            "  report.overall_grade      string 'A'|'B'|'C'|'D'|'F'\n"
            "  report.criticals          int — number of CRITICAL findings\n"
            "  report.highs              int — number of HIGH findings\n"
            "  report.findings_count     int\n"
            "  report.categories.code_safety.score   int\n"
            "  report.categories.code_safety.grade   string\n"
            "  (same for cve, guardrails, permissions, supply_chain, ai_bom)\n"
            "  report.shadow_models      int — AI_BOM findings suggesting shadow AI\n\n"
            "Allowed operators: and, or, not, ==, !=, <, <=, >, >=, in, not in.\n"
            "Do NOT call any functions. Do NOT use imports. Do NOT use attribute calls."
        )
        try:
            resp = client.chat.completions.create(
                model=self.llm_config.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": policy_text},
                ],
                temperature=0,
            )
            expr = (resp.choices[0].message.content or "").strip()
        except Exception as e:
            raise PolicyError(f"LLM translation failed: {e}") from e
        if not expr:
            raise PolicyError("LLM returned empty policy")
        # strip common markdown wrappings
        if expr.startswith("```"):
            expr = expr.strip("`").strip()
            if expr.startswith("python\n"):
                expr = expr[len("python\n"):]
        return expr

    def _compile(self, expression: str) -> PolicyRule:
        try:
            tree = ast.parse(expression, mode="eval")
        except SyntaxError as e:
            raise PolicyError(f"invalid policy syntax: {e}") from e
        _validate_ast(tree)
        return PolicyRule(expression=expression, _tree=tree)


def _validate_ast(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise PolicyError(
                f"disallowed policy construct: {type(node).__name__}"
            )
        if isinstance(node, ast.Call):
            raise PolicyError("function calls are not allowed in policies")
        if isinstance(node, ast.Name):
            if node.id.startswith("_"):
                raise PolicyError(f"disallowed name: {node.id}")
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("_"):
                raise PolicyError(f"disallowed attribute: {node.attr}")


def _report_namespace(report: Report) -> SimpleNamespace:
    criticals = sum(1 for f in report.findings if f.severity == Severity.CRITICAL)
    highs = sum(1 for f in report.findings if f.severity == Severity.HIGH)
    categories = SimpleNamespace(**{
        c.category.value: SimpleNamespace(score=c.score, grade=c.grade.value)
        for c in report.categories
    })
    shadow_models = sum(
        1 for f in report.findings
        if f.analyzer == "aibom" and f.severity in (Severity.LOW, Severity.HIGH, Severity.CRITICAL)
    )
    return SimpleNamespace(
        overall_score=report.overall_score,
        overall_grade=report.overall_grade.value,
        criticals=criticals,
        highs=highs,
        findings_count=len(report.findings),
        categories=categories,
        shadow_models=shadow_models,
    )


class _SafeEvaluator:
    def __init__(self, namespace: dict):
        self.namespace = namespace

    def visit(self, node):
        method = getattr(self, f"visit_{type(node).__name__}", None)
        if method is None:
            raise PolicyError(f"unsupported node: {type(node).__name__}")
        return method(node)

    def visit_Constant(self, node: ast.Constant):
        return node.value

    def visit_Name(self, node: ast.Name):
        if node.id not in self.namespace:
            raise PolicyError(f"unknown identifier: {node.id}")
        return self.namespace[node.id]

    def visit_Attribute(self, node: ast.Attribute):
        obj = self.visit(node.value)
        if node.attr.startswith("_"):
            raise PolicyError(f"disallowed attribute: {node.attr}")
        try:
            return getattr(obj, node.attr)
        except AttributeError:
            raise PolicyError(f"unknown field: {node.attr}") from None

    def visit_Subscript(self, node: ast.Subscript):
        obj = self.visit(node.value)
        key = self.visit(node.slice)
        try:
            return obj[key]
        except (KeyError, IndexError, TypeError) as e:
            raise PolicyError(f"subscript failed: {e}") from e

    def visit_Tuple(self, node: ast.Tuple):
        return tuple(self.visit(e) for e in node.elts)

    def visit_List(self, node: ast.List):
        return [self.visit(e) for e in node.elts]

    def visit_UnaryOp(self, node: ast.UnaryOp):
        operand = self.visit(node.operand)
        if isinstance(node.op, ast.Not):
            return not operand
        if isinstance(node.op, ast.USub):
            return -operand
        if isinstance(node.op, ast.UAdd):
            return +operand
        raise PolicyError(f"unsupported unary op: {type(node.op).__name__}")

    def visit_BoolOp(self, node: ast.BoolOp):
        values = [self.visit(v) for v in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        if isinstance(node.op, ast.Or):
            return any(values)
        raise PolicyError(f"unsupported bool op: {type(node.op).__name__}")

    def visit_Compare(self, node: ast.Compare):
        left = self.visit(node.left)
        for op, comparator in zip(node.ops, node.comparators):
            right = self.visit(comparator)
            if not _apply_compare(op, left, right):
                return False
            left = right
        return True


def _apply_compare(op: ast.cmpop, left, right) -> bool:
    if isinstance(op, ast.Eq):
        return left == right
    if isinstance(op, ast.NotEq):
        return left != right
    if isinstance(op, ast.Lt):
        return left < right
    if isinstance(op, ast.LtE):
        return left <= right
    if isinstance(op, ast.Gt):
        return left > right
    if isinstance(op, ast.GtE):
        return left >= right
    if isinstance(op, ast.In):
        return left in right
    if isinstance(op, ast.NotIn):
        return left not in right
    raise PolicyError(f"unsupported comparison: {type(op).__name__}")
