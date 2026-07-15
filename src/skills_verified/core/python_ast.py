import ast
import warnings


def parse_python(source: str) -> ast.Module:
    """Parse untrusted Python without leaking its syntax warnings to scanner stderr."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(source)
