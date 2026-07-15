import io
import re
import shlex
import tokenize
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

PATTERNS = [
    {
        "title": "Unsafe eval() call",
        "pattern": re.compile(r"(?<![.\w])eval\s*\("),
        "severity": Severity.CRITICAL,
        "description": "eval() executes arbitrary code and should not be used with untrusted input.",
        "extensions": {".js", ".mjs", ".py", ".rb", ".ts"},
    },
    {
        "title": "Unsafe exec() call",
        "pattern": re.compile(r"(?<![.\w])exec\s*\("),
        "severity": Severity.CRITICAL,
        "description": "exec() executes arbitrary code and should not be used with untrusted input.",
        "extensions": {".py", ".rb"},
    },
    {
        "title": "Unsafe compile() call",
        "pattern": re.compile(r"(?<![.\w])(?<!def )compile\s*\("),
        "severity": Severity.HIGH,
        "description": "compile() can be used to execute arbitrary code.",
        "extensions": {".py"},
    },
    {
        "title": "Subprocess with shell=True",
        "pattern": re.compile(r"shell\s*=\s*True"),
        "severity": Severity.HIGH,
        "description": "shell=True allows shell injection if input is not sanitized.",
        "extensions": {".py"},
    },
    {
        "title": "os.system() usage",
        "pattern": re.compile(r"\bos\.system\s*\("),
        "severity": Severity.HIGH,
        "description": "os.system() executes shell commands and is vulnerable to injection.",
        "extensions": {".py"},
    },
    {
        "title": "os.popen() usage",
        "pattern": re.compile(r"\bos\.popen\s*\("),
        "severity": Severity.HIGH,
        "description": "os.popen() executes shell commands and is vulnerable to injection.",
        "extensions": {".py"},
    },
    {
        "title": "Unsafe pickle.load()",
        "pattern": re.compile(r"\bpickle\.load\s*\("),
        "severity": Severity.HIGH,
        "description": "pickle.load() can execute arbitrary code during deserialization.",
        "extensions": {".py"},
    },
    {
        "title": "Unsafe yaml.load()",
        "pattern": re.compile(r"\byaml\.load\s*\([^)]*\)\s*(?!.*Loader)"),
        "severity": Severity.MEDIUM,
        "description": "yaml.load() without SafeLoader can execute arbitrary code.",
        "extensions": {".py"},
    },
    {
        "title": "Hardcoded secret or API key",
        "pattern": re.compile(
            r"""(?P<secret_name>[A-Za-z0-9_-]*(?:api[_-]?key|secret|password|token|passwd))\s*=\s*['\"](?P<secret_value>[^'"]{8,})['\"]""",
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "description": "Hardcoded credentials should be stored in environment variables or secret managers.",
    },
    {
        "rule_id": "SV-CODE-DOWNLOAD-EXECUTE",
        "title": "Remote download piped directly to a shell",
        "pattern": re.compile(
            r"(?:\b(?:curl|wget)\b[^|\n]{0,500}\|\s*"
            r"(?:/usr/bin/env\s+)?(?:ba|da|z|k)?sh\b|"
            r"\b(?:ba|da|z|k)?sh\s+-c\s+['\"]?\$\(\s*(?:curl|wget)\b)",
            re.IGNORECASE,
        ),
        "severity": Severity.CRITICAL,
        "description": (
            "Remote content is executed by a shell without an integrity or review step."
        ),
        "remediation": (
            "Download the artifact separately, verify its pinned digest or signature, "
            "inspect it, and execute it only in an isolated environment."
        ),
        "scan_in_docs": True,
        "extensions": {
            ".bash",
            ".json",
            ".md",
            ".ps1",
            ".sh",
            ".toml",
            ".txt",
            ".yaml",
            ".yml",
        },
    },
    {
        "rule_id": "SV-CODE-SHELL-EVAL",
        "title": "Shell eval of variable-controlled command",
        "pattern": re.compile(
            r"^\s*eval\s+[^#\n]*\$(?:\{?[A-Za-z_][A-Za-z0-9_]*\}?|[@*])",
            re.IGNORECASE,
        ),
        "severity": Severity.CRITICAL,
        "description": (
            "Shell eval executes text supplied through a variable and permits command injection."
        ),
        "remediation": (
            "Replace eval with a fixed command and pass validated values as quoted arguments."
        ),
        "extensions": {".bash", ".sh"},
    },
]

CODE_SCAN_EXTENSIONS = {
    ".bash",
    ".js",
    ".mjs",
    ".ps1",
    ".py",
    ".rb",
    ".sh",
    ".ts",
}
SCAN_EXTENSIONS = CODE_SCAN_EXTENSIONS | {
    ".json",
    ".md",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

_DEFENSIVE_CONTEXT = re.compile(
    r"(?:\b(?:classify|mark|treat)\b.{0,160}\b(?:unsafe|untrusted)\b|"
    r"\b(?:avoid|block|detect|do not|don't|never|reject)\b.{0,100}"
    r"\b(?:apply|execute|follow|obey|run|use)\b|"
    r"\b(?:not\s+(?:yet\s+)?authorized|review\s+before|security\s+policy|"
    r"such\s+as)\b)",
    re.IGNORECASE,
)


def _python_code_lines(content: str) -> list[str]:
    """Mask Python comments and string contents while preserving line positions."""
    lines = content.splitlines()
    masked = [list(line) for line in lines]
    try:
        tokens = tokenize.generate_tokens(io.StringIO(content).readline)
        for token in tokens:
            if token.type not in {tokenize.COMMENT, tokenize.STRING}:
                continue
            start_row, start_column = token.start
            end_row, end_column = token.end
            for row in range(start_row, end_row + 1):
                if not 1 <= row <= len(masked):
                    continue
                start = start_column if row == start_row else 0
                end = end_column if row == end_row else len(masked[row - 1])
                for column in range(start, min(end, len(masked[row - 1]))):
                    if token.type == tokenize.COMMENT or masked[row - 1][
                        column
                    ] not in {
                        "'",
                        '"',
                    }:
                        masked[row - 1][column] = " "
    except (IndentationError, tokenize.TokenError):
        return lines
    return ["".join(line) for line in masked]


def _quoted_defensive_example(lines: list[str], index: int, match: re.Match) -> bool:
    line = lines[index]
    before, after = line[: match.start()], line[match.end() :]
    quoted = before.count("`") % 2 == 1 and after.count("`") % 2 == 1
    if not quoted:
        return False
    context = " ".join(lines[max(0, index - 2) : index + 4])
    return bool(_DEFENSIVE_CONTEXT.search(context))


def _security_reference_example(rel_path: str) -> bool:
    path = Path(rel_path)
    return path.name.casefold() != "skill.md" and bool(
        re.search(r"(?:security|threat|vulnerab|prompt.?injection)", rel_path, re.I)
    )


def _known_non_secret_assignment(match: re.Match) -> bool:
    name = match.group("secret_name").casefold()
    value = match.group("secret_value").strip()
    normalized = value.casefold()
    if "$" in value or normalized.startswith(("replace", "example", "dummy")):
        return True
    if normalized.startswith("phc_"):
        return True
    return (
        "token" in name
        and any(marker in name for marker in ("renderer", "type", "kind", "label"))
        and value.isalpha()
    )


def _shell_pipeline_is_executable(line: str) -> bool:
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars="|")
        lexer.whitespace_split = True
        return "|" in lexer
    except ValueError:
        return False


_SHELL_ASSIGNMENT = re.compile(
    r"^\s*(?:local\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)$"
)
_SHELL_VARIABLE = re.compile(
    r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)[^}]*\}|"
    r"(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)
_SHELL_POSITIONAL = re.compile(r"\$(?:[1-9@*]|\{[1-9][^}]*\})")
_PREDICTABLE_TEMP = re.compile(
    r"^[\"']?(?:/tmp/|\$\{TMPDIR:-/tmp\}/|\$TMPDIR/)", re.IGNORECASE
)

_SHELL_FLOW_RULES = {
    "archive": {
        "rule_id": "SV-CODE-SHELL-ARCHIVE-TRAVERSAL",
        "title": "Untrusted archive extracted without path validation",
        "description": (
            "An archive supplied through a shell input is extracted without validating "
            "member paths, allowing writes outside the destination."
        ),
        "severity": Severity.HIGH,
        "remediation": (
            "Reject absolute and parent-directory member paths before extraction, or use "
            "an archive API that enforces destination confinement."
        ),
    },
    "source": {
        "rule_id": "SV-CODE-SHELL-SOURCE-UNTRUSTED",
        "title": "Shell sources a caller-controlled file",
        "description": (
            "A path derived from a caller-controlled argument is sourced as shell code."
        ),
        "severity": Severity.CRITICAL,
        "remediation": "Parse untrusted configuration as data instead of sourcing it.",
    },
    "temporary": {
        "rule_id": "SV-CODE-SHELL-PREDICTABLE-TEMP",
        "title": "Predictable temporary file is written",
        "description": (
            "A predictable path in a shared temporary directory is opened for writing, "
            "which permits symlink-based file overwrite attacks."
        ),
        "severity": Severity.HIGH,
        "remediation": "Create the file atomically with mktemp and restrictive permissions.",
    },
}


def _shell_variables(text: str) -> set[str]:
    return {
        match.group("braced") or match.group("plain")
        for match in _SHELL_VARIABLE.finditer(text)
    }


def _shell_tokens(line: str) -> list[str]:
    try:
        return shlex.split(line, comments=True, posix=True)
    except ValueError:
        return []


def _tar_extracted_archive(tokens: list[str]) -> str | None:
    if not tokens or tokens[0] != "tar":
        return None
    extracting = False
    archive: str | None = None
    for index, token in enumerate(tokens[1:], start=1):
        if token == "--extract":
            extracting = True
            continue
        if token.startswith("--file="):
            archive = token.partition("=")[2]
            continue
        if token in {"--file", "-f"}:
            archive = tokens[index + 1] if index + 1 < len(tokens) else None
            continue
        if not token.startswith("-") and index != 1:
            continue
        flags = token.lstrip("-")
        extracting = extracting or "x" in flags
        if "f" in flags:
            attached = flags.partition("f")[2]
            archive = attached or (
                tokens[index + 1] if index + 1 < len(tokens) else None
            )
    return archive if extracting else None


def _shell_flow_finding(
    rule: str,
    rel_path: str,
    line_number: int,
    line: str,
) -> Finding:
    definition = _SHELL_FLOW_RULES[rule]
    return Finding(
        title=definition["title"],
        description=definition["description"],
        severity=definition["severity"],
        category=Category.CODE_SAFETY,
        file_path=rel_path,
        line_number=line_number,
        analyzer="pattern",
        rule_id=definition["rule_id"],
        evidence=Evidence(kind="source", snippet=line.strip()[:500]),
        remediation=definition["remediation"],
    )


def _shell_flow_findings(lines: list[str], rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    tainted: set[str] = set()
    predictable_temps: set[str] = set()

    for line_number, line in enumerate(lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        assignment = _SHELL_ASSIGNMENT.match(line)
        if assignment:
            name = assignment.group("name")
            value = assignment.group("value")
            references = _shell_variables(value)
            if _SHELL_POSITIONAL.search(value) or any(
                reference in tainted for reference in references
            ):
                tainted.add(name)
            else:
                tainted.discard(name)
            if _PREDICTABLE_TEMP.match(value.strip()):
                predictable_temps.add(name)
            else:
                predictable_temps.discard(name)

        tokens = _shell_tokens(line)
        references = _shell_variables(line)
        archive = _tar_extracted_archive(tokens)
        if archive is not None and _shell_variables(archive) & tainted:
            findings.append(_shell_flow_finding("archive", rel_path, line_number, line))

        if (
            len(tokens) == 2
            and tokens[0] in {".", "source"}
            and _shell_variables(tokens[1]) & tainted
        ):
            findings.append(_shell_flow_finding("source", rel_path, line_number, line))

        for variable in predictable_temps:
            if re.search(
                rf">{{1,2}}\s*[\"']?\$\{{?{re.escape(variable)}\}}?",
                line,
            ):
                findings.append(
                    _shell_flow_finding("temporary", rel_path, line_number, line)
                )
                break

    return findings


class PatternAnalyzer(Analyzer):
    name = "pattern"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        self.diagnostics = []
        findings: list[Finding] = []
        for file_path in iter_analysis_files(repo_path, kwargs.get("context")):
            dialect = detect_shell_dialect(file_path)
            if file_path.suffix not in SCAN_EXTENSIONS and dialect is None:
                continue
            effective_suffix = file_path.suffix or (
                ".bash" if dialect == "bash" else ".sh"
            )
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
            lines = content.splitlines()
            if file_path.suffix == ".py":
                scan_lines = _python_code_lines(content)
            elif effective_suffix in {".bash", ".sh"}:
                scan_lines = [
                    "" if line.lstrip().startswith("#") else line for line in lines
                ]
            else:
                scan_lines = lines
            for line_number, (line, scan_line) in enumerate(
                zip(lines, scan_lines, strict=True), start=1
            ):
                for pat in PATTERNS:
                    if effective_suffix not in pat.get("extensions", SCAN_EXTENSIONS):
                        continue
                    if effective_suffix not in CODE_SCAN_EXTENSIONS and not pat.get(
                        "scan_in_docs", False
                    ):
                        continue
                    match = pat["pattern"].search(scan_line)
                    if match and pat.get("scan_in_docs", False):
                        if _security_reference_example(rel_path):
                            continue
                        if _quoted_defensive_example(lines, line_number - 1, match):
                            continue
                        if effective_suffix in {".bash", ".sh"} and not (
                            _shell_pipeline_is_executable(scan_line)
                        ):
                            continue
                    if (
                        match
                        and pat["title"] == "Hardcoded secret or API key"
                        and _known_non_secret_assignment(match)
                    ):
                        continue
                    if match:
                        findings.append(
                            Finding(
                                title=pat["title"],
                                description=pat["description"],
                                severity=pat["severity"],
                                category=Category.CODE_SAFETY,
                                file_path=rel_path,
                                line_number=line_number,
                                analyzer=self.name,
                                rule_id=pat.get("rule_id"),
                                evidence=Evidence(
                                    kind="source", snippet=line.strip()[:500]
                                ),
                                remediation=pat.get("remediation"),
                            )
                        )
            if effective_suffix in {".bash", ".sh"}:
                findings.extend(_shell_flow_findings(lines, rel_path))
        return findings
