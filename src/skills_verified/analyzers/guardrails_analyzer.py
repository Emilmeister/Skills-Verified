import base64
import re
import unicodedata
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

INJECTION_PATTERNS = [
    {
        "title": "Prompt injection — ignore instructions",
        "pattern": re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|guidelines|rules)",
            re.IGNORECASE,
        ),
        "severity": Severity.CRITICAL,
        "description": "Attempts to override LLM system instructions.",
    },
    {
        "title": "Prompt injection — disregard instructions",
        "pattern": re.compile(
            r"disregard\s+(your\s+)?(previous|prior|above)?\s*(instructions|guidelines|rules)",
            re.IGNORECASE,
        ),
        "severity": Severity.CRITICAL,
        "description": "Attempts to override LLM system instructions.",
    },
    {
        "title": "Prompt injection — role override",
        "pattern": re.compile(
            r"you\s+are\s+now\b.{0,60}\b(?:DAN|developer\s+mode|jailbroken|"
            r"unrestricted|without\s+restrictions|system\s+administrator)\b",
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "description": "Attempts to reassign the LLM's role.",
    },
    {
        "title": "Jailbreak — developer mode",
        "pattern": re.compile(
            r"(?:\byou\s+are\s+now\b.{0,40}\bdeveloper\s+mode\b|"
            r"\bdeveloper\s+mode\b.{0,80}"
            r"\b(?:ignore|bypass|disable)\b.{0,40}\b(?:safety|rules|restrictions)\b)",
            re.IGNORECASE,
        ),
        "severity": Severity.CRITICAL,
        "description": "Developer mode jailbreak attempt.",
    },
    {
        "title": "Jailbreak — DAN pattern",
        "pattern": re.compile(r"\bDAN\b.*\b(do\s+anything|jailbreak)\b", re.IGNORECASE),
        "severity": Severity.CRITICAL,
        "description": "DAN (Do Anything Now) jailbreak pattern.",
    },
    {
        "title": "Jailbreak — STAN pattern",
        "pattern": re.compile(r"\bSTAN\b.*\b(strive|do\s+anything)\b", re.IGNORECASE),
        "severity": Severity.CRITICAL,
        "description": "STAN jailbreak pattern.",
    },
    {
        "title": "Prompt injection — safety bypass",
        "pattern": re.compile(
            r"ignore\s+(all\s+)?safety\s+(guidelines|restrictions|rules|filters)",
            re.IGNORECASE,
        ),
        "severity": Severity.CRITICAL,
        "description": "Attempts to bypass LLM safety filters.",
    },
    {
        "title": "Prompt injection — system prompt extraction",
        "pattern": re.compile(
            r"(output|show|display|print|reveal)\s+(all\s+)?"
            r"(?:(?:your|the)\s+system\s+prompt|your\s+(?:instructions|rules))",
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "description": "Attempts to extract LLM system prompt.",
    },
    {
        "rule_id": "SV-GUARD-HIDDEN-EXECUTION",
        "title": "Hidden execution directive",
        "pattern": re.compile(
            r"\b(?:silently|quietly|invisibly)\s+"
            r"(?:run|execute|invoke|launch)\b",
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "description": (
            "Instructs the agent to execute an action without making it visible to the user."
        ),
        "remediation": (
            "Remove covert execution instructions and require explicit user-visible consent."
        ),
    },
    {
        "rule_id": "SV-GUARD-DEFERRED-EXECUTION",
        "title": "Deferred hidden execution directive",
        "pattern": re.compile(
            r"\b(?:in\s+(?:a\s+)?future\s+session|"
            r"(?:on|during)\s+(?:the\s+)?next\s+(?:session|run)|"
            r"when\s+the\s+user\b)[\s\S]{0,240}?"
            r"\b(?:silently|quietly|invisibly)\s+"
            r"(?:run|execute|invoke|launch)\b",
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "description": (
            "Defers a hidden action until a later session or user-controlled trigger."
        ),
        "remediation": (
            "Remove deferred hidden triggers and require an explicit action at execution time."
        ),
    },
    {
        "rule_id": "SV-GUARD-REMOTE-INSTALL",
        "title": "Remote installer copied into a terminal",
        "pattern": re.compile(
            r"(?:\bcopy\b[^\n]{0,120}\b(?:installation\s+)?script\b"
            r"[^\n]{0,120}\bpaste\b[^\n]{0,60}\b(?:terminal|shell)\b|"
            r"\bdownload\b[^\n]{0,160}\.(?:zip|exe|dmg|pkg)\b"
            r"[^\n]{0,160}\b(?:run|execute|launch)\b)",
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "description": (
            "Directs the user or agent to execute an unverified remote installer."
        ),
        "remediation": (
            "Use a trusted package source with a pinned version and verified signature or digest."
        ),
    },
]

HIDDEN_UNICODE_CHARS = {
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
}

SCAN_EXTENSIONS = {
    ".md",
    ".txt",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".py",
    ".js",
    ".ts",
}

_DEFENSIVE_CONTEXT = re.compile(
    r"(?:\b(?:classify|mark|treat)\b.{0,160}\b(?:unsafe|untrusted)\b|"
    r"\b(?:avoid|block|detect|do not|don't|never|reject)\b.{0,100}"
    r"\b(?:apply|execute|follow|obey|run|use)\b)",
    re.IGNORECASE,
)
_EXAMPLE_PATH_PARTS = {"fixture", "fixtures", "test", "tests"}
_SECURITY_DOC_PATH = re.compile(
    r"(?:guardrail|safety|scanner|security|threat|prompt.?injection|jailbreak)", re.I
)
_SECURITY_EXAMPLE_CONTEXT = re.compile(
    r"\b(?:attack|critical|detect|example|injection|malicious|override|pattern|"
    r"payload|risk|signature|test|untrusted)\b",
    re.IGNORECASE,
)


def _quoted_defensive_example(content: str, match: re.Match) -> bool:
    lines = content.splitlines()
    index = content.count("\n", 0, match.start())
    line_start = content.rfind("\n", 0, match.start()) + 1
    line_end = content.find("\n", match.end())
    if line_end == -1:
        line_end = len(content)
    before = content[line_start : match.start()]
    after = content[match.end() : line_end]
    if not any(
        before.count(quote) % 2 == 1 and after.count(quote) % 2 == 1
        for quote in ("`", '"', "'")
    ):
        return False
    context = " ".join(lines[max(0, index - 2) : index + 1])
    return bool(_DEFENSIVE_CONTEXT.search(context))


def _documented_or_test_example(content: str, match: re.Match, rel_path: str) -> bool:
    path = Path(rel_path)
    if _EXAMPLE_PATH_PARTS & {part.casefold() for part in path.parts}:
        return True
    if not _SECURITY_DOC_PATH.search(rel_path):
        return False
    if path.name.casefold() != "skill.md":
        return True
    line_start = content.rfind("\n", 0, match.start()) + 1
    line_end = content.find("\n", match.end())
    if line_end == -1:
        line_end = len(content)
    before = content[line_start : match.start()]
    after = content[match.end() : line_end]
    if any(
        before.count(quote) % 2 == 1 and after.count(quote) % 2 == 1
        for quote in ("`", '"', "'")
    ):
        return True
    window = content[max(0, match.start() - 240) : match.end() + 240]
    return bool(_SECURITY_EXAMPLE_CONTEXT.search(window))


def _is_emoji_joiner(line: str, index: int) -> bool:
    def neighbor(position: int, step: int) -> str | None:
        while 0 <= position < len(line):
            if line[position] not in {"\ufe0e", "\ufe0f"}:
                return line[position]
            position += step
        return None

    before = neighbor(index - 1, -1)
    after = neighbor(index + 1, 1)
    return bool(
        before
        and after
        and unicodedata.category(before) in {"So", "Sk"}
        and unicodedata.category(after) in {"So", "Sk"}
    )


def _negated_or_descriptive_execution(content: str, match: re.Match) -> bool:
    line_start = content.rfind("\n", 0, match.start()) + 1
    prefix = content[line_start : match.start()]
    return bool(
        re.search(
            r"\b(?:can|could|did\s+not|do\s+not|does\s+not|either|may|might|"
            r"must\s+not|never|not|would)\s+$",
            prefix,
            re.IGNORECASE,
        )
    )


def _suspicious_hidden_chars(line: str) -> list[str]:
    bidi_controls = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
    sanitized = "".join(char for char in line if char not in HIDDEN_UNICODE_CHARS)
    injection_after_removal = any(
        pattern["pattern"].search(sanitized) for pattern in INJECTION_PATTERNS
    )
    suspicious: list[str] = []
    for index, char in enumerate(line):
        if char not in HIDDEN_UNICODE_CHARS:
            continue
        if char in bidi_controls:
            suspicious.append(char)
            continue
        if char == "\u200d" and _is_emoji_joiner(line, index):
            continue
        before = line[index - 1] if index else ""
        after = line[index + 1] if index + 1 < len(line) else ""
        splits_ascii_word = (
            before.isascii()
            and after.isascii()
            and (before.isalnum() and after.isalnum())
        )
        if splits_ascii_word or injection_after_removal:
            suspicious.append(char)
    return suspicious


class GuardrailsAnalyzer(Analyzer):
    name = "guardrails"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []

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
            findings.extend(self._check_patterns(content, rel_path))
            findings.extend(self._check_unicode(content, rel_path))
            findings.extend(self._check_base64(content, rel_path))
        return findings

    def _check_patterns(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for pat in INJECTION_PATTERNS:
            for match in pat["pattern"].finditer(content):
                if _quoted_defensive_example(
                    content, match
                ) or _documented_or_test_example(content, match, rel_path):
                    continue
                if pat.get(
                    "rule_id"
                ) == "SV-GUARD-HIDDEN-EXECUTION" and _negated_or_descriptive_execution(
                    content, match
                ):
                    continue
                line_number = content.count("\n", 0, match.start()) + 1
                snippet = lines[line_number - 1].strip() if lines else ""
                findings.append(
                    Finding(
                        title=pat["title"],
                        description=pat["description"],
                        severity=pat["severity"],
                        category=Category.GUARDRAILS,
                        file_path=rel_path,
                        line_number=line_number,
                        analyzer=self.name,
                        rule_id=pat.get("rule_id"),
                        evidence=Evidence(kind="instruction", snippet=snippet[:500]),
                        remediation=pat.get("remediation"),
                    )
                )
        return findings

    def _check_unicode(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        if (
            _SECURITY_DOC_PATH.search(rel_path)
            and Path(rel_path).name.casefold() != "skill.md"
        ):
            return findings
        for line_number, line in enumerate(content.splitlines(), start=1):
            found_chars = _suspicious_hidden_chars(line)
            visible_line = "".join(
                char for char in line if char not in HIDDEN_UNICODE_CHARS
            ).strip()
            if re.fullmatch(r"(?:```|~~~)[\w+-]*", visible_line):
                continue
            if found_chars:
                findings.append(
                    Finding(
                        title="Hidden unicode characters detected",
                        description=f"Found {len(found_chars)} hidden unicode character(s) that may be used for prompt injection.",
                        severity=Severity.HIGH,
                        category=Category.GUARDRAILS,
                        file_path=rel_path,
                        line_number=line_number,
                        analyzer=self.name,
                    )
                )
        return findings

    def _check_base64(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        if _SECURITY_DOC_PATH.search(rel_path):
            return findings
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
        for line_number, line in enumerate(content.splitlines(), start=1):
            for match in b64_pattern.finditer(line):
                try:
                    decoded = base64.b64decode(match.group(), validate=True).decode(
                        "utf-8"
                    )
                    printable = sum(
                        char.isprintable() or char in "\r\n\t" for char in decoded
                    )
                    if not decoded or printable / len(decoded) < 0.9:
                        continue
                    suspicious_words = [
                        "ignore",
                        "system",
                        "prompt",
                        "instruction",
                        "override",
                        "jailbreak",
                    ]
                    if any(w in decoded.lower() for w in suspicious_words):
                        findings.append(
                            Finding(
                                title="Suspicious base64-encoded content",
                                description=f"Base64 string decodes to suspicious content: {decoded[:100]}",
                                severity=Severity.HIGH,
                                category=Category.GUARDRAILS,
                                file_path=rel_path,
                                line_number=line_number,
                                analyzer=self.name,
                            )
                        )
                except Exception:
                    pass
        return findings
