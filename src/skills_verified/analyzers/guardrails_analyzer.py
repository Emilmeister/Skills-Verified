import base64
import re
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity

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
            r"you\s+are\s+now\s+(in\s+)?(a\s+)?",
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "description": "Attempts to reassign the LLM's role.",
    },
    {
        "title": "Jailbreak — developer mode",
        "pattern": re.compile(r"\bdeveloper\s+mode\b", re.IGNORECASE),
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
            r"(output|show|display|print|reveal)\s+(all\s+)?(your\s+)?(system\s+prompt|instructions|rules)",
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "description": "Attempts to extract LLM system prompt.",
    },
]

HIDDEN_UNICODE_CHARS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",
}

SCAN_EXTENSIONS = {".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".py", ".js", ".ts"}


class GuardrailsAnalyzer(Analyzer):
    name = "guardrails"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in repo_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix not in SCAN_EXTENSIONS:
                continue
            try:
                content = file_path.read_text(errors="ignore")
            except OSError:
                continue
            rel_path = str(file_path.relative_to(repo_path))
            findings.extend(self._check_patterns(content, rel_path))
            findings.extend(self._check_unicode(content, rel_path))
            findings.extend(self._check_base64(content, rel_path))
        return findings

    def _check_patterns(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            for pat in INJECTION_PATTERNS:
                if pat["pattern"].search(line):
                    findings.append(Finding(
                        title=pat["title"],
                        description=pat["description"],
                        severity=pat["severity"],
                        category=Category.GUARDRAILS,
                        file_path=rel_path,
                        line_number=line_number,
                        analyzer=self.name,
                    ))
        return findings

    def _check_unicode(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            found_chars = [c for c in line if c in HIDDEN_UNICODE_CHARS]
            if found_chars:
                findings.append(Finding(
                    title="Hidden unicode characters detected",
                    description=f"Found {len(found_chars)} hidden unicode character(s) that may be used for prompt injection.",
                    severity=Severity.HIGH,
                    category=Category.GUARDRAILS,
                    file_path=rel_path,
                    line_number=line_number,
                    analyzer=self.name,
                ))
        return findings

    def _check_base64(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
        for line_number, line in enumerate(content.splitlines(), start=1):
            for match in b64_pattern.finditer(line):
                try:
                    decoded = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
                    suspicious_words = ["ignore", "system", "prompt", "instruction", "override", "jailbreak"]
                    if any(w in decoded.lower() for w in suspicious_words):
                        findings.append(Finding(
                            title="Suspicious base64-encoded content",
                            description=f"Base64 string decodes to suspicious content: {decoded[:100]}",
                            severity=Severity.HIGH,
                            category=Category.GUARDRAILS,
                            file_path=rel_path,
                            line_number=line_number,
                            analyzer=self.name,
                        ))
                except Exception:
                    pass
        return findings
