import re
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity

PATTERNS = [
    {
        "title": "Unsafe eval() call",
        "pattern": re.compile(r"\beval\s*\("),
        "severity": Severity.CRITICAL,
        "description": "eval() executes arbitrary code and should not be used with untrusted input.",
    },
    {
        "title": "Unsafe exec() call",
        "pattern": re.compile(r"\bexec\s*\("),
        "severity": Severity.CRITICAL,
        "description": "exec() executes arbitrary code and should not be used with untrusted input.",
    },
    {
        "title": "Unsafe compile() call",
        "pattern": re.compile(r"(?<!\w\.)(?<!re\.)\bcompile\s*\("),
        "severity": Severity.HIGH,
        "description": "compile() can be used to execute arbitrary code.",
    },
    {
        "title": "Subprocess with shell=True",
        "pattern": re.compile(r"shell\s*=\s*True"),
        "severity": Severity.HIGH,
        "description": "shell=True allows shell injection if input is not sanitized.",
    },
    {
        "title": "os.system() usage",
        "pattern": re.compile(r"\bos\.system\s*\("),
        "severity": Severity.HIGH,
        "description": "os.system() executes shell commands and is vulnerable to injection.",
    },
    {
        "title": "os.popen() usage",
        "pattern": re.compile(r"\bos\.popen\s*\("),
        "severity": Severity.HIGH,
        "description": "os.popen() executes shell commands and is vulnerable to injection.",
    },
    {
        "title": "Unsafe pickle.load()",
        "pattern": re.compile(r"\bpickle\.load\s*\("),
        "severity": Severity.HIGH,
        "description": "pickle.load() can execute arbitrary code during deserialization.",
    },
    {
        "title": "Unsafe yaml.load()",
        "pattern": re.compile(r"\byaml\.load\s*\([^)]*\)\s*(?!.*Loader)"),
        "severity": Severity.MEDIUM,
        "description": "yaml.load() without SafeLoader can execute arbitrary code.",
    },
    {
        "title": "Hardcoded secret or API key",
        "pattern": re.compile(
            r"""(?:api[_-]?key|secret|password|token|passwd)\s*=\s*['\"][^'"]{8,}['\"]""",
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "description": "Hardcoded credentials should be stored in environment variables or secret managers.",
    },
]

SCAN_EXTENSIONS = {".py", ".js", ".mjs", ".ts", ".sh", ".bash", ".ps1", ".rb"}


class PatternAnalyzer(Analyzer):
    name = "pattern"

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
            for line_number, line in enumerate(content.splitlines(), start=1):
                for pat in PATTERNS:
                    if pat["pattern"].search(line):
                        findings.append(Finding(
                            title=pat["title"],
                            description=pat["description"],
                            severity=pat["severity"],
                            category=Category.CODE_SAFETY,
                            file_path=str(file_path.relative_to(repo_path)),
                            line_number=line_number,
                            analyzer=self.name,
                        ))
        return findings
