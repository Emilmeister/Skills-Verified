import re
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity

PERMISSION_PATTERNS = [
    {
        "title": "Destructive file operation — shutil.rmtree",
        "pattern": re.compile(r"\bshutil\.rmtree\s*\("),
        "severity": Severity.HIGH,
        "description": "Recursively deletes directory trees. Dangerous with user-controlled paths.",
    },
    {
        "title": "File deletion — os.remove",
        "pattern": re.compile(r"\bos\.remove\s*\("),
        "severity": Severity.MEDIUM,
        "description": "Deletes files. Verify the path is not user-controlled.",
    },
    {
        "title": "File deletion — os.unlink",
        "pattern": re.compile(r"\bos\.unlink\s*\("),
        "severity": Severity.MEDIUM,
        "description": "Deletes files. Verify the path is not user-controlled.",
    },
    {
        "title": "Directory removal — os.rmdir",
        "pattern": re.compile(r"\bos\.rmdir\s*\("),
        "severity": Severity.MEDIUM,
        "description": "Removes directories.",
    },
    {
        "title": "Process spawning — subprocess.Popen",
        "pattern": re.compile(r"\bsubprocess\.Popen\s*\("),
        "severity": Severity.MEDIUM,
        "description": "Spawns external processes. Review command construction for injection risks.",
    },
    {
        "title": "Process termination — os.kill",
        "pattern": re.compile(r"\bos\.kill\s*\("),
        "severity": Severity.HIGH,
        "description": "Terminates processes by PID. Can cause denial-of-service.",
    },
    {
        "title": "Network access — requests library",
        "pattern": re.compile(r"\brequests\.(get|post|put|delete|patch|head)\s*\("),
        "severity": Severity.LOW,
        "description": "Makes HTTP requests to external services.",
    },
    {
        "title": "Network access — urllib",
        "pattern": re.compile(r"\burllib\.request\.(urlopen|urlretrieve)\s*\("),
        "severity": Severity.LOW,
        "description": "Makes HTTP requests or downloads files.",
    },
    {
        "title": "Network access — httpx",
        "pattern": re.compile(r"\bhttpx\.(get|post|put|delete|patch)\s*\("),
        "severity": Severity.LOW,
        "description": "Makes HTTP requests to external services.",
    },
    {
        "title": "Low-level network access — socket",
        "pattern": re.compile(r"\bsocket\.socket\s*\("),
        "severity": Severity.MEDIUM,
        "description": "Creates raw network sockets. Unusual for typical applications.",
    },
    {
        "title": "Insecure HTTP URL (no TLS)",
        "pattern": re.compile(
            r"""['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[^'"]+['\"]"""
        ),
        "severity": Severity.MEDIUM,
        "description": "Uses plain HTTP instead of HTTPS. All network calls should use TLS 1.2+ to prevent interception.",
    },
]

SCAN_EXTENSIONS = {".py", ".js", ".mjs", ".ts", ".sh", ".bash", ".ps1"}


class PermissionsAnalyzer(Analyzer):
    name = "permissions"

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
            for line_number, line in enumerate(content.splitlines(), start=1):
                for pat in PERMISSION_PATTERNS:
                    if pat["pattern"].search(line):
                        findings.append(Finding(
                            title=pat["title"],
                            description=pat["description"],
                            severity=pat["severity"],
                            category=Category.PERMISSIONS,
                            file_path=rel_path,
                            line_number=line_number,
                            analyzer=self.name,
                        ))
        return findings
