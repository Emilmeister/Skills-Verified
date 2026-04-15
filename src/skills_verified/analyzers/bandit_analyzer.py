import json
import logging
import subprocess
from pathlib import Path

from skills_verified.core.analyzer import Analyzer, find_tool
from skills_verified.core.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}



class BanditAnalyzer(Analyzer):
    name = "bandit"

    def is_available(self) -> bool:
        return find_tool("bandit") is not None

    def analyze(self, repo_path: Path) -> list[Finding]:
        try:
            result = subprocess.run(
                [find_tool("bandit"), "-r", str(repo_path), "-f", "json", "-q"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            return self._parse_output(result.stdout, repo_path)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("bandit execution failed")
            return []

    def _parse_output(self, output: str, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []
        for result in data.get("results", []):
            test_id = result.get("test_id", "")
            severity_str = result.get("issue_severity", "MEDIUM")
            severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            # B105: skip empty-string "passwords" — common API payload pattern
            if test_id == "B105":
                issue_text = result.get("issue_text", "")
                if "password: ''" in issue_text or 'password: ""' in issue_text:
                    continue

            file_abs = Path(result.get("filename", ""))
            try:
                file_rel = str(file_abs.relative_to(repo_path))
            except ValueError:
                file_rel = str(file_abs)
            findings.append(Finding(
                title=f"Bandit {test_id}: {result.get('test_name', '')}",
                description=result.get("issue_text", ""),
                severity=severity,
                category=Category.CODE_SAFETY,
                file_path=file_rel,
                line_number=result.get("line_number"),
                analyzer=self.name,
            ))
        return findings
