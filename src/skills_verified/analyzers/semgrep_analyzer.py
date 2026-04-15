import json
import logging
import subprocess
from pathlib import Path

from skills_verified.core.analyzer import Analyzer, find_tool
from skills_verified.core.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepAnalyzer(Analyzer):
    name = "semgrep"

    def is_available(self) -> bool:
        return find_tool("semgrep") is not None

    def analyze(self, repo_path: Path) -> list[Finding]:
        try:
            cmd = [
                find_tool("semgrep"), "scan",
                "--config", "p/security-audit",
                "--config", "p/python",
            ]
            ai_rules = RULES_DIR / "ai-skills.yml"
            if ai_rules.is_file():
                cmd.extend(["--config", str(ai_rules)])
            cmd.extend(["--json", "--quiet", str(repo_path)])
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            return self._parse_output(result.stdout, repo_path)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("semgrep execution failed")
            return []

    def _parse_output(self, output: str, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []
        for result in data.get("results", []):
            extra = result.get("extra", {})
            severity_str = extra.get("severity", "WARNING")
            severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
            file_abs = Path(result.get("path", ""))
            try:
                file_rel = str(file_abs.relative_to(repo_path))
            except ValueError:
                file_rel = str(file_abs)
            findings.append(Finding(
                title=f"Semgrep: {result.get('check_id', 'unknown')}",
                description=extra.get("message", ""),
                severity=severity,
                category=Category.CODE_SAFETY,
                file_path=file_rel,
                line_number=result.get("start", {}).get("line"),
                analyzer=self.name,
            ))
        return findings
