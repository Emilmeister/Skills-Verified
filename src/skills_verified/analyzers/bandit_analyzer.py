import json
import re
import subprocess
import tempfile
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.context import analysis_roots
from skills_verified.core.models import Category, Diagnostic, Finding, Severity
from skills_verified.analyzers.external_tool import find_executable

SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}
CONFIDENCE_MAP = {
    "HIGH": 0.9,
    "MEDIUM": 0.7,
    "LOW": 0.4,
    "UNDEFINED": 0.5,
}

NON_ACTIONABLE_TEST_IDS = {
    "B101",  # assertions are not a vulnerability without runtime context
    "B105",
    "B110",
    "B112",
    "B403",  # import-only advisories duplicate actionable pickle use rules
    "B404",
    "B405",  # import-only advisories duplicate unsafe XML parsing rules
    "B408",
    "B603",
    "B606",
    "B607",
}
SECURITY_RANDOM_CONTEXT = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:api.?key|credential|csrf|nonce|password|secret|session|token)(?:$|[^A-Za-z0-9])",
    re.IGNORECASE,
)


class BanditAnalyzer(Analyzer):
    name = "bandit"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []
        try:
            self.version = version("bandit")
        except PackageNotFoundError:
            self.version = None

    def is_available(self) -> bool:
        return find_executable("bandit") is not None

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        self.diagnostics = []
        targets = [
            str(path) for path in analysis_roots(repo_path, kwargs.get("context"))
        ]
        with tempfile.TemporaryDirectory(prefix="sv-bandit-") as neutral_cwd:
            trusted_config = Path(neutral_cwd) / "bandit.ini"
            trusted_config.write_text("[bandit]\n", encoding="utf-8")
            executable = find_executable("bandit")
            if executable is None:
                raise RuntimeError("bandit executable disappeared")
            try:
                result = subprocess.run(
                    [
                        executable,
                        "-r",
                        *targets,
                        "-f",
                        "json",
                        "-q",
                        "--ignore-nosec",
                        "--confidence-level",
                        "medium",
                        "--ini",
                        str(trusted_config),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd=neutral_cwd,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("bandit timed out") from exc
            except FileNotFoundError as exc:
                raise RuntimeError("bandit executable disappeared") from exc
        if result.returncode not in {0, 1}:
            raise RuntimeError(f"bandit exited with status {result.returncode}")
        return self._parse_output(result.stdout, repo_path)

    def _parse_output(self, output: str, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError as exc:
            raise ValueError("bandit did not return valid JSON") from exc
        for error in data.get("errors", []):
            self.diagnostics.append(
                Diagnostic(
                    code="bandit_analysis_error",
                    message=str(error),
                    analyzer=self.name,
                )
            )
        for result in data.get("results", []):
            severity_str = str(result.get("issue_severity", "MEDIUM")).upper()
            severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
            confidence_str = str(result.get("issue_confidence", "UNDEFINED")).upper()
            test_id = str(result.get("test_id", "UNKNOWN")).upper()
            if confidence_str == "LOW" or not self._is_actionable(result, test_id):
                continue
            confidence = CONFIDENCE_MAP.get(
                confidence_str,
                0.5,
            )
            file_abs = Path(result.get("filename", ""))
            try:
                file_rel = str(file_abs.relative_to(repo_path))
            except ValueError:
                file_rel = str(file_abs)
            line_number = result.get("line_number")
            line_range = result.get("line_range")
            end_line = (
                max(line for line in line_range if isinstance(line, int))
                if isinstance(line_range, list)
                and any(isinstance(line, int) for line in line_range)
                else line_number
            )
            findings.append(
                Finding(
                    title=f"Bandit {test_id}: {result.get('test_name', '')}",
                    description=result.get("issue_text", ""),
                    severity=severity,
                    category=Category.CODE_SAFETY,
                    file_path=file_rel,
                    line_number=line_number,
                    end_line=end_line,
                    analyzer=self.name,
                    confidence=confidence,
                    rule_id=f"SV-BANDIT-{test_id.upper()}",
                    remediation=(
                        f"Review and remediate the code according to Bandit rule {test_id}."
                    ),
                )
            )
        return findings

    @staticmethod
    def _is_actionable(result: dict, test_id: str) -> bool:
        if test_id in NON_ACTIONABLE_TEST_IDS:
            return False
        if test_id == "B311":
            return bool(SECURITY_RANDOM_CONTEXT.search(str(result.get("code", ""))))
        return True
