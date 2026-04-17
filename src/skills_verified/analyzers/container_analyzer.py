import json
import logging
import subprocess
from pathlib import Path

from skills_verified.core.analyzer import Analyzer, find_tool
from skills_verified.core.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Negligible": Severity.INFO,
}


class ContainerAnalyzer(Analyzer):
    name = "container"

    def __init__(self, image: str | None = None):
        self.image = image

    def is_available(self) -> bool:
        return find_tool("grype") is not None

    def analyze(self, repo_path: Path) -> list[Finding]:
        if self.image:
            target = self.image
        else:
            target = f"dir:{repo_path}"

        try:
            result = subprocess.run(
                [find_tool("grype"), target, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            return self._parse_output(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("grype execution failed")
            return []

    def _parse_output(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []

        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            vuln_id = vuln.get("id", "unknown")
            severity_str = vuln.get("severity", "Medium")
            severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
            description = vuln.get("description", "")
            pkg_name = artifact.get("name", "unknown")
            pkg_version = artifact.get("version", "unknown")

            locations = artifact.get("locations", [])
            file_path = locations[0].get("path", None) if locations else None

            findings.append(Finding(
                title=f"Container CVE in {pkg_name}=={pkg_version}: {vuln_id}",
                description=description or f"Severity: {severity_str}",
                severity=severity,
                category=Category.CVE,
                file_path=file_path,
                line_number=None,
                analyzer=self.name,
                cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
            ))

        return findings
