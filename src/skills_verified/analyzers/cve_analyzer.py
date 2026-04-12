import json
import logging
import shutil
import subprocess
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class CveAnalyzer(Analyzer):
    name = "cve"

    def is_available(self) -> bool:
        return shutil.which("pip-audit") is not None or shutil.which("npm") is not None

    def analyze(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        req_files = (
            list(repo_path.rglob("requirements*.txt"))
            + list(repo_path.rglob("Pipfile"))
            + list(repo_path.rglob("pyproject.toml"))
        )
        if req_files and shutil.which("pip-audit"):
            for req_file in repo_path.rglob("requirements*.txt"):
                findings.extend(self._run_pip_audit(req_file, repo_path))
        if list(repo_path.rglob("package-lock.json")) and shutil.which("npm"):
            for lock_file in repo_path.rglob("package-lock.json"):
                findings.extend(self._run_npm_audit(lock_file.parent, repo_path))
        return findings

    def _run_pip_audit(self, req_file: Path, repo_path: Path) -> list[Finding]:
        try:
            result = subprocess.run(
                ["pip-audit", "-r", str(req_file), "-f", "json", "--desc"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            rel_path = str(req_file.relative_to(repo_path))
            return self._parse_pip_audit(result.stdout, rel_path)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("pip-audit failed for %s", req_file)
            return []

    def _run_npm_audit(self, pkg_dir: Path, repo_path: Path) -> list[Finding]:
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(pkg_dir),
            )
            rel_path = str((pkg_dir / "package.json").relative_to(repo_path))
            return self._parse_npm_audit(result.stdout, rel_path)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("npm audit failed for %s", pkg_dir)
            return []

    def _parse_pip_audit(self, output: str, file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []
        for dep in data:
            pkg_name = dep.get("name", "unknown")
            version = dep.get("version", "unknown")
            for vuln in dep.get("vulns", []):
                cve_id = vuln.get("id", "")
                desc = vuln.get("description", "No description")
                findings.append(Finding(
                    title=f"CVE in {pkg_name}=={version}: {cve_id}",
                    description=desc,
                    severity=Severity.HIGH,
                    category=Category.CVE,
                    file_path=file_path,
                    line_number=None,
                    analyzer=self.name,
                    cve_id=cve_id if cve_id.startswith("CVE-") else None,
                ))
        return findings

    def _parse_npm_audit(self, output: str, file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []
        for pkg_name, vuln_info in data.get("vulnerabilities", {}).items():
            severity_str = vuln_info.get("severity", "medium")
            severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
            via = vuln_info.get("via", [])
            title_detail = ""
            if via and isinstance(via[0], dict):
                title_detail = via[0].get("title", "")
            findings.append(Finding(
                title=f"Vulnerability in {pkg_name}: {title_detail}",
                description=f"Severity: {severity_str}, Range: {vuln_info.get('range', 'unknown')}",
                severity=severity,
                category=Category.CVE,
                file_path=file_path,
                line_number=None,
                analyzer=self.name,
            ))
        return findings
