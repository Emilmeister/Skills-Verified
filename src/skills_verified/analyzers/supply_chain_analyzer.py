import json
import re
from pathlib import Path

from Levenshtein import distance as levenshtein_distance

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity

POPULAR_PACKAGES_PY = [
    "requests", "flask", "django", "numpy", "pandas", "scipy",
    "tensorflow", "torch", "pillow", "cryptography", "paramiko",
    "boto3", "celery", "redis", "psycopg2", "sqlalchemy",
    "pyyaml", "jinja2", "matplotlib", "scikit-learn",
]

POPULAR_PACKAGES_NPM = [
    "express", "react", "lodash", "axios", "moment", "webpack",
    "typescript", "next", "vue", "angular", "socket.io",
    "mongoose", "sequelize", "passport", "jsonwebtoken",
    "dotenv", "cors", "helmet", "morgan", "chalk",
    "requests",
]

SUSPICIOUS_SCRIPTS = {"preinstall", "postinstall", "preuninstall", "postuninstall"}


class SupplyChainAnalyzer(Analyzer):
    name = "supply_chain"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_package_json(repo_path))
        findings.extend(self._check_setup_py(repo_path))
        findings.extend(self._check_requirements_txt(repo_path))
        return findings

    def _check_package_json(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for pkg_file in repo_path.rglob("package.json"):
            try:
                data = json.loads(pkg_file.read_text(errors="ignore"))
            except (json.JSONDecodeError, OSError):
                continue
            rel_path = str(pkg_file.relative_to(repo_path))
            scripts = data.get("scripts", {})
            for script_name in SUSPICIOUS_SCRIPTS:
                if script_name in scripts:
                    cmd = scripts[script_name]
                    if self._is_suspicious_command(cmd):
                        findings.append(Finding(
                            title=f"Suspicious {script_name} install script",
                            description=f"Install script runs: {cmd}",
                            severity=Severity.CRITICAL,
                            category=Category.SUPPLY_CHAIN,
                            file_path=rel_path,
                            line_number=None,
                            analyzer=self.name,
                        ))
            all_deps = {}
            all_deps.update(data.get("dependencies", {}))
            all_deps.update(data.get("devDependencies", {}))
            for dep_name in all_deps:
                findings.extend(
                    self._check_typosquat(dep_name, POPULAR_PACKAGES_NPM, rel_path)
                )
        return findings

    def _check_setup_py(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for setup_file in repo_path.rglob("setup.py"):
            try:
                content = setup_file.read_text(errors="ignore")
            except OSError:
                continue
            rel_path = str(setup_file.relative_to(repo_path))
            dangerous_patterns = [
                re.compile(r"\bos\.system\s*\("),
                re.compile(r"\bsubprocess\.(run|call|Popen)\s*\("),
                re.compile(r"\bexec\s*\("),
            ]
            for line_number, line in enumerate(content.splitlines(), start=1):
                for pat in dangerous_patterns:
                    if pat.search(line):
                        findings.append(Finding(
                            title="Dangerous code execution in setup.py",
                            description=f"setup.py contains executable code at install time: {line.strip()}",
                            severity=Severity.CRITICAL,
                            category=Category.SUPPLY_CHAIN,
                            file_path=rel_path,
                            line_number=line_number,
                            analyzer=self.name,
                        ))
        return findings

    def _check_requirements_txt(self, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for req_file in repo_path.rglob("requirements*.txt"):
            try:
                content = req_file.read_text(errors="ignore")
            except OSError:
                continue
            rel_path = str(req_file.relative_to(repo_path))
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pkg_name = re.split(r"[=<>!~\[]", line)[0].strip()
                if pkg_name:
                    findings.extend(
                        self._check_typosquat(pkg_name, POPULAR_PACKAGES_PY, rel_path)
                    )
        return findings

    def _check_typosquat(
        self, name: str, known_packages: list[str], file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        name_lower = name.lower()
        for popular in known_packages:
            if name_lower == popular:
                continue
            dist = levenshtein_distance(name_lower, popular)
            if dist <= 2:
                findings.append(Finding(
                    title=f"Possible typosquatting: '{name}' (similar to '{popular}')",
                    description=f"Package name '{name}' is 1 edit distance from popular package '{popular}'.",
                    severity=Severity.HIGH,
                    category=Category.SUPPLY_CHAIN,
                    file_path=file_path,
                    line_number=None,
                    analyzer=self.name,
                ))
        return findings

    def _is_suspicious_command(self, cmd: str) -> bool:
        suspicious = ["curl", "wget", "bash", "sh", "powershell", "eval", "exec"]
        cmd_lower = cmd.lower()
        return any(s in cmd_lower for s in suspicious)
