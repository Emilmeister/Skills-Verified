import json
import re
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.context import iter_analysis_files
from skills_verified.core.models import Category, Diagnostic, Finding, Severity

POPULAR_PACKAGES_PY = [
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "scipy",
    "tensorflow",
    "torch",
    "pillow",
    "cryptography",
    "paramiko",
    "boto3",
    "celery",
    "redis",
    "psycopg2",
    "sqlalchemy",
    "pyyaml",
    "jinja2",
    "matplotlib",
    "scikit-learn",
]

POPULAR_PACKAGES_NPM = [
    "express",
    "react",
    "lodash",
    "axios",
    "moment",
    "webpack",
    "typescript",
    "next",
    "vue",
    "angular",
    "socket.io",
    "mongoose",
    "sequelize",
    "passport",
    "jsonwebtoken",
    "dotenv",
    "cors",
    "helmet",
    "morgan",
    "chalk",
    "requests",
]

SUSPICIOUS_SCRIPTS = {"preinstall", "postinstall", "preuninstall", "postuninstall"}


def _bounded_edit_distance(left: str, right: str, limit: int = 2) -> int:
    """Return the edit distance, or limit + 1 once it cannot match the cutoff."""
    if abs(len(left) - len(right)) > limit:
        return limit + 1
    previous = list(range(len(right) + 1))
    for row, left_char in enumerate(left, start=1):
        current = [row]
        for column, right_char in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[column] + 1,
                    previous[column - 1] + (left_char != right_char),
                )
            )
        if min(current) > limit:
            return limit + 1
        previous = current
    return min(previous[-1], limit + 1)


class SupplyChainAnalyzer(Analyzer):
    name = "supply_chain"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        self.diagnostics = []
        findings: list[Finding] = []
        files = tuple(iter_analysis_files(repo_path, kwargs.get("context")))
        findings.extend(self._check_package_json(repo_path, files))
        findings.extend(self._check_setup_py(repo_path, files))
        findings.extend(self._check_requirements_txt(repo_path, files))
        return findings

    def _check_package_json(
        self, repo_path: Path, files: tuple[Path, ...] | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        candidates = repo_path.rglob("package.json") if files is None else files
        for pkg_file in candidates:
            if pkg_file.name != "package.json":
                continue
            rel_path = str(pkg_file.relative_to(repo_path))
            try:
                content = pkg_file.read_text(errors="ignore")
            except OSError as exc:
                self._diagnostic(
                    "package_json_read_error",
                    f"Could not read package.json: {type(exc).__name__}",
                    rel_path,
                )
                continue
            try:
                data = json.loads(content)
            except json.JSONDecodeError as exc:
                self._diagnostic(
                    "package_json_parse_error",
                    f"Invalid package.json at line {exc.lineno}, column {exc.colno}",
                    rel_path,
                )
                continue
            if not isinstance(data, dict):
                self._diagnostic(
                    "package_json_schema_error",
                    "package.json root must be a JSON object",
                    rel_path,
                )
                continue
            scripts = data.get("scripts", {})
            if not isinstance(scripts, dict):
                self._diagnostic(
                    "package_json_schema_error",
                    "package.json scripts must be a JSON object",
                    rel_path,
                )
                scripts = {}
            for script_name in SUSPICIOUS_SCRIPTS:
                if script_name in scripts:
                    cmd = scripts[script_name]
                    if not isinstance(cmd, str):
                        self._diagnostic(
                            "package_json_schema_error",
                            f"package.json script '{script_name}' must be a string",
                            rel_path,
                        )
                        continue
                    if self._is_suspicious_command(cmd):
                        findings.append(
                            Finding(
                                title=f"Suspicious {script_name} install script",
                                description=f"Install script runs: {cmd}",
                                severity=Severity.CRITICAL,
                                category=Category.SUPPLY_CHAIN,
                                file_path=rel_path,
                                line_number=None,
                                analyzer=self.name,
                            )
                        )
            all_deps: dict = {}
            for section in ("dependencies", "devDependencies"):
                dependencies = data.get(section, {})
                if not isinstance(dependencies, dict):
                    self._diagnostic(
                        "package_json_schema_error",
                        f"package.json {section} must be a JSON object",
                        rel_path,
                    )
                    continue
                all_deps.update(dependencies)
            for dep_name in all_deps:
                findings.extend(
                    self._check_typosquat(dep_name, POPULAR_PACKAGES_NPM, rel_path)
                )
        return findings

    def _check_setup_py(
        self, repo_path: Path, files: tuple[Path, ...] | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        candidates = repo_path.rglob("setup.py") if files is None else files
        for setup_file in candidates:
            if setup_file.name != "setup.py":
                continue
            try:
                content = setup_file.read_text(errors="ignore")
            except OSError as exc:
                self._diagnostic(
                    "setup_py_read_error",
                    f"Could not read setup.py: {type(exc).__name__}",
                    str(setup_file.relative_to(repo_path)),
                )
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
                        findings.append(
                            Finding(
                                title="Dangerous code execution in setup.py",
                                description=f"setup.py contains executable code at install time: {line.strip()}",
                                severity=Severity.CRITICAL,
                                category=Category.SUPPLY_CHAIN,
                                file_path=rel_path,
                                line_number=line_number,
                                analyzer=self.name,
                            )
                        )
        return findings

    def _check_requirements_txt(
        self, repo_path: Path, files: tuple[Path, ...] | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        candidates = repo_path.rglob("requirements*.txt") if files is None else files
        for req_file in candidates:
            if not (
                req_file.name.startswith("requirements") and req_file.suffix == ".txt"
            ):
                continue
            try:
                content = req_file.read_text(errors="ignore")
            except OSError as exc:
                self._diagnostic(
                    "requirements_read_error",
                    f"Could not read requirements file: {type(exc).__name__}",
                    str(req_file.relative_to(repo_path)),
                )
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
            # Edit distance on short names labels many established packages
            # (vite/vue, acorn/cors, recast/react) as typosquats.
            if min(len(name_lower), len(popular)) < 7:
                continue
            dist = _bounded_edit_distance(name_lower, popular)
            if dist <= 2:
                findings.append(
                    Finding(
                        title=f"Possible typosquatting: '{name}' (similar to '{popular}')",
                        description=f"Package name '{name}' is {dist} edits from popular package '{popular}'.",
                        severity=Severity.HIGH,
                        category=Category.SUPPLY_CHAIN,
                        file_path=file_path,
                        line_number=None,
                        analyzer=self.name,
                    )
                )
        return findings

    def _is_suspicious_command(self, cmd: str) -> bool:
        suspicious = ["curl", "wget", "bash", "sh", "powershell", "eval", "exec"]
        cmd_lower = cmd.lower()
        return any(s in cmd_lower for s in suspicious)

    def _diagnostic(self, code: str, message: str, path: str) -> None:
        self.diagnostics.append(
            Diagnostic(code=code, message=message, analyzer=self.name, path=path)
        )
