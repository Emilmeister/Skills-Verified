import hashlib
import json
import os
import re
import subprocess
import tempfile
from importlib import resources
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.context import analysis_roots
from skills_verified.core.models import (
    Category,
    Diagnostic,
    DiagnosticLevel,
    Finding,
    Severity,
)
from skills_verified.analyzers.external_tool import find_executable

SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}
CONFIDENCE_MAP = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.4}
IGNORED_RULES = {
    # This registry rule reports unrelated source locations in generated/test HTML
    # projects and does not provide actionable source-to-sink evidence.
    "javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag",
}
REACT_HTML_RULE = (
    "typescript.react.security.audit.react-dangerouslysetinnerhtml."
    "react-dangerouslysetinnerhtml"
)
PINNED_CONFIGS = (
    (
        "security-audit",
        "semgrep-security-audit.yml",
        "fdc7027973176abe71f6b1fc8739ef88a4c411735c380cfce4f731df9644e47a",
    ),
    (
        "python",
        "semgrep-python.yml",
        "58d902c05089c543d3cc303cefb82d0a0ebc6c73aa5a69f64dd9b8f06864082c",
    ),
)
MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_DIAGNOSTIC_PATHS = 100
_SOURCE_RULES = Path(__file__).resolve().parents[3] / "data"


class SemgrepAnalyzer(Analyzer):
    name = "semgrep"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []
        try:
            self.version = version("semgrep")
        except PackageNotFoundError:
            self.version = None

    def is_available(self) -> bool:
        return find_executable("semgrep") is not None

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        self.diagnostics = []
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("SEMGREP_")
        }
        with tempfile.TemporaryDirectory(prefix="sv-semgrep-") as neutral_cwd:
            config_paths = self._materialize_pinned_configs(Path(neutral_cwd))
            executable = find_executable("semgrep")
            if executable is None:
                raise RuntimeError("semgrep executable disappeared")
            command = [executable, "scan"]
            for config_path in config_paths:
                command.extend(("--config", config_path.name))
            for rule_id in sorted(IGNORED_RULES):
                command.extend(("--exclude-rule", rule_id))
            command.extend(
                (
                    "--json",
                    "--quiet",
                    "--metrics=off",
                    "--disable-version-check",
                    "--disable-nosem",
                    "--no-git-ignore",
                    "--x-ignore-semgrepignore-files",
                    "--jobs=2",
                    "--timeout=30",
                    "--timeout-threshold=0",
                )
            )
            command.extend(self._scan_targets(repo_path, kwargs.get("context")))
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd=neutral_cwd,
                    env=environment,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("semgrep timed out") from exc
            except FileNotFoundError as exc:
                raise RuntimeError("semgrep executable disappeared") from exc
        if result.returncode not in {0, 1}:
            raise RuntimeError(f"semgrep exited with status {result.returncode}")
        findings = self._parse_output(result.stdout, repo_path)
        self.diagnostics.append(
            Diagnostic(
                code="semgrep_ruleset_provenance",
                message="Semgrep used hash-pinned local rule files",
                level=DiagnosticLevel.INFO,
                analyzer=self.name,
                details={
                    "configs": [
                        {"name": name, "sha256": expected_sha256}
                        for name, _filename, expected_sha256 in PINNED_CONFIGS
                    ]
                },
            )
        )
        return findings

    def _materialize_pinned_configs(self, directory: Path) -> list[Path]:
        paths: list[Path] = []
        rules_directory = self._rules_directory()
        for name, filename, expected_sha256 in PINNED_CONFIGS:
            try:
                content = rules_directory.joinpath(filename).read_bytes()
            except OSError as exc:
                raise RuntimeError(
                    f"Bundled Semgrep ruleset {name} could not be read"
                ) from exc
            if len(content) > MAX_CONFIG_BYTES:
                raise RuntimeError(f"Semgrep ruleset {name} exceeded its size limit")
            if hashlib.sha256(content).hexdigest() != expected_sha256:
                raise RuntimeError(f"Semgrep ruleset {name} digest mismatch")
            path = directory / f"{name}.yml"
            path.write_bytes(content)
            paths.append(path)
        return paths

    @staticmethod
    def _rules_directory():
        packaged_rules = resources.files("skills_verified.data").joinpath("rules")
        return packaged_rules if packaged_rules.is_dir() else _SOURCE_RULES

    @staticmethod
    def _scan_targets(repo_path: Path, context: object | None) -> list[str]:
        return [str(path) for path in analysis_roots(repo_path, context)]

    def _parse_output(self, output: str, repo_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError as exc:
            raise ValueError("semgrep did not return valid JSON") from exc
        tool_version = data.get("version")
        if isinstance(tool_version, str) and tool_version:
            self.version = tool_version
        self._parse_errors(data.get("errors", []), repo_path)
        for result in data.get("results", []):
            check_id = str(result.get("check_id", "unknown"))
            if check_id in IGNORED_RULES:
                continue
            extra = result.get("extra", {})
            severity_str = extra.get("severity", "WARNING")
            severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
            metadata = extra.get("metadata", {})
            confidence_label = (
                metadata.get("confidence", "MEDIUM")
                if isinstance(metadata, dict)
                else "MEDIUM"
            )
            confidence = CONFIDENCE_MAP.get(str(confidence_label).upper(), 0.7)
            file_abs = Path(result.get("path", ""))
            try:
                file_rel = str(file_abs.relative_to(repo_path))
            except ValueError:
                file_rel = str(file_abs)
            start_line = result.get("start", {}).get("line")
            if check_id == REACT_HTML_RULE and self._dompurify_sanitizes_sink(
                file_abs, start_line
            ):
                continue
            normalized_id = re.sub(r"[^A-Z0-9]+", "-", check_id.upper()).strip("-")
            findings.append(
                Finding(
                    title=f"Semgrep: {check_id}",
                    description=extra.get("message", ""),
                    severity=severity,
                    category=Category.CODE_SAFETY,
                    file_path=file_rel,
                    line_number=start_line,
                    end_line=result.get("end", {}).get("line"),
                    analyzer=self.name,
                    confidence=confidence,
                    rule_id=f"SV-SEMGREP-{normalized_id or 'UNKNOWN'}",
                    remediation=(
                        extra.get("fix") if isinstance(extra.get("fix"), str) else None
                    ),
                )
            )
        return findings

    def _parse_errors(self, errors: object, repo_path: Path) -> None:
        if not isinstance(errors, list):
            return
        partial_paths: set[str] = set()
        timeout_paths: set[str] = set()
        timeout_rules: set[str] = set()
        other_errors: list[tuple[str, str | None]] = []
        for error in errors:
            if not isinstance(error, dict):
                other_errors.append(("unknown", None))
                continue
            raw_type = error.get("type")
            error_type = (
                str(raw_type[0])
                if isinstance(raw_type, list) and raw_type
                else str(raw_type or "unknown")
            )
            path = self._relative_error_path(error.get("path"), repo_path)
            if error_type == "PartialParsing":
                if path:
                    partial_paths.add(path)
                continue
            if error_type == "Timeout":
                rule_id = error.get("rule_id")
                if isinstance(rule_id, str) and rule_id in IGNORED_RULES:
                    continue
                if path:
                    timeout_paths.add(path)
                if isinstance(rule_id, str):
                    timeout_rules.add(rule_id)
                continue
            other_errors.append((error_type, path))

        if partial_paths:
            paths = sorted(partial_paths)
            self.diagnostics.append(
                Diagnostic(
                    code="semgrep_partial_parsing",
                    message="Semgrep could not parse parts of some source files",
                    analyzer=self.name,
                    details={
                        "errors_total": sum(
                            self._error_type(error) == "PartialParsing"
                            for error in errors
                            if isinstance(error, dict)
                        ),
                        "files_total": len(paths),
                        "paths": paths[:MAX_DIAGNOSTIC_PATHS],
                    },
                )
            )
        if timeout_paths or timeout_rules:
            self.diagnostics.append(
                Diagnostic(
                    code="semgrep_timeout",
                    message="Semgrep timed out on one or more rule and file pairs",
                    analyzer=self.name,
                    details={
                        "paths": sorted(timeout_paths)[:MAX_DIAGNOSTIC_PATHS],
                        "rules": sorted(timeout_rules)[:MAX_DIAGNOSTIC_PATHS],
                    },
                )
            )
        for error_type, path in other_errors[:MAX_DIAGNOSTIC_PATHS]:
            self.diagnostics.append(
                Diagnostic(
                    code="semgrep_analysis_error",
                    message=f"Semgrep reported an analysis error: {error_type}",
                    analyzer=self.name,
                    path=path,
                    details={"error_type": error_type},
                )
            )

    @staticmethod
    def _error_type(error: dict) -> str:
        raw_type = error.get("type")
        if isinstance(raw_type, list) and raw_type:
            return str(raw_type[0])
        return str(raw_type or "unknown")

    @staticmethod
    def _relative_error_path(value: object, repo_path: Path) -> str | None:
        if not isinstance(value, str) or not value:
            return None
        path = Path(value)
        try:
            return path.relative_to(repo_path).as_posix()
        except ValueError:
            return path.as_posix()

    @staticmethod
    def _dompurify_sanitizes_sink(file_path: Path, line_number: object) -> bool:
        if not isinstance(line_number, int) or line_number < 1:
            return False
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        lines = content.splitlines()
        if line_number > len(lines):
            return False
        sink_line = lines[line_number - 1]
        if re.search(r"__html\s*:\s*DOMPurify\.sanitize\s*\(", sink_line):
            return True
        sink = re.search(r"__html\s*:\s*([A-Za-z_$][\w$]*)", sink_line)
        if sink is None:
            return False
        before_sink = "\n".join(lines[: line_number - 1])
        assignment = list(
            re.finditer(
                rf"\b{re.escape(sink.group(1))}\s*=\s*"
                rf"([A-Za-z_$][\w$]*)\s*\(",
                before_sink,
            )
        )
        if not assignment:
            return False
        helper = assignment[-1].group(1)
        definitions = list(
            re.finditer(rf"\bfunction\s+{re.escape(helper)}\s*\(", before_sink)
        )
        if not definitions:
            return False
        helper_source = before_sink[definitions[-1].start() : assignment[-1].start()]
        return "DOMPurify.sanitize(" in helper_source
