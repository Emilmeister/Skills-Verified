from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path

from skills_verified.analyzers.shell_utils import (
    SHELL_SUFFIXES,
    detect_shell_dialect,
)
from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import (
    Category,
    Diagnostic,
    DiagnosticLevel,
    Finding,
    Severity,
)

_DIRECTIVE = re.compile(r"^\s*#\s*shellcheck(?:\s|$)", re.IGNORECASE)
_VERSION = re.compile(r"^version:\s*(\S+)", re.MULTILINE | re.IGNORECASE)
_MAX_FILES_PER_BATCH = 200
_MAX_ARG_CHARS_PER_BATCH = 60_000
_TIMEOUT_SECONDS = 300
_MAX_DIAGNOSTIC_PATHS = 100
_NON_ACTIONABLE_RULE_IDS = {
    # Unused assignments are code-quality advice and do not establish a security risk.
    "SC2034",
}
_SECURITY_INFO_RULE_IDS = {
    # Client-side expansion inside an ssh command can become remote injection.
    "SC2029",
    # Bare globs can turn attacker-controlled filenames into command options.
    "SC2035",
}


class ShellCheckAnalyzer(Analyzer):
    name = "shellcheck"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []
        self.version: str | None = None
        self._executable: str | None = None

    def is_available(self) -> bool:
        self._executable = self._find_executable()
        return self._executable is not None

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        self.diagnostics = []
        executable = self._executable or self._find_executable()
        if executable is None:
            raise RuntimeError("shellcheck executable disappeared")

        context = kwargs.get("context")
        inventory = getattr(context, "files", None)
        candidates = inventory if inventory is not None else repo_path.rglob("*")
        roots = tuple(
            Path(root)
            for root in (getattr(context, "skill_roots", None) or [])
            if Path(root) != Path(".")
        )

        findings: list[Finding] = []
        with tempfile.TemporaryDirectory(prefix="sv-shellcheck-") as temporary:
            neutral_cwd = Path(temporary)
            mirror = neutral_cwd / "workspace"
            mirror.mkdir()
            environment = self._environment(neutral_cwd)
            self._load_version(executable, neutral_cwd, environment)
            groups = self._materialize_shell_files(
                repo_path,
                candidates,
                roots,
                mirror,
            )
            attempted = 0
            completed = 0
            for dialect in ("sh", "bash"):
                for batch in self._batches(groups[dialect]):
                    attempted += 1
                    result = self._run_batch(
                        executable,
                        dialect,
                        batch,
                        neutral_cwd,
                        environment,
                    )
                    if result is None:
                        continue
                    if result.returncode not in {0, 1, 2}:
                        self._execution_diagnostic(result.returncode, result.stderr)
                        continue
                    try:
                        findings.extend(self._parse_output(result.stdout, mirror))
                    except ValueError as exc:
                        self.diagnostics.append(
                            Diagnostic(
                                code="shellcheck_response_invalid",
                                message=f"ShellCheck returned invalid JSON: {exc}",
                                level=DiagnosticLevel.ERROR,
                                analyzer=self.name,
                            )
                        )
                        continue
                    completed += 1
                    if result.returncode == 2:
                        self.diagnostics.append(
                            Diagnostic(
                                code="shellcheck_incomplete",
                                message="ShellCheck could not process every input file",
                                analyzer=self.name,
                                details={"stderr": result.stderr.strip()[:500]},
                            )
                        )

            if attempted and not completed:
                raise RuntimeError("shellcheck could not analyze any input batch")
        return findings

    @staticmethod
    def _find_executable() -> str | None:
        executable = shutil.which("shellcheck")
        if executable:
            return executable
        sibling = Path(sys.executable).with_name(
            "shellcheck.exe" if os.name == "nt" else "shellcheck"
        )
        return str(sibling) if sibling.is_file() else None

    @staticmethod
    def _environment(neutral_cwd: Path) -> dict[str, str]:
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in {"SHELLCHECK_OPTS", "XDG_CONFIG_HOME"}
        }
        environment["HOME"] = str(neutral_cwd)
        return environment

    def _load_version(
        self,
        executable: str,
        neutral_cwd: Path,
        environment: dict[str, str],
    ) -> None:
        try:
            result = subprocess.run(
                [executable, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=neutral_cwd,
                env=environment,
            )
        except (OSError, subprocess.SubprocessError):
            return
        match = _VERSION.search(result.stdout)
        if result.returncode == 0 and match:
            self.version = match.group(1)

    def _materialize_shell_files(
        self,
        repo_path: Path,
        candidates: Iterable[Path],
        roots: tuple[Path, ...],
        mirror: Path,
    ) -> dict[str, list[Path]]:
        groups: dict[str, list[Path]] = {"sh": [], "bash": []}
        suppressed_paths: list[str] = []
        suppression_count = 0
        for source in sorted(candidates, key=lambda path: path.as_posix()):
            if not source.is_file():
                continue
            try:
                relative = source.relative_to(repo_path)
            except ValueError:
                continue
            if roots and not any(
                relative == root or root in relative.parents for root in roots
            ):
                continue
            dialect = detect_shell_dialect(source)
            if dialect is None:
                if source.suffix.casefold() in SHELL_SUFFIXES:
                    self.diagnostics.append(
                        Diagnostic(
                            code="shellcheck_unsupported_dialect",
                            message="Shell script uses an unsupported or invalid shebang",
                            analyzer=self.name,
                            path=relative.as_posix(),
                        )
                    )
                continue
            try:
                content = source.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.diagnostics.append(
                    Diagnostic(
                        code="shellcheck_file_read_failed",
                        message=f"Could not read shell source: {type(exc).__name__}",
                        analyzer=self.name,
                        path=relative.as_posix(),
                    )
                )
                continue
            sanitized, ignored = self._strip_directives(content)
            if ignored:
                suppression_count += ignored
                suppressed_paths.append(relative.as_posix())
            target = mirror / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(sanitized, encoding="utf-8")
            groups[dialect].append(target)

        if suppression_count:
            self.diagnostics.append(
                Diagnostic(
                    code="shellcheck_suppressions_ignored",
                    message="Repository-controlled ShellCheck directives were ignored",
                    level=DiagnosticLevel.INFO,
                    analyzer=self.name,
                    details={
                        "count": suppression_count,
                        "paths": sorted(set(suppressed_paths))[:_MAX_DIAGNOSTIC_PATHS],
                    },
                )
            )
        return groups

    @staticmethod
    def _strip_directives(content: str) -> tuple[str, int]:
        sanitized: list[str] = []
        ignored = 0
        for line in content.splitlines(keepends=True):
            if _DIRECTIVE.match(line):
                ignored += 1
                sanitized.append("\n" if line.endswith(("\n", "\r")) else "")
            else:
                sanitized.append(line)
        return "".join(sanitized), ignored

    @staticmethod
    def _batches(paths: list[Path]) -> Iterable[list[Path]]:
        batch: list[Path] = []
        size = 0
        for path in sorted(paths, key=lambda item: item.as_posix()):
            path_size = len(str(path)) + 1
            if batch and (
                len(batch) >= _MAX_FILES_PER_BATCH
                or size + path_size > _MAX_ARG_CHARS_PER_BATCH
            ):
                yield batch
                batch = []
                size = 0
            batch.append(path)
            size += path_size
        if batch:
            yield batch

    def _run_batch(
        self,
        executable: str,
        dialect: str,
        batch: list[Path],
        neutral_cwd: Path,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[str] | None:
        command = [
            executable,
            "--format=json1",
            "--norc",
            "--severity=style",
            f"--shell={dialect}",
            *(str(path) for path in batch),
        ]
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_SECONDS,
                cwd=neutral_cwd,
                env=environment,
            )
        except subprocess.TimeoutExpired:
            self.diagnostics.append(
                Diagnostic(
                    code="shellcheck_timeout",
                    message="ShellCheck batch exceeded its wall-clock timeout",
                    analyzer=self.name,
                    details={"files": len(batch)},
                )
            )
            return None
        except FileNotFoundError as exc:
            raise RuntimeError("shellcheck executable disappeared") from exc

    def _parse_output(self, output: str, mirror: Path) -> list[Finding]:
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as exc:
            raise ValueError("response is not valid JSON") from exc
        comments = payload.get("comments") if isinstance(payload, dict) else None
        if not isinstance(comments, list):
            raise ValueError("response does not contain a comments array")

        findings: list[Finding] = []
        mirror = mirror.resolve()
        for comment in comments:
            if not isinstance(comment, dict):
                raise ValueError("comment is not an object")
            level = str(comment.get("level", "")).casefold()
            code = comment.get("code")
            if type(code) is not int or code < 1:
                raise ValueError("comment code is invalid")
            rule = f"SC{code}"
            if level not in {"error", "warning"} and rule not in (
                _SECURITY_INFO_RULE_IDS
            ):
                continue
            raw_path = comment.get("file")
            if not isinstance(raw_path, str) or not raw_path:
                raise ValueError("comment file is invalid")
            candidate = Path(raw_path)
            if not candidate.is_absolute():
                candidate = mirror / candidate
            try:
                relative = candidate.resolve().relative_to(mirror).as_posix()
            except ValueError:
                self.diagnostics.append(
                    Diagnostic(
                        code="shellcheck_location_invalid",
                        message="ShellCheck returned a path outside its analysis workspace",
                        analyzer=self.name,
                    )
                )
                continue
            line = comment.get("line")
            end_line = comment.get("endLine", line)
            if type(line) is not int or line < 1:
                raise ValueError("comment line is invalid")
            if type(end_line) is not int or end_line < line:
                raise ValueError("comment endLine is invalid")
            if rule in _NON_ACTIONABLE_RULE_IDS:
                continue
            message = str(comment.get("message", "ShellCheck finding"))[:4_000]
            findings.append(
                Finding(
                    title=f"ShellCheck {rule}",
                    description=message,
                    severity=(Severity.MEDIUM if level == "error" else Severity.LOW),
                    category=Category.CODE_SAFETY,
                    file_path=relative,
                    line_number=line,
                    end_line=end_line,
                    analyzer=self.name,
                    confidence=0.9,
                    rule_id=f"SV-SHELLCHECK-{rule}",
                    remediation=f"Review and correct ShellCheck rule {rule}.",
                    references=[f"https://www.shellcheck.net/wiki/{rule}"],
                )
            )
        return findings

    def _execution_diagnostic(self, returncode: int, stderr: str) -> None:
        self.diagnostics.append(
            Diagnostic(
                code="shellcheck_execution_failed",
                message=f"ShellCheck exited with status {returncode}",
                level=DiagnosticLevel.ERROR,
                analyzer=self.name,
                details={"stderr": stderr.strip()[:500]},
            )
        )
