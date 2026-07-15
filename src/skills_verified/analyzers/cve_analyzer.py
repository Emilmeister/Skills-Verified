import json
import re
import ssl
import tomllib
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import certifi
import yaml

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.context import iter_analysis_files
from skills_verified.core.models import Category, Diagnostic, Finding, Severity
from skills_verified.repo.files import collect_safe_files, safe_read_text


OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULNERABILITY_URL = "https://api.osv.dev/v1/vulns/{vulnerability_id}"
_MAX_OSV_RESPONSE_BYTES = 10 * 1024 * 1024
_MAX_OSV_BATCH = 1000
_MAX_OSV_DETAIL_WORKERS = 8
_MAX_DEPENDENCIES = 10_000
_MAX_MANIFEST_RECORDS = 10_000
_MAX_DIAGNOSTICS_PER_CODE = 25
_MAX_DIAGNOSTIC_MESSAGE_CHARS = 500
_PINNED_REQUIREMENT = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^]]+\])?\s*==(?!=)\s*(?P<version>[^\s;\\]+)"
)
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}
_SEVERITY_RANK = {
    Severity.UNKNOWN: 0,
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


class CveLookupError(RuntimeError):
    """OSV could not provide a complete vulnerability result."""


@dataclass(frozen=True)
class _Dependency:
    ecosystem: str
    name: str
    version: str
    file_path: str


class CveAnalyzer(Analyzer):
    name = "cve"

    def __init__(self, *, timeout: float = 15) -> None:
        if timeout <= 0:
            raise ValueError("OSV request timeout must be positive")
        self.timeout = timeout
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        self.last_diagnostics: list[Diagnostic] = []
        self._diagnostic_counts: dict[str, int] = {}
        self._diagnostic_aggregates: dict[str, Diagnostic] = {}
        self._manifest_records_seen = 0
        self._manifest_limit_reported = False
        self._osv_cache: dict[tuple[str, str, str], dict] = {}
        self._vulnerability_cache: dict[str, dict] = {}

    @property
    def diagnostics(self) -> list[Diagnostic]:
        """Transitional diagnostics for pipelines that still expect findings only."""
        return self.last_diagnostics

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        self._reset_diagnostics()
        # Advisory data changes over time. Caches are deliberately per scan so a
        # long-lived service cannot return a stale clean result or grow forever.
        self._osv_cache.clear()
        self._vulnerability_cache.clear()
        context = kwargs.get("context")
        dependencies = self._collect_dependencies(
            repo_path, tuple(iter_analysis_files(repo_path, context))
        )
        if not dependencies:
            return []
        try:
            results = self._query_osv(dependencies)
        except CveLookupError as exc:
            self._diagnostic("osv_lookup_failed", str(exc))
            raise
        results = self._enrich_results(results)

        findings: dict[tuple[str, str, str, str, str], Finding] = {}
        for dependency, result in zip(dependencies, results, strict=True):
            for vulnerability in result.get("vulns") or []:
                finding = self._finding(dependency, vulnerability)
                identity = finding.cve_id or finding.rule_id or "unknown"
                key = (
                    dependency.ecosystem,
                    dependency.name,
                    dependency.version,
                    dependency.file_path,
                    identity,
                )
                previous = findings.get(key)
                if previous is None:
                    findings[key] = finding
                    continue
                preferred, other = (
                    (finding, previous)
                    if _SEVERITY_RANK[finding.severity]
                    > _SEVERITY_RANK[previous.severity]
                    else (previous, finding)
                )
                preferred.references = sorted(
                    set(preferred.references) | set(other.references)
                )
                preferred.remediation = preferred.remediation or other.remediation
                findings[key] = preferred
        return list(findings.values())

    def _collect_dependencies(
        self,
        repo_path: Path,
        inventory_files: Iterable[Path] | None = None,
    ) -> list[_Dependency]:
        self._manifest_records_seen = 0
        self._manifest_limit_reported = False
        inventory = collect_safe_files(repo_path) if inventory_files is None else None
        files = inventory.files if inventory is not None else inventory_files
        for skipped in inventory.skipped if inventory is not None else ():
            if Path(skipped.path).name in {
                "Pipfile",
                "package-lock.json",
                "pyproject.toml",
            } or Path(skipped.path).name.startswith("requirements"):
                self._diagnostic(
                    "manifest_skipped",
                    f"Skipped dependency manifest: {skipped.reason}",
                    skipped.path,
                )

        dependencies: list[_Dependency] = []
        seen: set[_Dependency] = set()
        for path in files:
            relative = path.relative_to(repo_path).as_posix()
            try:
                parsed: Iterator[_Dependency] | None = None
                if path.name.startswith("requirements") and path.suffix == ".txt":
                    parsed = self._iter_requirement_lines(
                        StringIO(safe_read_text(path, repo_path)), relative
                    )
                elif path.name == "pyproject.toml":
                    parsed = self._iter_pyproject(
                        safe_read_text(path, repo_path), relative
                    )
                elif path.name == "Pipfile":
                    parsed = self._iter_pipfile(
                        safe_read_text(path, repo_path), relative
                    )
                elif path.name == "package-lock.json":
                    parsed = self._iter_package_lock(
                        safe_read_text(path, repo_path), relative
                    )
                elif path.name == "bun.lock":
                    parsed = self._iter_bun_lock(
                        safe_read_text(path, repo_path), relative
                    )
                if parsed is None:
                    continue
                for dependency in parsed:
                    if dependency in seen:
                        continue
                    if len(dependencies) >= _MAX_DEPENDENCIES:
                        self._diagnostic(
                            "dependency_limit_exceeded",
                            f"Stopped after {_MAX_DEPENDENCIES} pinned dependency records",
                            relative,
                        )
                        return dependencies
                    seen.add(dependency)
                    dependencies.append(dependency)
            except (
                json.JSONDecodeError,
                tomllib.TOMLDecodeError,
                yaml.YAMLError,
                RecursionError,
                TypeError,
                ValueError,
            ) as exc:
                self._diagnostic(
                    "manifest_parse_error",
                    f"Could not parse dependency manifest: {exc}",
                    relative,
                )
                continue
            if self._manifest_limit_reported:
                return dependencies

        return dependencies

    def _parse_requirement_lines(
        self, lines: Iterable[str], file_path: str
    ) -> list[_Dependency]:
        return list(self._iter_requirement_lines(lines, file_path))

    def _iter_requirement_lines(
        self, lines: Iterable[str], file_path: str
    ) -> Iterator[_Dependency]:
        for raw_line in lines:
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if not self._take_manifest_record(file_path):
                return
            if line.startswith(("-r", "--requirement", "-c", "--constraint", "-e")):
                self._diagnostic(
                    "unsupported_requirement",
                    f"Skipped indirect dependency declaration: {line}",
                    file_path,
                )
                continue
            if line.startswith("-"):
                continue
            match = _PINNED_REQUIREMENT.match(line)
            if not match:
                display_line = line.rstrip(" \\")
                self._diagnostic(
                    "unpinned_dependency",
                    f"Skipped unpinned dependency: {display_line}",
                    file_path,
                )
                continue
            yield _Dependency(
                "PyPI",
                self._normalize_python_name(match.group("name")),
                match.group("version"),
                file_path,
            )

    def _iter_pyproject(self, text: str, file_path: str) -> Iterator[_Dependency]:
        data = tomllib.loads(text)
        requirements = list(data.get("project", {}).get("dependencies", []))
        for optional in (
            data.get("project", {}).get("optional-dependencies", {}).values()
        ):
            requirements.extend(optional)
        yield from self._iter_requirement_lines(requirements, file_path)
        if self._manifest_limit_reported:
            return

        poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for name, constraint in poetry.items():
            if name.lower() == "python":
                continue
            if not self._take_manifest_record(file_path):
                return
            if isinstance(constraint, dict):
                constraint = constraint.get("version")
            if not isinstance(constraint, str):
                continue
            version = self._exact_toml_version(constraint)
            if version:
                yield _Dependency(
                    "PyPI", self._normalize_python_name(name), version, file_path
                )
            else:
                self._diagnostic(
                    "unpinned_dependency",
                    f"Skipped unpinned dependency: {name} {constraint}",
                    file_path,
                )

    def _iter_pipfile(self, text: str, file_path: str) -> Iterator[_Dependency]:
        data = tomllib.loads(text)
        for section in ("packages", "dev-packages"):
            for name, constraint in data.get(section, {}).items():
                if not self._take_manifest_record(file_path):
                    return
                if isinstance(constraint, dict):
                    constraint = constraint.get("version")
                if not isinstance(constraint, str):
                    continue
                version = self._exact_toml_version(constraint, require_equals=True)
                if version:
                    yield _Dependency(
                        "PyPI",
                        self._normalize_python_name(name),
                        version,
                        file_path,
                    )
                else:
                    self._diagnostic(
                        "unpinned_dependency",
                        f"Skipped unpinned dependency: {name} {constraint}",
                        file_path,
                    )

    def _iter_package_lock(self, text: str, file_path: str) -> Iterator[_Dependency]:
        data = json.loads(text)
        packages = data.get("packages")
        if isinstance(packages, dict):
            for key, package in packages.items():
                if not key:
                    continue
                if not self._take_manifest_record(file_path):
                    return
                if not isinstance(package, dict) or package.get("link"):
                    continue
                name = package.get("name") or key.rsplit("node_modules/", 1)[-1]
                version = package.get("version")
                if isinstance(name, str) and isinstance(version, str):
                    yield _Dependency("npm", name, version, file_path)
            return

        root_dependencies = data.get("dependencies")
        if not isinstance(root_dependencies, dict):
            return
        stack = [iter(root_dependencies.items())]
        while stack:
            try:
                name, package = next(stack[-1])
            except StopIteration:
                stack.pop()
                continue
            if not self._take_manifest_record(file_path):
                return
            if not isinstance(package, dict):
                continue
            version = package.get("version")
            if isinstance(version, str):
                yield _Dependency("npm", name, version, file_path)
            nested = package.get("dependencies")
            if isinstance(nested, dict):
                stack.append(iter(nested.items()))

    def _iter_bun_lock(self, text: str, file_path: str) -> Iterator[_Dependency]:
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError("bun.lock root must be a mapping")
        packages = data.get("packages")
        if not isinstance(packages, dict):
            raise ValueError("bun.lock packages must be a mapping")
        for record in packages.values():
            if not self._take_manifest_record(file_path):
                return
            if not isinstance(record, list) or not record:
                continue
            resolved = record[0]
            if not isinstance(resolved, str) or "@" not in resolved.lstrip("@"):
                continue
            name, version = resolved.rsplit("@", 1)
            if not name or not version or version.startswith("workspace:"):
                continue
            yield _Dependency("npm", name, version, file_path)

    def _query_osv(self, dependencies: list[_Dependency]) -> list[dict]:
        missing: dict[tuple[str, str, str], _Dependency] = {}
        for dependency in dependencies:
            key = (dependency.ecosystem, dependency.name, dependency.version)
            if key not in self._osv_cache:
                missing.setdefault(key, dependency)

        uncached = list(missing.values())
        fetched: list[dict] = []
        for start in range(0, len(uncached), _MAX_OSV_BATCH):
            batch = uncached[start : start + _MAX_OSV_BATCH]
            payload = {
                "queries": [
                    {
                        "package": {
                            "ecosystem": dependency.ecosystem,
                            "name": dependency.name,
                        },
                        "version": dependency.version,
                    }
                    for dependency in batch
                ]
            }
            request = Request(
                OSV_QUERY_URL,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urlopen(
                    request, timeout=self.timeout, context=self.ssl_context
                ) as response:
                    raw_response = response.read(_MAX_OSV_RESPONSE_BYTES + 1)
                    if len(raw_response) > _MAX_OSV_RESPONSE_BYTES:
                        raise CveLookupError("OSV response exceeded the size limit")
                    data = json.loads(raw_response)
            except CveLookupError:
                raise
            except (
                HTTPError,
                URLError,
                TimeoutError,
                OSError,
                json.JSONDecodeError,
            ) as exc:
                raise CveLookupError(f"OSV query failed: {exc}") from exc
            if not isinstance(data, dict):
                raise CveLookupError("OSV response was not a JSON object")
            batch_results = data.get("results")
            if not isinstance(batch_results, list) or len(batch_results) != len(batch):
                raise CveLookupError("OSV result count did not match the request")
            for result in batch_results:
                if not isinstance(result, dict):
                    raise CveLookupError("OSV returned an invalid result entry")
                vulnerabilities = result.get("vulns")
                if vulnerabilities is not None and (
                    not isinstance(vulnerabilities, list)
                    or not all(isinstance(item, dict) for item in vulnerabilities)
                ):
                    raise CveLookupError("OSV returned an invalid vulnerability entry")
                if result.get("next_page_token"):
                    raise CveLookupError(
                        "OSV query returned paginated results; completeness is unknown"
                    )
            fetched.extend(batch_results)

        for dependency, result in zip(uncached, fetched, strict=True):
            key = (dependency.ecosystem, dependency.name, dependency.version)
            self._osv_cache[key] = result
        return [
            self._osv_cache[(dependency.ecosystem, dependency.name, dependency.version)]
            for dependency in dependencies
        ]

    def _enrich_results(self, results: list[dict]) -> list[dict]:
        all_detail_ids = sorted(
            {
                vulnerability["id"]
                for result in results
                for vulnerability in result.get("vulns") or []
                if isinstance(vulnerability.get("id"), str)
                and set(vulnerability).issubset({"id", "modified"})
            }
        )
        detail_ids = all_detail_ids
        details: dict[str, dict] = {}
        failures: list[tuple[str, CveLookupError]] = []
        if detail_ids:
            with ThreadPoolExecutor(
                max_workers=min(_MAX_OSV_DETAIL_WORKERS, len(detail_ids))
            ) as executor:
                futures = {
                    executor.submit(
                        self._get_vulnerability, vulnerability_id
                    ): vulnerability_id
                    for vulnerability_id in detail_ids
                }
                for future in as_completed(futures):
                    vulnerability_id = futures[future]
                    try:
                        details[vulnerability_id] = future.result()
                    except CveLookupError as exc:
                        failures.append((vulnerability_id, exc))
        for vulnerability_id, exc in sorted(failures):
            self._diagnostic(
                "osv_detail_lookup_failed",
                f"Could not enrich OSV record {vulnerability_id}: {exc}",
            )

        enriched_results: list[dict] = []
        for result in results:
            enriched = dict(result)
            vulnerabilities: list[dict] = []
            for summary in result.get("vulns") or []:
                vulnerability_id = summary.get("id")
                vulnerabilities.append(details.get(vulnerability_id, summary))
            enriched["vulns"] = vulnerabilities
            enriched_results.append(enriched)
        return enriched_results

    def _get_vulnerability(self, vulnerability_id: str) -> dict:
        cached = self._vulnerability_cache.get(vulnerability_id)
        if cached is not None:
            return cached
        request = Request(
            OSV_VULNERABILITY_URL.format(
                vulnerability_id=quote(vulnerability_id, safe="")
            ),
            headers={"Accept": "application/json"},
            method="GET",
        )
        try:
            with urlopen(
                request,
                timeout=self.timeout,
                context=self.ssl_context,
            ) as response:
                raw_response = response.read(_MAX_OSV_RESPONSE_BYTES + 1)
                if len(raw_response) > _MAX_OSV_RESPONSE_BYTES:
                    raise CveLookupError(
                        "OSV vulnerability response exceeded the size limit"
                    )
                data = json.loads(raw_response)
        except CveLookupError:
            raise
        except (
            HTTPError,
            URLError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            raise CveLookupError(f"OSV vulnerability query failed: {exc}") from exc
        if not isinstance(data, dict) or data.get("id") != vulnerability_id:
            raise CveLookupError("OSV returned an invalid vulnerability record")
        self._vulnerability_cache[vulnerability_id] = data
        return data

    def _finding(self, dependency: _Dependency, vulnerability: dict) -> Finding:
        vulnerability_id = str(vulnerability.get("id", "unknown"))
        aliases = [str(item) for item in vulnerability.get("aliases") or []]
        cve_id = next(
            (item for item in [vulnerability_id, *aliases] if item.startswith("CVE-")),
            None,
        )
        severity = self._severity(vulnerability)
        summary = vulnerability.get("summary") or vulnerability.get("details")
        description = str(summary or "No vulnerability description provided by OSV")
        if severity == Severity.UNKNOWN:
            description = f"{description}\nSeverity: not provided by OSV"
        fixed_versions = self._fixed_versions(vulnerability)
        references = [
            str(item["url"])
            for item in vulnerability.get("references") or []
            if isinstance(item, dict) and isinstance(item.get("url"), str)
        ]
        return Finding(
            title=(
                f"Vulnerability in {dependency.name}=={dependency.version}: "
                f"{vulnerability_id}"
            ),
            description=description,
            severity=severity,
            category=Category.CVE,
            file_path=dependency.file_path,
            line_number=None,
            analyzer=self.name,
            cve_id=cve_id,
            rule_id=(
                "SV-CVE-"
                + re.sub(r"[^A-Z0-9]+", "-", vulnerability_id.upper()).strip("-")
            ),
            remediation=(
                f"Upgrade {dependency.name} to {', '.join(fixed_versions)} or later."
                if fixed_versions
                else None
            ),
            references=references,
        )

    @staticmethod
    def _severity(vulnerability: dict) -> Severity:
        database_specific = vulnerability.get("database_specific")
        candidates = [
            database_specific.get("severity")
            if isinstance(database_specific, dict)
            else None
        ]
        for affected in vulnerability.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            ecosystem_specific = affected.get("ecosystem_specific")
            database_specific = affected.get("database_specific")
            candidates.append(
                ecosystem_specific.get("severity")
                if isinstance(ecosystem_specific, dict)
                else None
            )
            candidates.append(
                database_specific.get("severity")
                if isinstance(database_specific, dict)
                else None
            )
        for candidate in candidates:
            if isinstance(candidate, str) and candidate.lower() in _SEVERITY_MAP:
                return _SEVERITY_MAP[candidate.lower()]
        return Severity.UNKNOWN

    @staticmethod
    def _fixed_versions(vulnerability: dict) -> list[str]:
        versions: set[str] = set()
        for affected in vulnerability.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            for item in affected.get("ranges") or []:
                if not isinstance(item, dict):
                    continue
                for event in item.get("events") or []:
                    if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                        versions.add(event["fixed"])
        return sorted(versions)

    @staticmethod
    def _normalize_python_name(name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).lower()

    @staticmethod
    def _exact_toml_version(value: str, *, require_equals: bool = False) -> str | None:
        value = value.strip()
        if value.startswith("=="):
            value = value[2:].strip()
        elif require_equals:
            return None
        if not value or value == "*" or any(char in value for char in "^~<>=*, "):
            return None
        return value

    def _take_manifest_record(self, file_path: str) -> bool:
        if self._manifest_records_seen >= _MAX_MANIFEST_RECORDS:
            if not self._manifest_limit_reported:
                self._manifest_limit_reported = True
                self._diagnostic(
                    "manifest_record_limit_exceeded",
                    f"Stopped after {_MAX_MANIFEST_RECORDS} dependency declarations",
                    file_path,
                )
            return False
        self._manifest_records_seen += 1
        return True

    def _reset_diagnostics(self) -> None:
        self.last_diagnostics = []
        self._diagnostic_counts = {}
        self._diagnostic_aggregates = {}

    def _diagnostic(self, code: str, message: str, path: str | None = None) -> None:
        count = self._diagnostic_counts.get(code, 0) + 1
        self._diagnostic_counts[code] = count
        if count > _MAX_DIAGNOSTICS_PER_CODE:
            aggregate = self._diagnostic_aggregates.get(code)
            if aggregate is None:
                aggregate = Diagnostic(
                    code="diagnostics_suppressed",
                    message=f"Additional {code} diagnostics were suppressed",
                    analyzer=self.name,
                    path=path,
                    details={"diagnostic_code": code, "suppressed_count": 1},
                )
                self._diagnostic_aggregates[code] = aggregate
                self.last_diagnostics.append(aggregate)
            else:
                aggregate.details["suppressed_count"] += 1
            return

        if len(message) > _MAX_DIAGNOSTIC_MESSAGE_CHARS:
            message = message[: _MAX_DIAGNOSTIC_MESSAGE_CHARS - 1] + "…"
        self.last_diagnostics.append(
            Diagnostic(
                code=code,
                message=message,
                analyzer=self.name,
                path=path,
            )
        )
