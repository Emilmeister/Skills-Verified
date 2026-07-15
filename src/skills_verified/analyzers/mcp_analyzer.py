"""Static checks for poisoning and rug-pull indicators in MCP definitions."""

from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path
from typing import Any, Iterator

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.context import iter_analysis_files
from skills_verified.core.models import (
    Category,
    Diagnostic,
    Evidence,
    Finding,
    Severity,
)
from skills_verified.platforms.base import MCPToolDefinition, PlatformProfile

_INJECTION_PATTERNS = (
    re.compile(
        r"ignore\s+(all\s+)?(previous|prior|above)\s+"
        r"(instructions|guidelines|rules)",
        re.IGNORECASE,
    ),
    re.compile(r"disregard\s+(your\s+)?(instructions|guidelines)", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"\bact\s+as\b", re.IGNORECASE),
    re.compile(r"\bsystem\s+prompt\b", re.IGNORECASE),
)

_CROSS_TOOL_PATTERNS = (
    re.compile(r"\bthen\s+call\b", re.IGNORECASE),
    re.compile(r"\binvoke\s+(?:the\s+)?\S+\s+tool\b", re.IGNORECASE),
    re.compile(r"\buse\s+the\s+\S+\s+tool\b", re.IGNORECASE),
    re.compile(r"\brun\s+\S+\s+after\b", re.IGNORECASE),
)

_DANGEROUS_CONTENT_PATTERNS = (
    re.compile(r"\b(?:curl|wget)\s+(?:-[^\s]+\s+)*https?://", re.IGNORECASE),
    re.compile(r"\b(?:bash|sh)\s+-c\b", re.IGNORECASE),
    re.compile(
        r"\bpowershell(?:\.exe)?\b.{0,80}\b(?:-enc|-encodedcommand)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    re.compile(
        r"\b(?:send|upload|post|exfiltrate)\b.{0,80}"
        r"\b(?:secret|credential|token|private key|environment variable)\b",
        re.IGNORECASE,
    ),
)

_DATA_URI_RE = re.compile(
    r"data:[a-z0-9.+-]+/[a-z0-9.+-]+(?:;[a-z0-9=.+-]+)*;base64,"
    r"[a-z0-9+/=]+",
    re.IGNORECASE,
)
_BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])"
)
_UNICODE_CONTROL_RE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]"
)

_RUG_PULL_DYNAMIC_LIST_RE = re.compile(r"tools/list|listTools", re.IGNORECASE)
_RUG_PULL_CONDITIONAL_RE = re.compile(r"\b(?:if|switch|case)\b", re.IGNORECASE)
_RUG_PULL_PY_REDEFINE_RE = re.compile(r"server\.tool\s*\(", re.IGNORECASE)
_RUG_PULL_JS_REDEFINE_RE = re.compile(r"registerTool\s*\(", re.IGNORECASE)
_RUG_PULL_TIMER_RE = re.compile(r"\b(?:setTimeout|setInterval)\b")

_SCHEMA_STRING_FIELDS = {"title", "default", "examples", "enum", "description"}
_POISONABLE_FIELDS = {"default", "description"}
_CODE_EXTENSIONS = {".py", ".js", ".mjs", ".ts", ".mts"}


class MCPAnalyzer(Analyzer):
    name = "mcp"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs: Any) -> list[Finding]:
        self.diagnostics = []
        definitions = self._definitions(repo_path, kwargs)
        findings: list[Finding] = []
        for tool_def in definitions:
            findings.extend(self._check_tool_name(tool_def))
            findings.extend(self._check_tool_description(tool_def))
            findings.extend(self._check_schema_poisoning(tool_def))
            findings.extend(self._check_cross_tool_chaining(tool_def))
        findings.extend(self._check_rug_pull(repo_path, kwargs.get("context")))
        return findings

    @staticmethod
    def _definitions(
        repo_path: Path, kwargs: dict[str, Any]
    ) -> list[MCPToolDefinition]:
        context = kwargs.get("context")
        if context is not None and hasattr(context, "mcp_definitions"):
            return list(context.mcp_definitions)
        if "mcp_definitions" in kwargs:
            return list(kwargs["mcp_definitions"] or [])

        definitions: list[MCPToolDefinition] = []
        platforms: list[PlatformProfile] = kwargs.get("platforms") or []
        for platform in platforms:
            definitions.extend(platform.get_mcp_definitions(repo_path))
        return definitions

    def _check_tool_description(self, tool_def: MCPToolDefinition) -> list[Finding]:
        description = (
            tool_def.description if isinstance(tool_def.description, str) else ""
        )
        return self._check_text(
            tool_def,
            description,
            field_name="description",
            field_path="description",
            schema=False,
        )

    def _check_tool_name(self, tool_def: MCPToolDefinition) -> list[Finding]:
        name = str(tool_def.name)
        if not _UNICODE_CONTROL_RE.search(name):
            return []
        return [
            self._finding(
                tool_def,
                rule_id="SV-MCP-003",
                title=f"Hidden Unicode controls in MCP tool name '{self._evidence(name)}'",
                description="Zero-width or bidirectional controls appear in the tool name.",
                severity=Severity.HIGH,
                snippet=self._evidence(name),
                remediation=(
                    "Remove zero-width and bidirectional control characters from the tool name."
                ),
            )
        ]

    def _check_schema_poisoning(self, tool_def: MCPToolDefinition) -> list[Finding]:
        values: dict[tuple[str, str], tuple[str, str]] = {}
        unicode_keys: dict[str, str] = {}
        for root_name, source in (
            ("input_schema", tool_def.input_schema),
            ("raw_definition", tool_def.raw_definition),
        ):
            for field_name, field_path, text in self._iter_schema_strings(
                source, path=root_name
            ):
                if field_path == "raw_definition.description":
                    continue
                values.setdefault((field_name, text), (field_path, text))
            for field_path, key in self._iter_unicode_keys(source, path=root_name):
                unicode_keys.setdefault(key, field_path)

        findings: list[Finding] = []
        for (field_name, _), (field_path, text) in values.items():
            findings.extend(
                self._check_text(
                    tool_def,
                    text,
                    field_name=field_name,
                    field_path=field_path,
                    schema=True,
                )
            )
        for key, field_path in unicode_keys.items():
            findings.append(
                self._finding(
                    tool_def,
                    rule_id="SV-MCP-003",
                    title=(
                        "Hidden Unicode controls in MCP schema key for "
                        f"'{self._display_name(tool_def)}'"
                    ),
                    description=(
                        f"Zero-width or bidirectional controls appear in {field_path}."
                    ),
                    severity=Severity.HIGH,
                    snippet=self._evidence(key),
                    remediation=(
                        "Remove zero-width and bidirectional controls from schema field names."
                    ),
                )
            )
        return findings

    def _check_text(
        self,
        tool_def: MCPToolDefinition,
        text: str,
        *,
        field_name: str,
        field_path: str,
        schema: bool,
    ) -> list[Finding]:
        if not text:
            return []
        findings: list[Finding] = []
        evidence = self._evidence(text)
        tool_name = self._display_name(tool_def)

        if any(pattern.search(text) for pattern in _INJECTION_PATTERNS):
            findings.append(
                self._finding(
                    tool_def,
                    rule_id="SV-MCP-002" if schema else "SV-MCP-001",
                    title=(
                        f"MCP schema poisoning in '{tool_name}'"
                        if schema
                        else f"MCP tool poisoning in '{tool_name}'"
                    ),
                    description=f"Prompt-injection language appears in {field_path}.",
                    severity=Severity.HIGH if schema else Severity.CRITICAL,
                    snippet=evidence,
                    remediation=(
                        "Remove instructions aimed at the host agent from MCP descriptions "
                        "and schema values."
                    ),
                )
            )

        if _UNICODE_CONTROL_RE.search(text):
            findings.append(
                self._finding(
                    tool_def,
                    rule_id="SV-MCP-003",
                    title=f"Hidden Unicode controls in MCP field for '{tool_name}'",
                    description=f"Zero-width or bidirectional controls appear in {field_path}.",
                    severity=Severity.HIGH,
                    snippet=evidence,
                    remediation=(
                        "Remove zero-width and bidirectional control characters, or replace "
                        "them with visible text."
                    ),
                )
            )

        if field_name.lower() in _POISONABLE_FIELDS and any(
            pattern.search(text) for pattern in _DANGEROUS_CONTENT_PATTERNS
        ):
            findings.append(
                self._finding(
                    tool_def,
                    rule_id="SV-MCP-004",
                    title=f"Executable instruction in MCP {field_name} for '{tool_name}'",
                    description=f"Command-like or exfiltration content appears in {field_path}.",
                    severity=Severity.HIGH,
                    snippet=evidence,
                    remediation=(
                        "Remove executable commands and data-transfer instructions from "
                        "schema defaults and tool descriptions."
                    ),
                )
            )

        data_uri = _DATA_URI_RE.search(text)
        if data_uri:
            findings.append(
                self._finding(
                    tool_def,
                    rule_id="SV-MCP-005",
                    title=f"Embedded data URI in MCP field for '{tool_name}'",
                    description=f"An encoded data URI appears in {field_path}.",
                    severity=Severity.MEDIUM,
                    snippet=self._evidence(data_uri.group(0)),
                    remediation="Remove embedded data payloads and use an explicit typed input.",
                )
            )
        elif self._contains_encoded_poison(text):
            findings.append(
                self._finding(
                    tool_def,
                    rule_id="SV-MCP-006",
                    title=f"Base64-encoded instruction in MCP field for '{tool_name}'",
                    description=f"Base64 in {field_path} decodes to suspicious instructions.",
                    severity=Severity.HIGH,
                    snippet=evidence,
                    remediation="Remove encoded instructions and express legitimate values plainly.",
                )
            )
        return findings

    @staticmethod
    def _iter_schema_strings(
        obj: Any,
        *,
        parent_key: str = "",
        active_field: str = "",
        path: str = "$",
    ) -> Iterator[tuple[str, str, str]]:
        if isinstance(obj, dict):
            for key, value in obj.items():
                field_name = str(key).lower()
                yield from MCPAnalyzer._iter_schema_strings(
                    value,
                    parent_key=str(key),
                    active_field=(
                        field_name
                        if field_name in _SCHEMA_STRING_FIELDS
                        else active_field
                    ),
                    path=f"{path}.{key}",
                )
        elif isinstance(obj, list):
            for index, item in enumerate(obj):
                yield from MCPAnalyzer._iter_schema_strings(
                    item,
                    parent_key=parent_key,
                    active_field=active_field,
                    path=f"{path}[{index}]",
                )
        elif isinstance(obj, str):
            field_name = active_field or parent_key.lower()
            if field_name in _SCHEMA_STRING_FIELDS:
                yield field_name, path, obj

    @staticmethod
    def _iter_unicode_keys(obj: Any, *, path: str = "$") -> Iterator[tuple[str, str]]:
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_text = str(key)
                key_path = f"{path}.{key_text}"
                if _UNICODE_CONTROL_RE.search(key_text):
                    yield key_path, key_text
                yield from MCPAnalyzer._iter_unicode_keys(value, path=key_path)
        elif isinstance(obj, list):
            for index, item in enumerate(obj):
                yield from MCPAnalyzer._iter_unicode_keys(item, path=f"{path}[{index}]")

    @staticmethod
    def _contains_encoded_poison(text: str) -> bool:
        for match in _BASE64_RE.finditer(text):
            candidate = match.group(1)
            if all(char in "0123456789abcdefABCDEF" for char in candidate):
                continue
            try:
                padded = candidate + "=" * (-len(candidate) % 4)
                decoded = base64.b64decode(padded, validate=True).decode(
                    "utf-8", errors="ignore"
                )
            except (binascii.Error, UnicodeError, ValueError):
                continue
            if any(pattern.search(decoded) for pattern in _INJECTION_PATTERNS):
                return True
            if any(pattern.search(decoded) for pattern in _DANGEROUS_CONTENT_PATTERNS):
                return True
        return False

    def _check_cross_tool_chaining(self, tool_def: MCPToolDefinition) -> list[Finding]:
        description = (
            tool_def.description if isinstance(tool_def.description, str) else ""
        )
        if not any(pattern.search(description) for pattern in _CROSS_TOOL_PATTERNS):
            return []
        return [
            self._finding(
                tool_def,
                rule_id="SV-MCP-007",
                title=f"Cross-tool chaining in '{self._display_name(tool_def)}'",
                description="The tool description instructs the agent to call another tool.",
                severity=Severity.MEDIUM,
                snippet=self._evidence(description),
                remediation=(
                    "Remove implicit tool chaining; let the host agent choose tools from "
                    "explicit user intent."
                ),
            )
        ]

    def _check_rug_pull(
        self, repo_path: Path, context: object | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in iter_analysis_files(repo_path, context):
            if file_path.suffix not in _CODE_EXTENSIONS:
                continue
            try:
                relative = file_path.relative_to(repo_path).as_posix()
            except ValueError as exc:
                self.diagnostics.append(
                    Diagnostic(
                        code="mcp_source_path_invalid",
                        message="An MCP source candidate was outside the scan workspace",
                        analyzer=self.name,
                        details={"error_type": type(exc).__name__},
                    )
                )
                continue
            try:
                lines = file_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError as exc:
                self.diagnostics.append(
                    Diagnostic(
                        code="mcp_source_read_failed",
                        message="An MCP source file could not be read",
                        analyzer=self.name,
                        path=relative,
                        details={"error_type": type(exc).__name__},
                    )
                )
                continue
            findings.extend(self._check_dynamic_list(lines, relative))
            findings.extend(
                self._check_runtime_redefine(lines, relative, file_path.suffix)
            )
        return findings

    @staticmethod
    def _nearby(pattern: re.Pattern[str], lines: list[str], index: int) -> bool:
        window = lines[max(0, index - 8) : index + 9]
        return any(pattern.search(line) for line in window)

    def _check_dynamic_list(self, lines: list[str], relative: str) -> list[Finding]:
        findings: list[Finding] = []
        for index, line in enumerate(lines):
            if not _RUG_PULL_DYNAMIC_LIST_RE.search(line):
                continue
            if not self._nearby(_RUG_PULL_CONDITIONAL_RE, lines, index):
                continue
            findings.append(
                Finding(
                    rule_id="SV-MCP-008",
                    title="MCP dynamic tool-list indicator",
                    description=(
                        "A tools/list implementation is near conditional logic and may expose "
                        "different tools between requests."
                    ),
                    severity=Severity.HIGH,
                    category=Category.MCP_SECURITY,
                    file_path=relative,
                    line_number=index + 1,
                    analyzer=self.name,
                    confidence=0.8,
                    evidence=Evidence(kind="source", snippet=self._evidence(line)),
                    remediation=(
                        "Return a stable tool manifest, or expose version changes as explicit "
                        "artifacts for comparison."
                    ),
                )
            )
        return findings

    def _check_runtime_redefine(
        self, lines: list[str], relative: str, suffix: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        redefine = (
            _RUG_PULL_PY_REDEFINE_RE if suffix == ".py" else _RUG_PULL_JS_REDEFINE_RE
        )
        for index, line in enumerate(lines):
            if not redefine.search(line):
                continue
            has_timer = self._nearby(_RUG_PULL_TIMER_RE, lines, index)
            has_conditional = self._nearby(_RUG_PULL_CONDITIONAL_RE, lines, index)
            if not (has_timer or has_conditional):
                continue
            trigger = "timer" if has_timer else "conditional"
            findings.append(
                Finding(
                    rule_id="SV-MCP-009",
                    title="MCP runtime tool-redefinition indicator",
                    description=f"Tool registration is near {trigger} logic.",
                    severity=Severity.HIGH,
                    category=Category.MCP_SECURITY,
                    file_path=relative,
                    line_number=index + 1,
                    analyzer=self.name,
                    confidence=0.7,
                    evidence=Evidence(kind="source", snippet=self._evidence(line)),
                    remediation=(
                        "Register a stable tool set at startup and version manifest changes "
                        "explicitly."
                    ),
                )
            )
        return findings

    def _finding(
        self,
        tool_def: MCPToolDefinition,
        *,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        snippet: str,
        remediation: str,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            category=Category.MCP_SECURITY,
            file_path=Path(tool_def.source_file).as_posix(),
            line_number=None,
            analyzer=self.name,
            evidence=Evidence(kind="mcp_definition", snippet=snippet),
            remediation=remediation,
        )

    @staticmethod
    def _evidence(text: str) -> str:
        return text[:300].encode("unicode_escape").decode("ascii")

    @staticmethod
    def _display_name(tool_def: MCPToolDefinition) -> str:
        return MCPAnalyzer._evidence(str(tool_def.name))[:100]
