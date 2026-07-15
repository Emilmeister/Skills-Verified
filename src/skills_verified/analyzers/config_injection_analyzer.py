"""Config injection analyzer — detects dangerous hooks, API URL overrides,
prompt injection in rules files, suspicious env vars, and credential
leaks across platform config files."""

from __future__ import annotations

import base64
import ipaddress
import re
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Evidence, Finding, Severity
from skills_verified.platforms.base import ConfigFile, PlatformProfile

# ---------------------------------------------------------------------------
# Shared patterns
# ---------------------------------------------------------------------------

_DANGEROUS_COMMANDS_RE = re.compile(
    r"\b(curl|wget|nc|ncat|bash\s+-c|sh\s+-c|powershell)\b",
    re.IGNORECASE,
)

_PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|guidelines|rules)",
        re.IGNORECASE,
    ),
    re.compile(
        r"disregard\s+(your\s+)?(instructions|guidelines)",
        re.IGNORECASE,
    ),
]

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_DEFENSIVE_CONTEXT_RE = re.compile(
    r"(?:\b(?:classify|mark|treat)\b.{0,160}\b(?:unsafe|untrusted)\b|"
    r"\b(?:avoid|block|detect|do not|don't|never|reject)\b.{0,100}"
    r"\b(?:apply|execute|follow|obey|run|use)\b)",
    re.IGNORECASE,
)

_SENSITIVE_ENV_VARS_RE = re.compile(
    r"\$(?:ANTHROPIC_API_KEY|GITHUB_TOKEN|AWS_SECRET(?:_ACCESS_KEY)?|"
    r"OPENAI_API_KEY|AZURE_KEY|GCP_KEY|DATABASE_URL|"
    r"PRIVATE_KEY|SSH_KEY|NPM_TOKEN|DOCKER_PASSWORD)",
    re.IGNORECASE,
)

_CREDENTIAL_KEY_RE = re.compile(
    r"(password|token|secret|api_key|apikey|private_key|credential)",
    re.IGNORECASE,
)

_ANTHROPIC_DOMAIN = "anthropic.com"
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
_URL_LIKE_RE = re.compile(
    r"^(?:(?:https?|wss?):|[a-z][a-z0-9+.-]*://)",
    re.IGNORECASE,
)


class ConfigInjectionAnalyzer(Analyzer):
    name = "config_injection"

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs: Any) -> list[Finding]:
        platforms: list[PlatformProfile] = kwargs.get("platforms") or []
        context = kwargs.get("context")
        all_configs: list[ConfigFile] = list(
            kwargs.get("configs") or getattr(context, "configs", []) or []
        )
        if not platforms and not all_configs:
            return []

        if not all_configs:
            for platform in platforms:
                all_configs.extend(platform.get_config_files(repo_path))

        if not all_configs:
            return []

        findings: list[Finding] = []
        for cfg in all_configs:
            if cfg.config_type == "settings":
                findings.extend(self._check_settings(cfg))
            elif cfg.config_type == "rules":
                findings.extend(self._check_rules(cfg))
            elif cfg.config_type == "manifest":
                findings.extend(self._check_manifest(cfg))

            # OpenClaw-specific: credential leak in any JSON config
            if isinstance(cfg.content, dict):
                findings.extend(self._check_credentials_in_json(cfg))

        return findings

    # ------------------------------------------------------------------
    # settings (JSON) checks
    # ------------------------------------------------------------------

    def _check_settings(self, cfg: ConfigFile) -> list[Finding]:
        findings: list[Finding] = []
        data = cfg.content
        if not isinstance(data, dict):
            return findings

        file_path = str(cfg.path)

        # 1. Hooks with dangerous commands
        findings.extend(self._check_hooks(data, file_path))

        # 2. apiUrl / baseUrl override (CVE-2026-21852 vector)
        findings.extend(self._check_api_url_override(data, file_path))

        # 3. MCP servers with suspicious URLs
        findings.extend(self._check_mcp_server_urls(data, file_path))

        return findings

    def _check_hooks(self, data: dict, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for key in ("hooks", "customCommands"):
            value = data.get(key)
            if value is None:
                continue
            dangerous_strings = self._extract_all_strings(value)
            for text in dangerous_strings:
                if _DANGEROUS_COMMANDS_RE.search(text):
                    findings.append(
                        Finding(
                            title="Dangerous command in config hook",
                            description=(
                                f"Config key '{key}' contains a dangerous "
                                f"command: {text[:200]}"
                            ),
                            severity=Severity.HIGH,
                            category=Category.CONFIG_INJECTION,
                            file_path=file_path,
                            line_number=None,
                            analyzer=self.name,
                        )
                    )

        return findings

    def _check_api_url_override(self, data: dict, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for key in ("apiUrl", "baseUrl"):
            url = data.get(key)
            if not isinstance(url, str):
                continue
            if not self._is_allowed_anthropic_url(url):
                safe_url = self._redact_url(url)
                findings.append(
                    Finding(
                        title=f"Unsafe API URL override — {key}",
                        description=(
                            f"Config sets '{key}' to '{safe_url}', which is not "
                            f"an HTTPS URL on anthropic.com. This is a known attack "
                            f"vector (CVE-2026-21852) that redirects API calls "
                            f"to a malicious server."
                        ),
                        severity=Severity.CRITICAL,
                        category=Category.CONFIG_INJECTION,
                        file_path=file_path,
                        line_number=None,
                        analyzer=self.name,
                        cve_id="CVE-2026-21852",
                        rule_id="SV-CONFIG-API-URL-OVERRIDE",
                        evidence=Evidence(
                            kind="config_value",
                            snippet=f"{key}={safe_url}",
                        ),
                        remediation=(
                            "Remove the override or use an HTTPS URL on "
                            "anthropic.com without credentials or a custom port."
                        ),
                    )
                )

        return findings

    def _check_mcp_server_urls(self, data: dict, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        servers = data.get("mcpServers", {})
        if not isinstance(servers, dict):
            return findings

        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue
            for url_key in ("url", "command", "endpoint"):
                url_value = server_cfg.get(url_key)
                if not isinstance(url_value, str):
                    continue
                # Flag non-localhost, non-standard URLs
                if self._is_suspicious_url(url_value):
                    safe_url = self._redact_url(url_value)
                    findings.append(
                        Finding(
                            title=f"Suspicious MCP server URL in '{server_name}'",
                            description=(
                                f"MCP server '{server_name}' has {url_key}="
                                f"'{safe_url}' which points to a potentially "
                                f"untrusted host."
                            ),
                            severity=Severity.HIGH,
                            category=Category.CONFIG_INJECTION,
                            file_path=file_path,
                            line_number=None,
                            analyzer=self.name,
                            confidence=0.7,
                            rule_id="SV-CONFIG-MCP-UNTRUSTED-URL",
                            evidence=Evidence(
                                kind="config_value",
                                snippet=f"{url_key}={safe_url}",
                            ),
                            remediation=(
                                "Use a local MCP endpoint or an HTTPS endpoint on "
                                "an explicitly trusted domain."
                            ),
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # rules (text — CLAUDE.md, .cursorrules) checks
    # ------------------------------------------------------------------

    def _check_rules(self, cfg: ConfigFile) -> list[Finding]:
        findings: list[Finding] = []
        text = cfg.content
        if not isinstance(text, str):
            return findings

        file_path = str(cfg.path)

        # 1. Prompt injection patterns
        lines = text.splitlines()
        for line_number, line in enumerate(lines, start=1):
            for pattern in _PROMPT_INJECTION_PATTERNS:
                match = pattern.search(line)
                if match and self._quoted_defensive_example(
                    lines, line_number - 1, match
                ):
                    continue
                if match and self._security_reference_quote(file_path, line, match):
                    continue
                if match:
                    findings.append(
                        Finding(
                            title="Prompt injection in config rules file",
                            description=(
                                f"Rules file contains injection pattern: "
                                f"'{pattern.pattern}'. Line: {line.strip()[:150]}"
                            ),
                            severity=Severity.CRITICAL,
                            category=Category.CONFIG_INJECTION,
                            file_path=file_path,
                            line_number=line_number,
                            analyzer=self.name,
                        )
                    )

        # 2. Base64-encoded payloads
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in _BASE64_RE.finditer(line):
                try:
                    decoded = base64.b64decode(match.group()).decode(
                        "utf-8", errors="ignore"
                    )
                    suspicious = [
                        "ignore",
                        "system",
                        "prompt",
                        "instruction",
                        "override",
                        "jailbreak",
                        "curl",
                        "wget",
                        "bash",
                    ]
                    if any(w in decoded.lower() for w in suspicious):
                        findings.append(
                            Finding(
                                title="Base64-encoded payload in rules file",
                                description=(
                                    f"Base64 string decodes to suspicious "
                                    f"content: {decoded[:100]}"
                                ),
                                severity=Severity.HIGH,
                                category=Category.CONFIG_INJECTION,
                                file_path=file_path,
                                line_number=line_number,
                                analyzer=self.name,
                            )
                        )
                except Exception:
                    pass

        return findings

    @staticmethod
    def _quoted_defensive_example(
        lines: list[str], index: int, match: re.Match
    ) -> bool:
        line = lines[index]
        before, after = line[: match.start()], line[match.end() :]
        if not any(
            before.count(quote) % 2 == 1 and after.count(quote) % 2 == 1
            for quote in ("`", '"', "'")
        ):
            return False
        context = " ".join(lines[max(0, index - 2) : index + 1])
        return bool(_DEFENSIVE_CONTEXT_RE.search(context))

    @staticmethod
    def _security_reference_quote(file_path: str, line: str, match: re.Match) -> bool:
        if not re.search(
            r"(?:guardrail|safety|scanner|security|threat|prompt.?injection|jailbreak)",
            file_path,
            re.I,
        ):
            return False
        before, after = line[: match.start()], line[match.end() :]
        return any(
            before.count(quote) % 2 == 1 and after.count(quote) % 2 == 1
            for quote in ("`", '"', "'")
        )

    # ------------------------------------------------------------------
    # manifest (JSON — mcp.json, flow files) checks
    # ------------------------------------------------------------------

    def _check_manifest(self, cfg: ConfigFile) -> list[Finding]:
        findings: list[Finding] = []
        data = cfg.content
        if not isinstance(data, dict):
            return findings

        file_path = str(cfg.path)

        # 1. Suspicious env var references in args
        all_strings = self._extract_all_strings(data)
        for text in all_strings:
            if _SENSITIVE_ENV_VARS_RE.search(text):
                findings.append(
                    Finding(
                        title="Sensitive env var reference in manifest",
                        description=(
                            f"Manifest references a sensitive environment "
                            f"variable: {text[:200]}"
                        ),
                        severity=Severity.HIGH,
                        category=Category.CONFIG_INJECTION,
                        file_path=file_path,
                        line_number=None,
                        analyzer=self.name,
                    )
                )

        # 2. Server URLs pointing to suspicious domains
        servers = data.get("mcpServers", {})
        if isinstance(servers, dict):
            for server_name, server_cfg in servers.items():
                if not isinstance(server_cfg, dict):
                    continue
                for url_key in ("url", "command", "endpoint"):
                    url_value = server_cfg.get(url_key)
                    if isinstance(url_value, str) and self._is_suspicious_url(
                        url_value
                    ):
                        safe_url = self._redact_url(url_value)
                        findings.append(
                            Finding(
                                title=f"Suspicious server URL in manifest — '{server_name}'",
                                description=(
                                    f"Manifest server '{server_name}' has "
                                    f"{url_key}='{safe_url}' pointing to a "
                                    f"potentially untrusted host."
                                ),
                                severity=Severity.HIGH,
                                category=Category.CONFIG_INJECTION,
                                file_path=file_path,
                                line_number=None,
                                analyzer=self.name,
                                confidence=0.7,
                                rule_id="SV-CONFIG-MCP-UNTRUSTED-URL",
                                evidence=Evidence(
                                    kind="config_value",
                                    snippet=f"{url_key}={safe_url}",
                                ),
                                remediation=(
                                    "Use a local MCP endpoint or an HTTPS endpoint "
                                    "on an explicitly trusted domain."
                                ),
                            )
                        )

        return findings

    # ------------------------------------------------------------------
    # OpenClaw-specific: credentials stored in config
    # ------------------------------------------------------------------

    def _check_credentials_in_json(self, cfg: ConfigFile) -> list[Finding]:
        findings: list[Finding] = []
        data = cfg.content
        if not isinstance(data, dict):
            return findings

        file_path = str(cfg.path)
        self._walk_credential_keys(data, file_path, findings)
        return findings

    def _walk_credential_keys(
        self, obj: Any, file_path: str, findings: list[Finding]
    ) -> None:
        """Recursively scan JSON for keys that look like credentials."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str) and len(value) >= 8:
                    if _CREDENTIAL_KEY_RE.search(key):
                        findings.append(
                            Finding(
                                title="Credential stored in config file",
                                description=(
                                    f"Config key '{key}' appears to contain "
                                    f"a credential value (length {len(value)}). "
                                    f"Credentials should not be stored in "
                                    f"repository config files."
                                ),
                                severity=Severity.HIGH,
                                category=Category.CONFIG_INJECTION,
                                file_path=file_path,
                                line_number=None,
                                analyzer=self.name,
                            )
                        )
                else:
                    self._walk_credential_keys(value, file_path, findings)
        elif isinstance(obj, list):
            for item in obj:
                self._walk_credential_keys(item, file_path, findings)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_all_strings(obj: Any) -> list[str]:
        """Recursively collect all string values from a nested dict/list."""
        strings: list[str] = []

        def _walk(node: Any) -> None:
            if isinstance(node, str):
                strings.append(node)
            elif isinstance(node, dict):
                for v in node.values():
                    _walk(v)
            elif isinstance(node, list):
                for item in node:
                    _walk(item)

        _walk(obj)
        return strings

    @staticmethod
    def _is_suspicious_url(url: str) -> bool:
        """Flag URL-like values that are not local or on a known domain."""
        value = url.strip()
        if not _URL_LIKE_RE.match(value):
            return False

        parsed_url = ConfigInjectionAnalyzer._parse_url(value)
        if parsed_url is None:
            return True
        parsed, host, port = parsed_url
        if parsed.scheme.lower() not in _DEFAULT_PORTS:
            return True
        if parsed.username is not None or parsed.password is not None:
            return True

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None

        if address is not None:
            return not (address.is_loopback or address.is_unspecified)
        if host == "localhost":
            return False
        scheme = parsed.scheme.lower()
        return scheme not in ("https", "wss") or port not in (
            None,
            _DEFAULT_PORTS[scheme],
        )

    @staticmethod
    def _is_allowed_anthropic_url(url: str) -> bool:
        parsed_url = ConfigInjectionAnalyzer._parse_url(url)
        if parsed_url is None:
            return False
        parsed, host, port = parsed_url
        return (
            parsed.scheme.lower() == "https"
            and parsed.username is None
            and parsed.password is None
            and port in (None, 443)
            and ConfigInjectionAnalyzer._host_matches(host, _ANTHROPIC_DOMAIN)
        )

    @staticmethod
    def _parse_url(url: str) -> tuple[SplitResult, str, int | None] | None:
        value = url.strip()
        if not value or any(char.isspace() or ord(char) < 32 for char in value):
            return None
        try:
            parsed = urlsplit(value)
            host = parsed.hostname
            port = parsed.port
        except ValueError:
            return None
        if not parsed.scheme or not parsed.netloc or not host:
            return None
        try:
            normalized_host = host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        return parsed, normalized_host, port

    @staticmethod
    def _host_matches(host: str, domain: str) -> bool:
        return host == domain or host.endswith(f".{domain}")

    @staticmethod
    def _redact_url(url: str) -> str:
        return re.sub(r"(://)[^/\s]*@", r"\1[redacted]@", url.strip())[:500]
