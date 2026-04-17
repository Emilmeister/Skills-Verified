import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

SCAN_EXTENSIONS = {
    ".py", ".js", ".mjs", ".ts", ".tsx", ".jsx",
    ".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".env",
}
# Code and config files only — docs (.md/.txt) produce noisy `org/name` false
# positives from API-reference tables and prose.
MODEL_REF_EXTENSIONS = {
    ".py", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".sh", ".rb",
    ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".env",
}
PROMPT_EXTENSIONS = {".md", ".txt"}

# Known HuggingFace organisations — new candidates outside this set are
# rejected to suppress regex noise from arbitrary `word/word` fragments.
HF_ORGS_WHITELIST = {
    "meta-llama", "mistralai", "BAAI", "sentence-transformers",
    "Qwen", "deepseek-ai", "google", "microsoft", "openai-community",
    "stabilityai", "tiiuae", "NousResearch", "HuggingFaceH4", "CohereForAI",
    "intfloat", "THUDM", "bigscience", "EleutherAI", "allenai",
    "Salesforce", "facebook", "nvidia", "apple", "ibm-granite",
    "openchat", "teknium", "WizardLM", "01-ai", "xai-org",
    "t-tech", "ai-forever", "IlyaGusev", "cointegrated",
    "thenlper", "Alibaba-NLP", "nomic-ai", "jinaai", "mixedbread-ai", "Snowflake",
}

OPENAI_MODEL_RX = re.compile(
    r"\b(gpt-4[a-z0-9.\-]*|gpt-3\.5-turbo[a-z0-9.\-]*|o1-mini|o1-preview|o3-mini)\b"
)
ANTHROPIC_MODEL_RX = re.compile(r"\bclaude-[a-z0-9.\-]+\b")
HF_MODEL_RX = re.compile(r"\b([A-Za-z0-9_\-]{2,}/[A-Za-z0-9._\-]{2,})\b")
HF_CONTEXT_RX = re.compile(
    r"huggingface|transformers|from_pretrained|sentence-transformers|bge[\-_]", re.IGNORECASE
)
EMBEDDING_RX = re.compile(
    r"\b("
    # HuggingFace embedding families (org/model)
    r"sentence-transformers/[A-Za-z0-9._\-]+|"
    r"BAAI/bge[\-_][A-Za-z0-9._\-]+|"
    r"Qwen/Qwen[23](?:\.\d+)?-Embedding[A-Za-z0-9._\-]*|"
    r"intfloat/(?:multilingual-)?e5-[A-Za-z0-9._\-]+|"
    r"(?:thenlper|Alibaba-NLP)/gte-[A-Za-z0-9._\-]+|"
    r"nomic-ai/nomic-embed-[A-Za-z0-9._\-]+|"
    r"jinaai/jina-embeddings-[A-Za-z0-9._\-]+|"
    r"mixedbread-ai/mxbai-embed-[A-Za-z0-9._\-]+|"
    r"Snowflake/snowflake-arctic-embed-[A-Za-z0-9._\-]+|"
    r"cointegrated/(?:LaBSE[A-Za-z0-9._\-]*|rubert-[A-Za-z0-9._\-]+)|"
    r"google/embeddinggemma-[A-Za-z0-9._\-]+|"
    # API-based embedding providers
    r"text-embedding-[23]-(?:small|large)|"
    r"text-embedding-ada-\d+|"
    r"text-embedding-gecko(?:-\d+)?|"
    r"voyage-[A-Za-z0-9.\-]+|"
    r"embed-(?:english|multilingual)(?:-light)?-v\d+(?:\.\d+)?"
    r")\b"
)
# Heuristic: treat a model_id as an embedding if its name carries embedding hallmarks.
# Used to reroute HF whitelist-matched models whose regex-match didn't land in EMBEDDING_RX.
_EMBEDDING_HALLMARKS = (
    "embed", "embedding", "rerank", "reranker",
    "bge-", "gte-", "e5-", "labse", "rubert", "mpnet", "minilm",
    "sentence-", "arctic-embed", "nomic-embed",
)
SYSTEM_PROMPT_TEXT_RX = re.compile(r"\b(you are (?:a|an|the)|your role is)\b", re.IGNORECASE)
SYSTEM_PROMPT_CODE_RX = re.compile(
    r"\b(system_prompt|SYSTEM_PROMPT)\b|\"role\"\s*:\s*\"system\""
)
EXTERNAL_ENDPOINT_RX = re.compile(
    r"\b(api\.openai\.com|api\.anthropic\.com|[A-Za-z0-9.\-]+\.huggingface\.co)\b"
)

MCP_CONFIG_GLOBS = [
    "mcp.json",
    ".mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".codex/config.toml",
]


@dataclass
class AiModelRef:
    model_id: str
    provider: str
    occurrences: list[tuple[str, int]] = field(default_factory=list)  # (file, line)
    pinned_version: bool = False


@dataclass
class McpServerRef:
    name: str
    command: str | None
    args: list[str] = field(default_factory=list)
    env_keys: list[str] = field(default_factory=list)
    source_file: str = ""
    has_auth: bool = False


@dataclass
class SystemPromptRef:
    file_path: str
    line_number: int
    snippet: str


@dataclass
class EndpointRef:
    endpoint: str
    file_path: str
    line_number: int


@dataclass
class AibomInventory:
    models: list[AiModelRef] = field(default_factory=list)
    mcp_servers: list[McpServerRef] = field(default_factory=list)
    system_prompts: list[SystemPromptRef] = field(default_factory=list)
    endpoints: list[EndpointRef] = field(default_factory=list)
    embeddings: list[AiModelRef] = field(default_factory=list)


class AibomAnalyzer(Analyzer):
    name = "aibom"

    def __init__(self, strict: bool = False, risk_registry=None):
        self.strict = strict
        self.risk_registry = risk_registry
        self._last_inventory: AibomInventory | None = None

    def is_available(self) -> bool:
        return True

    @property
    def last_inventory(self) -> AibomInventory | None:
        return self._last_inventory

    def analyze(self, repo_path: Path) -> list[Finding]:
        inventory = self.detect(repo_path)
        self._last_inventory = inventory
        findings = self._to_findings(inventory)
        if self.risk_registry is not None:
            self.risk_registry.enrich_findings(findings)
        return findings

    def detect(self, repo_path: Path) -> AibomInventory:
        inv = AibomInventory()
        model_index: dict[tuple[str, str], AiModelRef] = {}
        embedding_index: dict[tuple[str, str], AiModelRef] = {}
        endpoint_seen: set[tuple[str, str, int]] = set()

        for file_path in repo_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix not in SCAN_EXTENSIONS:
                continue
            try:
                content = file_path.read_text(errors="ignore")
            except OSError:
                continue
            rel = str(file_path.relative_to(repo_path))

            for line_number, line in enumerate(content.splitlines(), start=1):
                for m in OPENAI_MODEL_RX.finditer(line):
                    self._route(model_index, embedding_index, m.group(0), "openai", rel, line_number)
                for m in ANTHROPIC_MODEL_RX.finditer(line):
                    self._route(model_index, embedding_index, m.group(0), "anthropic", rel, line_number)
                if (
                    file_path.suffix in MODEL_REF_EXTENSIONS
                    and HF_CONTEXT_RX.search(content)
                ):
                    for m in HF_MODEL_RX.finditer(line):
                        candidate = m.group(1)
                        if candidate.startswith(("http", "https")):
                            continue
                        org = candidate.split("/", 1)[0]
                        if org not in HF_ORGS_WHITELIST:
                            continue
                        self._route(model_index, embedding_index, candidate, "huggingface", rel, line_number)
                for m in EMBEDDING_RX.finditer(line):
                    self._record_model(embedding_index, m.group(0), _embedding_provider(m.group(0)), rel, line_number)
                for m in EXTERNAL_ENDPOINT_RX.finditer(line):
                    key = (m.group(0), rel, line_number)
                    if key in endpoint_seen:
                        continue
                    endpoint_seen.add(key)
                    inv.endpoints.append(EndpointRef(m.group(0), rel, line_number))

            if file_path.suffix in PROMPT_EXTENSIONS:
                for line_number, line in enumerate(content.splitlines(), start=1):
                    if SYSTEM_PROMPT_TEXT_RX.search(line):
                        inv.system_prompts.append(
                            SystemPromptRef(rel, line_number, line.strip()[:200])
                        )
                        break
            else:
                for line_number, line in enumerate(content.splitlines(), start=1):
                    if SYSTEM_PROMPT_CODE_RX.search(line):
                        inv.system_prompts.append(
                            SystemPromptRef(rel, line_number, line.strip()[:200])
                        )
                        break

        inv.models = list(model_index.values())
        inv.embeddings = list(embedding_index.values())
        inv.mcp_servers = self._detect_mcp_servers(repo_path)
        return inv

    @staticmethod
    def _record_model(
        index: dict,
        model_id: str,
        provider: str,
        file_path: str,
        line_number: int,
    ) -> None:
        key = (provider, model_id)
        if key not in index:
            index[key] = AiModelRef(
                model_id=model_id,
                provider=provider,
                pinned_version=_looks_pinned(model_id),
            )
        index[key].occurrences.append((file_path, line_number))

    @classmethod
    def _route(
        cls,
        model_index: dict,
        embedding_index: dict,
        model_id: str,
        provider: str,
        file_path: str,
        line_number: int,
    ) -> None:
        """Route a model reference to embeddings or models based on name heuristic."""
        target = embedding_index if _looks_like_embedding(model_id) else model_index
        cls._record_model(target, model_id, provider, file_path, line_number)

    def _detect_mcp_servers(self, repo_path: Path) -> list[McpServerRef]:
        servers: list[McpServerRef] = []
        seen: set[str] = set()
        for rel in MCP_CONFIG_GLOBS:
            candidate = repo_path / rel
            if not candidate.is_file():
                continue
            try:
                if candidate.suffix == ".json":
                    data = json.loads(candidate.read_text(errors="ignore"))
                elif candidate.suffix == ".toml":
                    import tomllib
                    data = tomllib.loads(candidate.read_text(errors="ignore"))
                else:
                    continue
            except (OSError, ValueError, json.JSONDecodeError) as e:
                logger.debug("could not parse %s: %s", candidate, e)
                continue
            mcp_section = data.get("mcpServers") or data.get("mcp_servers") or {}
            if not isinstance(mcp_section, dict):
                continue
            for server_name, spec in mcp_section.items():
                if not isinstance(spec, dict):
                    continue
                key = f"{rel}:{server_name}"
                if key in seen:
                    continue
                seen.add(key)
                env = spec.get("env", {}) if isinstance(spec.get("env"), dict) else {}
                has_auth = any(
                    "token" in k.lower() or "key" in k.lower() or "auth" in k.lower()
                    for k in env
                )
                servers.append(
                    McpServerRef(
                        name=server_name,
                        command=spec.get("command"),
                        args=list(spec.get("args", []) or []),
                        env_keys=list(env.keys()),
                        source_file=rel,
                        has_auth=has_auth,
                    )
                )
        return servers

    def _to_findings(self, inv: AibomInventory) -> list[Finding]:
        findings: list[Finding] = []
        info_severity = Severity.INFO
        shadow_severity = Severity.LOW if self.strict else Severity.INFO

        for model in inv.models:
            first_file, first_line = model.occurrences[0] if model.occurrences else (None, None)
            severity = info_severity if model.pinned_version else shadow_severity
            findings.append(Finding(
                title=f"AI model reference: {model.model_id}",
                description=(
                    f"Provider: {model.provider}. "
                    f"Occurrences: {len(model.occurrences)}. "
                    f"Pinned version: {model.pinned_version}."
                ),
                severity=severity,
                category=Category.AI_BOM,
                file_path=first_file,
                line_number=first_line,
                analyzer=self.name,
                confidence=0.6,
            ))

        for emb in inv.embeddings:
            first_file, first_line = emb.occurrences[0] if emb.occurrences else (None, None)
            findings.append(Finding(
                title=f"Embedding model reference: {emb.model_id}",
                description=f"Provider: {emb.provider}.",
                severity=info_severity,
                category=Category.AI_BOM,
                file_path=first_file,
                line_number=first_line,
                analyzer=self.name,
                confidence=0.7,
            ))

        for server in inv.mcp_servers:
            severity = info_severity if server.has_auth else shadow_severity
            findings.append(Finding(
                title=f"MCP server: {server.name}",
                description=(
                    f"Configured in {server.source_file}. "
                    f"Command: {server.command}. "
                    f"Has auth env: {server.has_auth}."
                ),
                severity=severity,
                category=Category.AI_BOM,
                file_path=server.source_file,
                line_number=None,
                analyzer=self.name,
            ))

        for prompt in inv.system_prompts:
            findings.append(Finding(
                title="System prompt detected",
                description=f"Snippet: {prompt.snippet}",
                severity=info_severity,
                category=Category.AI_BOM,
                file_path=prompt.file_path,
                line_number=prompt.line_number,
                analyzer=self.name,
                confidence=0.7,
            ))

        for ep in inv.endpoints:
            findings.append(Finding(
                title=f"External AI endpoint: {ep.endpoint}",
                description="Referenced in config/code.",
                severity=info_severity,
                category=Category.AI_BOM,
                file_path=ep.file_path,
                line_number=ep.line_number,
                analyzer=self.name,
            ))

        return findings


def _looks_pinned(model_id: str) -> bool:
    # Anything with a date-like suffix or numeric version counts as pinned.
    return bool(re.search(r"-\d{4,}|@\d|-\d+\.\d+", model_id))


def _looks_like_embedding(model_id: str) -> bool:
    name = model_id.lower()
    return any(h in name for h in _EMBEDDING_HALLMARKS)


_API_EMBEDDING_PREFIXES = ("text-embedding-", "text-embedding-gecko", "voyage-", "embed-")


def _embedding_provider(model_id: str) -> str:
    if model_id.startswith("text-embedding-") or model_id.startswith("text-embedding-gecko"):
        return "openai" if "gecko" not in model_id else "google"
    if model_id.startswith("voyage-"):
        return "voyage"
    if model_id.startswith("embed-"):
        return "cohere"
    if "/" in model_id:
        return "huggingface"
    return "openai"
