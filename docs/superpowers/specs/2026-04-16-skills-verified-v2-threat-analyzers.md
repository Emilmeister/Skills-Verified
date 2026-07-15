# Skills Verified v2: Threat Analyzers for AI Agent Skill Vulnerabilities

> **Status: Superseded.** Исторический документ; scoring и прежний report contract больше не действуют. Текущий контракт: [Policy-Free Scan Report Roadmap](./2026-07-13-policy-free-scan-report-roadmap.md).

**Date:** 2026-04-16
**Original status:** Approved
**Previous spec:** [2026-04-12-skills-verified-design.md](./2026-04-12-skills-verified-design.md)

## Motivation

Research into the Claude Code / OpenClaw / MCP ecosystem uncovered systemic security threats that the current verifier does not detect:

- **Snyk ToxicSkills**: 534 of 3,984 skills (13.4%) contain critical vulnerabilities; 76 confirmed malicious
- **ClawHavoc**: 341 malicious skills in ClawHub (~12%)
- **CVE-2025-59536** (CVSS 8.7): RCE via hooks/MCP in `.claude/settings.json`
- **CVE-2026-21852** (CVSS 5.3): API key exfiltration via `apiUrl` override
- **CVE-2026-25253** (CVSS 8.8): OpenClaw 1-click RCE via WebSocket hijacking
- **MCP tool poisoning**, rug pull attacks, schema poisoning (Invariant Labs, CyberArk, Unit 42)
- **Ransomware deployment** through modified skills (Cato Networks / MedusaLocker)
- **Dependency hijacking** via marketplace skills (SentinelOne)

The current verifier covers pattern matching, guardrails, permissions, supply chain, and CVE scanning. This spec adds 9 new analyzers, a platform abstraction layer, and 4 new scoring categories to close the identified gaps.

## Decisions

- **Architecture**: Approach B — platform abstraction layer + flat analyzers
- **Dependencies**: All built-in (no external tools). LLM Guardrails remains the only external integration
- **Signature storage**: YAML files in `data/` directory at project root
- **Platforms**: Claude Code, OpenClaw, Cursor, Generic MCP (auto-detected)
- **Scoring**: 4 new categories (MCP_SECURITY, CONFIG_INJECTION, OBFUSCATION, EXFILTRATION) added to existing 5. Total 9, equal weight, arithmetic mean

## 1. Platform Layer

### Purpose

Unified layer for detecting AI agent repository types and extracting platform-specific artifacts (configs, manifests, skill metadata, MCP tool definitions).

### Interface

```python
# src/skills_verified/platforms/base.py

@dataclass
class ConfigFile:
    path: Path           # relative to repo root
    platform: str        # "claude_code", "openclaw", "cursor", "generic_mcp"
    config_type: str     # "settings", "hooks", "rules", "manifest"
    content: dict | str  # parsed content

@dataclass
class SkillMetadata:
    name: str | None
    description: str | None
    author: str | None
    permissions_declared: list[str]
    entry_points: list[Path]
    platform: str

@dataclass
class MCPToolDefinition:
    name: str
    description: str
    input_schema: dict
    source_file: Path
    raw_definition: dict  # full schema for analyzing all fields


class PlatformProfile(ABC):
    name: str

    @abstractmethod
    def detect(self, repo_path: Path) -> bool:
        """Check if repository belongs to this platform."""

    @abstractmethod
    def get_config_files(self, repo_path: Path) -> list[ConfigFile]:
        """Return all platform config files."""

    @abstractmethod
    def get_skill_metadata(self, repo_path: Path) -> SkillMetadata | None:
        """Extract skill/plugin metadata if present."""

    @abstractmethod
    def get_mcp_definitions(self, repo_path: Path) -> list[MCPToolDefinition]:
        """Extract MCP tool definitions if present."""
```

### Platform Detection

```python
# src/skills_verified/platforms/detector.py

class PlatformDetector:
    def detect(self, repo_path: Path) -> list[PlatformProfile]:
        """Returns all detected platforms (can be >1)."""
```

A repository can be both a Claude Code skill and an MCP server simultaneously — hence `list`.

### Detection Markers

| Platform | Markers |
|----------|---------|
| Claude Code | `SKILL.md`, `.skills/`, `.claude/settings.json`, `.claude/config.json`, `CLAUDE.md` |
| OpenClaw | `flows/`, `nodes/`, `.openclaw/`, `credentials/`, `package.json` with `node-red` |
| Cursor | `.cursor/`, `.cursorrules`, `.cursor/rules/` |
| Generic MCP | `mcp.json`, `mcp-config.json`, MCP SDK imports in code, `stdio`/`sse` transport patterns |

### Platform Implementations

- `src/skills_verified/platforms/claude_code.py` — `ClaudeCodeProfile`
- `src/skills_verified/platforms/openclaw.py` — `OpenClawProfile`
- `src/skills_verified/platforms/cursor.py` — `CursorProfile`
- `src/skills_verified/platforms/generic_mcp.py` — `GenericMCPProfile`

## 2. New Scoring Categories

### Added to `Category` enum

```python
class Category(str, Enum):
    CODE_SAFETY = "code_safety"
    CVE = "cve"
    GUARDRAILS = "guardrails"
    PERMISSIONS = "permissions"
    SUPPLY_CHAIN = "supply_chain"
    MCP_SECURITY = "mcp_security"          # NEW
    CONFIG_INJECTION = "config_injection"    # NEW
    OBFUSCATION = "obfuscation"            # NEW
    EXFILTRATION = "exfiltration"           # NEW
```

### Scoring Rules

- All 9 categories equal weight. Overall score = arithmetic mean of 9 category scores
- Category with 0 findings = score 100 (no attack surface = no risk)
- Penalty weights unchanged: CRITICAL -25, HIGH -15, MEDIUM -7, LOW -3, INFO 0

## 3. New Analyzers

### Analyzer-to-Category Mapping

| Analyzer | Category | Platform Layer Needed |
|----------|----------|----------------------|
| `mcp_analyzer` | MCP_SECURITY | Yes |
| `config_injection_analyzer` | CONFIG_INJECTION | Yes |
| `obfuscation_analyzer` | OBFUSCATION | No |
| `exfiltration_analyzer` | EXFILTRATION | No |
| `reverse_shell_analyzer` | CODE_SAFETY | No |
| `known_threats_analyzer` | SUPPLY_CHAIN | Yes (for metadata) |
| `metadata_analyzer` | CONFIG_INJECTION | Yes |
| `privilege_analyzer` | PERMISSIONS | Yes |
| `behavioral_analyzer` | CODE_SAFETY | No (uses Python AST) |

### 3.1 MCP Analyzer (`mcp_analyzer`) — MCP_SECURITY

Detects attacks through the MCP protocol layer.

**Checks:**
- **Tool poisoning**: malicious instructions in `description`, `input_schema`, `annotations` fields of MCP tools. Patterns: "ignore previous", "you are now", "disregard", hidden directives in descriptions
- **Schema poisoning**: injection in any JSON schema field (`title`, `default`, `examples`, `enum`). Each field is scanned for prompt injection patterns
- **Rug pull indicators**: dynamic modification of tool definitions, runtime `tools/list` handler overrides, conditional tool schema changes
- **Cross-tool chain attacks**: a tool description references invoking another tool (e.g., "after this, call X with parameter Y")

**Uses:** `PlatformProfile.get_mcp_definitions()`

### 3.2 Config Injection Analyzer (`config_injection_analyzer`) — CONFIG_INJECTION

Detects malicious instructions and payloads in platform configuration files.

**Checks:**
- **CLAUDE.md**: hidden shell commands, `curl`/`wget` in code blocks, prompt injection patterns, instructions surviving autocompact
- **`.claude/settings.json`**: suspicious hooks (`command` containing `curl`, `wget`, `nc`, `bash -c`), `apiUrl` override (CVE-2026-21852 vector), MCP server definitions with suspicious URLs/args
- **`.cursorrules`**: prompt injection, hidden instructions, role override attempts
- **`.openclaw/`**: credentials in configs, insecure flow configurations, community node references to untrusted sources
- **`mcp.json` / `mcp-config.json`**: MCP servers with suspicious URLs, environment variable exfiltration in args, `--allow-*` flags

**Uses:** `PlatformProfile.get_config_files()`

### 3.3 Obfuscation Analyzer (`obfuscation_analyzer`) — OBFUSCATION

Detects code obfuscation techniques used to hide malicious payloads.

**Checks:**
- Hex-escape sequences: `\x63\x6d\x64` (4+ consecutive = HIGH)
- `String.fromCharCode()` / `chr()` chains (3+ consecutive = HIGH)
- Rot13 encoded strings with decode calls
- XOR-encoded strings with decode loops
- Base64-encoded executable code: `exec(base64.b64decode(...))`, `eval(atob(...))` (CRITICAL)
- String concatenation to assemble commands: `"cu" + "rl"`, `"ev" + "al"` (MEDIUM)
- Unicode homoglyph substitution: Cyrillic characters in Latin identifiers (HIGH)
- Nested eval/exec: `eval(compile(...))`, multi-layer unpacking (CRITICAL)

**Signatures:** `data/obfuscation_signatures.yaml`

### 3.4 Exfiltration Analyzer (`exfiltration_analyzer`) — EXFILTRATION

Detects covert data extraction techniques.

**Checks:**
- **DNS exfiltration**: subdomain construction from variables (`f"{secret}.attacker.com"`)
- **HTTP exfiltration**: sending local files/env vars via requests/fetch/urllib
- **File staging**: reading credentials + writing to temp files
- **Environment harvesting**: bulk `os.environ` / `process.env` collection
- **Clipboard/stdin interception**: reading clipboard or stdin and forwarding externally

**Signatures:** `data/exfiltration_patterns.yaml`

### 3.5 Reverse Shell Analyzer (`reverse_shell_analyzer`) — CODE_SAFETY

Detects network backdoor patterns.

**Checks:**
- Classic: `bash -i >& /dev/tcp/`, `nc -e /bin/sh`, `python -c 'import socket'`
- Bind shell: `socket.bind()` + `subprocess` combination
- Web shell: HTTP server + `os.system`/`subprocess` in handler
- PowerShell reverse shells: `New-Object System.Net.Sockets.TCPClient`, `Invoke-Expression`
- Language-specific variants: Python, Ruby, Perl, PHP, Node.js

**Signatures:** `data/reverse_shell_signatures.yaml`

### 3.6 Known Threats Analyzer (`known_threats_analyzer`) — SUPPLY_CHAIN

Checks repository against known malicious actors, file hashes, and campaign signatures.

**Checks:**
- **Malicious authors**: git remote URL, author from metadata matched against known bad actors (Snyk, Straiker, Koi databases)
- **Malicious file hashes**: SHA256 of all files compared against known malicious hashes
- **Campaign signatures**: content patterns from known campaigns (ClawHavoc, ToxicSkills) — specific strings, file names, behavioral indicators

**Data files:**
- `data/malicious_authors.yaml`
- `data/malicious_hashes.yaml`
- `data/campaign_signatures.yaml`

**Uses:** `PlatformProfile.get_skill_metadata()` for author extraction

### 3.7 Metadata Analyzer (`metadata_analyzer`) — CONFIG_INJECTION

Analyzes skill/plugin metadata for injection and deception.

**Checks:**
- **SKILL.md fields**: name, description, permissions — scanned for prompt injection
- **package.json**: suspicious `repository` URL, `funding`, `contributors` fields
- **setup.py / pyproject.toml**: metadata injection
- **Permission mismatch signal**: declared permissions vs actually used (informational, not definitive)

**Uses:** `PlatformProfile.get_skill_metadata()`

### 3.8 Privilege Analyzer (`privilege_analyzer`) — PERMISSIONS

Compares declared permissions against actual code behavior.

**Checks:**
- **Over-privilege**: skill requests `filesystem`, `network`, `shell` but only uses `filesystem` (LOW — informational)
- **Undeclared access**: code uses `subprocess` but metadata doesn't declare `shell` permission (HIGH)
- **Dangerous combinations**: `network` + `filesystem` + `shell` simultaneously (HIGH)
- **Escalation patterns**: code attempts to modify its own permission declarations

**Uses:** `PlatformProfile.get_skill_metadata()` + results context from `permissions_analyzer`

### 3.9 Behavioral Analyzer (`behavioral_analyzer`) — CODE_SAFETY

Source-sink data flow analysis to detect suspicious behavior patterns.

**Checks:**
- **Source-sink flows**: data from sensitive sources (env vars, files, stdin) flows to dangerous sinks (network, exec, file write)
- **Tainted data flow**: variable read from `os.environ` → passed to `requests.post()`
- **Delayed execution**: `time.sleep()` + malicious action (evasion pattern)
- **Conditional activation**: code executes only under specific conditions (`if os.getenv("CI")`, `if platform.system() == "Linux"`)

**Implementation:** Python `ast` module for `.py` files (AST-based flow tracing), regex patterns for other languages.

## 4. Signature Data Files

### Common Format

```yaml
version: "1.0"
updated: "YYYY-MM-DD"

signatures:
  - id: "XX001"
    name: "Human-readable name"
    pattern: "regex pattern"
    severity: CRITICAL | HIGH | MEDIUM | LOW
    languages: [py, js, ts, sh, rb]
    description: "What this detects and why it matters"
    references:
      - "https://..."
```

### Data Files

| File | Purpose |
|------|---------|
| `data/malicious_authors.yaml` | Known bad actors from Snyk, Straiker, Koi research |
| `data/malicious_hashes.yaml` | SHA256 of known malicious files |
| `data/campaign_signatures.yaml` | Patterns from ClawHavoc, ToxicSkills campaigns |
| `data/reverse_shell_signatures.yaml` | Shell patterns per language |
| `data/exfiltration_patterns.yaml` | DNS/HTTP/file exfil patterns |
| `data/obfuscation_signatures.yaml` | Encoding/obfuscation patterns |

### Signature Loader

```python
# src/skills_verified/data/loader.py

class SignatureLoader:
    def __init__(self, data_dir: Path | None = None):
        self.data_dir = data_dir or Path(__file__).parent.parent.parent.parent / "data"

    def load(self, filename: str) -> dict:
        """Load YAML file from data/. Returns {} if not found."""
        path = self.data_dir / filename
        if not path.exists():
            return {}
        return yaml.safe_load(path.read_text())

    def load_signatures(self, filename: str) -> list[dict]:
        """Load signature list from YAML."""
        data = self.load(filename)
        return data.get("signatures", [])
```

Analyzers use the loader at init time. Missing YAML = analyzer works without external signatures (graceful degradation).

## 5. Changes to Existing Code

### Modified Files

| File | Change |
|------|--------|
| `core/models.py` | Add 4 values to `Category` enum |
| `core/analyzer.py` | Add optional `platforms: list[PlatformProfile] \| None = None` to `analyze()` signature |
| `core/pipeline.py` | Add `PlatformDetector` call before analyzers, pass `platforms` to `analyze()`, register 9 new analyzers |
| `cli.py` | Update analyzer name validation for `--only`/`--skip` |
| `output/console.py` | Verify 9-category table renders correctly (code already iterates dynamically) |

### Backward Compatibility

- `platforms=None` default — existing analyzers unaffected
- `Report` model unchanged — `categories` and `findings` lists already dynamic
- JSON report structure unchanged — new categories appear automatically
- Dockerfile unchanged — no new external dependencies
- Existing tests unchanged — continue passing

## 6. Pipeline Changes

```python
class Pipeline:
    def run(self, repo_path: Path) -> Report:
        detector = PlatformDetector()
        platforms = detector.detect(repo_path)

        findings = []
        for analyzer in self.analyzers:
            if not analyzer.is_available():
                continue
            results = analyzer.analyze(repo_path, platforms=platforms)
            findings.extend(results)

        return self.scorer.score(findings)
```

## 7. New File Structure

```
src/skills_verified/
  platforms/
    __init__.py
    detector.py
    base.py
    claude_code.py
    openclaw.py
    cursor.py
    generic_mcp.py
  analyzers/
    mcp_analyzer.py
    config_injection_analyzer.py
    obfuscation_analyzer.py
    exfiltration_analyzer.py
    reverse_shell_analyzer.py
    known_threats_analyzer.py
    metadata_analyzer.py
    privilege_analyzer.py
    behavioral_analyzer.py
  data/
    __init__.py
    loader.py

data/
  malicious_authors.yaml
  malicious_hashes.yaml
  campaign_signatures.yaml
  reverse_shell_signatures.yaml
  exfiltration_patterns.yaml
  obfuscation_signatures.yaml
```

## 8. Testing

### New Test Fixtures

```
tests/fixtures/fake_repo/
  mcp_server.py             # MCP server with tool poisoning in descriptions
  mcp_config.json           # suspicious MCP config
  SKILL.md                  # skill metadata with injection
  .claude/
    settings.json            # hooks with curl, overridden apiUrl
  .cursorrules              # prompt injection in cursor rules
  obfuscated.py             # hex-escape, chr() chains, base64+exec
  obfuscated.js             # String.fromCharCode, concatenation
  reverse_shell.py          # classic reverse shell patterns
  exfiltration.py           # DNS exfil, env harvesting, HTTP exfil
  privilege_mismatch.py     # uses subprocess but doesn't declare shell
  behavioral_suspect.py     # os.environ -> requests.post, sleep+exec
  clean_mcp_server.py       # clean MCP server (false positive test)
  clean_config.md           # safe CLAUDE.md (false positive test)
```

### New Test Files

```
tests/
  test_mcp_analyzer.py
  test_config_injection_analyzer.py
  test_obfuscation_analyzer.py
  test_exfiltration_analyzer.py
  test_reverse_shell_analyzer.py
  test_known_threats_analyzer.py
  test_metadata_analyzer.py
  test_privilege_analyzer.py
  test_behavioral_analyzer.py
  test_platform_detector.py
  test_platform_claude_code.py
  test_platform_openclaw.py
  test_platform_cursor.py
  test_platform_generic_mcp.py
  test_signature_loader.py
```

### Test Requirements Per Analyzer

1. True positive detection of known patterns
2. False positive verification on clean code
3. Correct severity and category in findings
4. Graceful degradation without YAML files

### Updated Integration Tests

- `test_integration.py`: extend to verify 9 categories in report
- `test_scorer.py`: add tests for 9-category scoring
