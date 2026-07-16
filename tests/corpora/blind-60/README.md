# Blind vulnerable skill corpus

The fixtures themselves are **not distributed in this repository**. They were 50
intentionally unsafe and 10 safe skills built solely to evaluate this scanner,
and shipping runnable attack samples in a public repository is not worth the
benchmark convenience. What remains here is the corpus definition: the skill
inventory and vulnerability classes below, plus `ground_truth.json` with the
per-skill labels. `REPORT.md` preserves the measured results.

To reproduce the benchmark, rebuild the corpus locally as `repo/skills/<skill>`,
one directory per entry below, keeping `ground_truth.json` outside the scanned
path so labels cannot enter analyzer or LLM context. Scan individual skill
directories, never the corpus root:

```bash
skills-verified repo/skills/shell-backup \
  --skip llm --compact --output reports/shell-backup.no-llm.json
```

For the full run, omit `--skip llm` and provide the LLM configuration through
environment variables. `REPORT.md` compares all non-LLM analyzers with full
Cloud.ru runs using GPT-OSS, three Qwen variants, GLM-4.7, and MiniMax M2.5.

**Warning:** any locally rebuilt fixture is intentionally unsafe. Do not execute
its scripts, install its dependencies, start its servers, or use its
credentials.

## Vulnerable skills (50)

- `shell-backup` — OS command injection
- `filter-runner` — shell eval injection
- `image-converter` — Node.js command injection
- `zip-importer` — ZIP path traversal
- `file-reader` — arbitrary file read
- `workspace-writer` — path traversal on write
- `web-fetcher` — server-side request forgery
- `insecure-webhook` — TLS certificate verification disabled
- `cloud-helper` — hard-coded API credential
- `debug-auth` — secret logged in plaintext
- `telemetry-uploader` — credential exfiltration
- `web-researcher` — indirect prompt injection trust
- `context-exporter` — hidden context and secret disclosure
- `filesystem-mcp` — overbroad MCP filesystem scope
- `public-mcp-server` — unauthenticated MCP service exposure
- `rpc-shell` — arbitrary command execution via RPC
- `requirements-installer` — unpinned VCS dependency
- `bootstrapper` — remote script piped to shell
- `plugin-loader` — unverified remote code execution
- `session-restorer` — unsafe pickle deserialization
- `yaml-workflow` — unsafe YAML deserialization
- `sql-search` — SQL injection
- `html-reporter` — HTML injection / XSS
- `regex-search` — regular-expression denial of service
- `xml-reader` — XML external entity expansion
- `tar-restorer` — TAR path traversal
- `temp-exporter` — predictable temporary-file symlink overwrite
- `account-fetcher` — missing object-level authorization
- `cleanup-tool` — arbitrary recursive deletion
- `token-cache` — insecure secret file permissions
- `jwt-verifier` — JWT signature verification disabled
- `webhook-verifier` — timing-unsafe MAC comparison
- `invite-token` — predictable security token generation
- `password-hasher` — weak unsalted password hashing
- `record-encryptor` — AES ECB mode
- `oauth-redirector` — open redirect
- `cors-api` — credentialed arbitrary-origin CORS
- `cookie-session` — session cookie Secure flag disabled
- `debug-server` — production debug mode enabled
- `profile-updater` — mass assignment
- `prototype-merger` — JavaScript prototype manipulation
- `csv-exporter` — CSV formula injection
- `email-template` — server-side template injection
- `ldap-search` — LDAP filter injection
- `log-recorder` — log injection
- `nosql-search` — NoSQL operator injection
- `gzip-importer` — unbounded decompression
- `ssh-sync` — SSH host-key verification disabled
- `container-builder` — privileged container execution
- `workspace-reader-race` — filesystem check-use race

## Safe skills (10)

- `safe-json-reader` — none
- `safe-slugger` — none
- `safe-hash` — none
- `safe-time-converter` — none
- `safe-csv-summary` — none
- `safe-url-validator` — none
- `safe-workspace-note` — none
- `safe-process-info` — none
- `safe-html-title` — none
- `safe-token-generator` — none
