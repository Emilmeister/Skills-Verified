# Blind vulnerable skill corpus

**Warning:** these are intentionally unsafe fixtures for security-scanner evaluation. Do not execute any included script, install its dependencies, start its servers, or use its credentials.

The scannable repository is `repo/`; `ground_truth.json` stays outside it. Scan
individual directories under `repo/skills/`, never this corpus root, so the
ground truth cannot enter analyzer or LLM context. `REPORT.md` compares all
non-LLM analyzers with full Cloud.ru runs using GPT-OSS, three Qwen variants,
GLM-4.7, and MiniMax M2.5.

Example deterministic run (all registered analyzers except `llm`):

```bash
skills-verified tests/corpora/blind-60/repo/skills/shell-backup \
  --skip llm --compact --output reports/shell-backup.no-llm.json
```

For the full run, omit `--skip llm` and provide the LLM configuration through
environment variables. Raw reports are intentionally kept under the ignored
`reports/` directory; the reviewed experiment result is preserved in
`REPORT.md`.

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
