# CI/CD Integration Design

> **Status: Superseded.** Исторический документ; описанные policy-решения и форматы удалены. Текущий контракт: [Policy-Free Scan Report Roadmap](./2026-07-13-policy-free-scan-report-roadmap.md).

**Date:** 2026-04-16
**Original status:** Approved

## Goal

Make skills-verified a first-class CI/CD citizen: automatic pass/fail decisions based on quality thresholds, rich reporting (annotations, PR comments, badges, Code Quality), ready-to-use configurations for GitHub Actions and GitLab CI.

## Scope

1. CLI enhancements: threshold flags, new output formats, exit codes
2. Four new output modules: codeclimate, badge, github annotations, markdown
3. Reusable GitHub Action (action.yml)
4. Includable GitLab CI template
5. Example workflows for both platforms
6. Tests for all new code
7. README update

---

## 1. CLI Changes

### New Options

| Flag | Type | Description |
|------|------|-------------|
| `--threshold N` | int (0-100) | Minimum acceptable overall_score. Exit 1 if below |
| `--threshold-grade GRADE` | click.Choice (A/B/C/D/F) | Minimum acceptable grade. Exit 1 if worse |
| `--format FORMAT` | multi-value | Additional output formats (repeatable) |
| `--output-dir DIR` | click.Path | Directory for format artifacts (default: `.`) |
| `--markdown-style STYLE` | click.Choice (full/summary) | Markdown report detail level (default: `full`) |

### Threshold Behavior

- `--threshold 70` alone: fail if score < 70
- `--threshold-grade C` alone: fail if grade worse than C (D or F)
- Both specified: fail if **either** condition is not met
- Neither specified: always exit 0 (backward compatible)

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan passed (above threshold or no threshold set) |
| 1 | Scan failed (below threshold) |
| 2 | Execution error (clone failure, crash, etc.) |

Current `sys.exit(1)` on errors becomes `sys.exit(2)`.

### Format Values

`--format` accepts one or more of:

| Format | Artifact File | Description |
|--------|--------------|-------------|
| `json` | via `--output` | Current JSON report (unchanged) |
| `codeclimate` | `gl-code-quality-report.json` | Code Climate JSON for GitLab Code Quality |
| `badge` | `badge.json` | shields.io endpoint JSON |
| `github` | none (stdout) | `::error`/`::warning` annotations for GitHub Actions |
| `markdown` | `report.md` | Markdown report for PR comments |

Console output (Rich) always prints regardless of `--format`.

---

## 2. Output Modules

### 2.1 Code Climate (`src/skills_verified/output/codeclimate.py`)

Converts findings to Code Climate JSON format for GitLab Code Quality.

**Severity mapping:**

| skills-verified | Code Climate |
|----------------|--------------|
| CRITICAL | blocker |
| HIGH | critical |
| MEDIUM | major |
| LOW | minor |
| INFO | info |

Each issue gets:
- `fingerprint`: SHA256 of `{analyzer}:{title}:{file_path}:{line_number}`
- `location.path`: finding.file_path (or "unknown")
- `location.lines.begin`: finding.line_number (or 1)
- `description`: finding.description
- `check_name`: finding.analyzer
- `categories`: derived from finding.category

Output: list of Code Climate issue objects, written to `gl-code-quality-report.json`.

### 2.2 Badge (`src/skills_verified/output/badge.py`)

Generates shields.io endpoint JSON.

```json
{
  "schemaVersion": 1,
  "label": "Trust Score",
  "message": "A (95)",
  "color": "brightgreen"
}
```

**Color mapping:**

| Grade | Color |
|-------|-------|
| A | brightgreen |
| B | green |
| C | yellow |
| D | orange |
| F | red |

Output: written to `badge.json`.

### 2.3 GitHub Annotations (`src/skills_verified/output/github_annotations.py`)

Writes GitHub Actions workflow commands to stdout.

```
::error file=src/main.py,line=42,title=Hardcoded API key::Found API key in source code
::warning file=src/util.py,line=10,title=eval() usage::Dangerous eval() call
```

**Mapping:**
- CRITICAL/HIGH severity -> `::error`
- MEDIUM/LOW severity -> `::warning`
- INFO -> `::notice`
- Findings without file_path: `::error title=...::description`

### 2.4 Markdown Report (`src/skills_verified/output/markdown_report.py`)

Generates Markdown report for PR comments. Supports two styles via `--markdown-style`.

**Full style:**

```markdown
## Skills Verified -- Trust Score: A (95/100)

**Repository:** `user/repo`
**Scan duration:** 3.2s | **Analyzers:** 12

### Summary
| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 3 |
| LOW | 5 |

### Categories
| Category | Grade | Score |
|----------|-------|-------|
| Code Safety | A | 95 |
| CVE | B | 82 |

### Findings

| Severity | Title | File | Confidence |
|----------|-------|------|------------|
| HIGH | Hardcoded API key | `src/main.py:42` | 0.95 |
| MEDIUM | eval() usage | `src/util.py:10` | 0.87 |
```

**Summary style:**

Same as full but without the Findings table. Replaced by:
`> N findings found. Run full scan for details.`

---

## 3. Reusable GitHub Action

File: `action.yml` in repository root.

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `source` | `.` | Path or URL to scan |
| `threshold` | — | Minimum score (0-100) |
| `threshold-grade` | — | Minimum grade (A/B/C/D/F) |
| `skip` | — | Analyzers to skip |
| `only` | — | Run only these analyzers |
| `use-docker` | `false` | Use Docker image instead of pip install |
| `python-version` | `3.11` | Python version (if not Docker) |
| `comment-on-pr` | `true` | Post Markdown comment on PR |
| `comment-style` | `full` | `full` or `summary` |
| `generate-badge` | `true` | Generate badge.json |

### Outputs

| Output | Description |
|--------|-------------|
| `score` | overall_score (number) |
| `grade` | overall_grade (letter) |
| `passed` | `true`/`false` |
| `report-path` | Path to JSON report |

### Steps

1. Setup Python (if not Docker) or pull Docker image
2. Install skills-verified + external scanners (pip path) or use Docker
3. Run `skills-verified` with `--format github markdown badge json` + threshold flags
4. Parse exit code, write outputs via `$GITHUB_OUTPUT`
5. If PR and `comment-on-pr=true`: `gh pr comment --body-file report.md`
6. Upload artifacts (JSON report, badge.json)
7. Write Job Summary: `cat report.md >> $GITHUB_STEP_SUMMARY`

---

## 4. GitLab CI Template

File: `templates/gitlab-ci-skills-verified.yml`

### Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SV_SOURCE` | `.` | Path or URL |
| `SV_THRESHOLD` | — | Minimum score |
| `SV_THRESHOLD_GRADE` | — | Minimum grade |
| `SV_SKIP` | — | Analyzers to skip |
| `SV_ONLY` | — | Run only these analyzers |
| `SV_USE_DOCKER` | `false` | Use Docker image |
| `SV_COMMENT_ON_MR` | `true` | Post comment on MR |
| `SV_COMMENT_STYLE` | `full` | `full` / `summary` |
| `SV_GENERATE_BADGE` | `true` | Generate badge.json |

### Jobs

**`skills-verified:pip`** (default):
- `image: python:3.11`
- Installs skills-verified + external scanners
- Runs with `--format codeclimate markdown badge json`
- Saves `gl-code-quality-report.json` as `reports: codequality` artifact
- Other files as regular artifacts

**`skills-verified:docker`** (if `SV_USE_DOCKER=true`):
- `image: docker:latest` with `services: [docker:dind]`
- Builds or pulls image, runs via `docker run`

### Post-scan Logic

1. If `SV_COMMENT_ON_MR=true` and MR pipeline: post `report.md` via GitLab API (`curl $CI_API_V4_URL`)
2. Code Quality report picked up by GitLab from artifact automatically
3. Badge.json saved as artifact
4. Threshold exit code propagated as job status

---

## 5. Examples

```
examples/
├── github-actions/
│   ├── basic.yml          -- minimal: scan + threshold
│   ├── full.yml           -- all features: annotations, badge, PR comment, Docker
│   └── monorepo.yml       -- matrix strategy for multiple directories
├── gitlab-ci/
│   ├── basic.yml          -- minimal: scan + threshold + codequality
│   ├── full.yml           -- all features: MR comment, badge, Docker
│   └── monorepo.yml       -- parallel:matrix for multiple paths
└── README.md              -- brief description of each example
```

---

## 6. Tests

- `tests/test_codeclimate.py` — Code Climate output: severity mapping, fingerprint generation, missing file_path handling
- `tests/test_badge.py` — badge JSON: grade-to-color mapping, schema correctness
- `tests/test_github_annotations.py` — annotation format: error/warning/notice mapping, with/without file_path
- `tests/test_markdown_report.py` — both full and summary styles, confidence column, edge cases (no findings, all critical)
- `tests/test_threshold.py` — threshold logic: score-only, grade-only, both, neither, edge values
- `tests/test_cli.py` — extend existing CLI tests with new flags, exit code verification

---

## 7. README Update

Update "Интеграция с CI/CD" section with:
- Links to `action.yml` and template
- Brief usage examples for both platforms
- Link to `examples/` directory
- Badge setup instructions (shields.io endpoint URL)

---

## Files to Create

| File | Purpose |
|------|---------|
| `src/skills_verified/output/codeclimate.py` | Code Climate JSON generator |
| `src/skills_verified/output/badge.py` | shields.io endpoint JSON generator |
| `src/skills_verified/output/github_annotations.py` | GitHub Actions annotations |
| `src/skills_verified/output/markdown_report.py` | Markdown report generator |
| `action.yml` | Reusable GitHub Action |
| `templates/gitlab-ci-skills-verified.yml` | GitLab CI template |
| `examples/github-actions/basic.yml` | GitHub Actions basic example |
| `examples/github-actions/full.yml` | GitHub Actions full example |
| `examples/github-actions/monorepo.yml` | GitHub Actions monorepo example |
| `examples/gitlab-ci/basic.yml` | GitLab CI basic example |
| `examples/gitlab-ci/full.yml` | GitLab CI full example |
| `examples/gitlab-ci/monorepo.yml` | GitLab CI monorepo example |
| `examples/README.md` | Examples documentation |
| `tests/test_codeclimate.py` | Code Climate output tests |
| `tests/test_badge.py` | Badge output tests |
| `tests/test_github_annotations.py` | GitHub annotations tests |
| `tests/test_markdown_report.py` | Markdown report tests |
| `tests/test_threshold.py` | Threshold logic tests |

## Files to Modify

| File | Changes |
|------|---------|
| `src/skills_verified/cli.py` | New options, format dispatch, threshold logic, exit codes |
| `src/skills_verified/output/__init__.py` | Export new modules |
| `tests/test_cli.py` | Extend with new flag tests |
| `README.md` | Update CI/CD section |
