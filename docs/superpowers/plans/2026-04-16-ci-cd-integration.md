# CI/CD Integration Implementation Plan

> **Status: Superseded.** Исторический план; не выполнять его инструкции. Текущий контракт: [Policy-Free Scan Report Roadmap](../specs/2026-07-13-policy-free-scan-report-roadmap.md).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add threshold-based pass/fail, four output formats (codeclimate, badge, github annotations, markdown), reusable GitHub Action, GitLab CI template, and example workflows.

**Architecture:** All logic lives in the CLI. Four new output modules under `src/skills_verified/output/` generate artifacts. CLI gains `--threshold`, `--threshold-grade`, `--format`, `--output-dir`, `--markdown-style` flags. Exit code 0/1/2 encodes pass/fail/error. CI configs are thin wrappers that call the CLI.

**Tech Stack:** Python 3.11+, Click, existing models (Report, Finding, Grade, Severity, Category)

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `src/skills_verified/output/codeclimate.py` | Convert findings to Code Climate JSON |
| `src/skills_verified/output/badge.py` | Generate shields.io endpoint JSON |
| `src/skills_verified/output/github_annotations.py` | Print `::error`/`::warning` to stdout |
| `src/skills_verified/output/markdown_report.py` | Generate Markdown report (full/summary) |
| `tests/test_codeclimate.py` | Tests for Code Climate output |
| `tests/test_badge.py` | Tests for badge output |
| `tests/test_github_annotations.py` | Tests for GitHub annotations |
| `tests/test_markdown_report.py` | Tests for Markdown report |
| `tests/test_threshold.py` | Tests for threshold logic |
| `action.yml` | Reusable GitHub Action |
| `templates/gitlab-ci-skills-verified.yml` | Includable GitLab CI template |
| `examples/github-actions/basic.yml` | Minimal GitHub Actions example |
| `examples/github-actions/full.yml` | Full-featured GitHub Actions example |
| `examples/github-actions/monorepo.yml` | Monorepo GitHub Actions example |
| `examples/gitlab-ci/basic.yml` | Minimal GitLab CI example |
| `examples/gitlab-ci/full.yml` | Full-featured GitLab CI example |
| `examples/gitlab-ci/monorepo.yml` | Monorepo GitLab CI example |
| `examples/README.md` | Examples documentation |

### Modified Files

| File | What Changes |
|------|-------------|
| `src/skills_verified/cli.py` | New options, format dispatch, threshold check, exit codes |
| `tests/test_cli.py` | New tests for flags and exit codes |
| `README.md` | Updated CI/CD section |

---

### Task 1: Badge Output Module

**Files:**
- Create: `src/skills_verified/output/badge.py`
- Create: `tests/test_badge.py`

- [ ] **Step 1: Write failing tests for badge generation**

Create `tests/test_badge.py`:

```python
import json

from skills_verified.core.models import Grade
from skills_verified.output.badge import generate_badge, save_badge


def test_badge_grade_a():
    data = generate_badge(score=95, grade=Grade.A)
    assert data["schemaVersion"] == 1
    assert data["label"] == "Trust Score"
    assert data["message"] == "A (95)"
    assert data["color"] == "brightgreen"


def test_badge_grade_b():
    data = generate_badge(score=85, grade=Grade.B)
    assert data["message"] == "B (85)"
    assert data["color"] == "green"


def test_badge_grade_c():
    data = generate_badge(score=70, grade=Grade.C)
    assert data["message"] == "C (70)"
    assert data["color"] == "yellow"


def test_badge_grade_d():
    data = generate_badge(score=55, grade=Grade.D)
    assert data["message"] == "D (55)"
    assert data["color"] == "orange"


def test_badge_grade_f():
    data = generate_badge(score=30, grade=Grade.F)
    assert data["message"] == "F (30)"
    assert data["color"] == "red"


def test_save_badge(tmp_path):
    path = tmp_path / "badge.json"
    save_badge(score=95, grade=Grade.A, path=path)
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["schemaVersion"] == 1
    assert data["message"] == "A (95)"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/test_badge.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'skills_verified.output.badge'`

- [ ] **Step 3: Implement badge module**

Create `src/skills_verified/output/badge.py`:

```python
import json
from pathlib import Path

from skills_verified.core.models import Grade

GRADE_COLORS = {
    Grade.A: "brightgreen",
    Grade.B: "green",
    Grade.C: "yellow",
    Grade.D: "orange",
    Grade.F: "red",
}


def generate_badge(score: int, grade: Grade) -> dict:
    return {
        "schemaVersion": 1,
        "label": "Trust Score",
        "message": f"{grade.value} ({score})",
        "color": GRADE_COLORS[grade],
    }


def save_badge(score: int, grade: Grade, path: Path) -> None:
    data = generate_badge(score, grade)
    path.write_text(json.dumps(data, indent=2))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/test_badge.py -v`
Expected: all 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/skills_verified/output/badge.py tests/test_badge.py
git commit -m "feat: add badge output module for shields.io endpoint"
```

---

### Task 2: GitHub Annotations Output Module

**Files:**
- Create: `src/skills_verified/output/github_annotations.py`
- Create: `tests/test_github_annotations.py`

- [ ] **Step 1: Write failing tests for GitHub annotations**

Create `tests/test_github_annotations.py`:

```python
from skills_verified.core.models import Category, Finding, Severity
from skills_verified.output.github_annotations import format_annotations


def _finding(
    severity: Severity,
    title: str = "Test issue",
    description: str = "Test desc",
    file_path: str | None = "src/main.py",
    line_number: int | None = 42,
) -> Finding:
    return Finding(
        title=title,
        description=description,
        severity=severity,
        category=Category.CODE_SAFETY,
        file_path=file_path,
        line_number=line_number,
        analyzer="test",
    )


def test_critical_produces_error():
    lines = format_annotations([_finding(Severity.CRITICAL)])
    assert lines[0].startswith("::error ")


def test_high_produces_error():
    lines = format_annotations([_finding(Severity.HIGH)])
    assert lines[0].startswith("::error ")


def test_medium_produces_warning():
    lines = format_annotations([_finding(Severity.MEDIUM)])
    assert lines[0].startswith("::warning ")


def test_low_produces_warning():
    lines = format_annotations([_finding(Severity.LOW)])
    assert lines[0].startswith("::warning ")


def test_info_produces_notice():
    lines = format_annotations([_finding(Severity.INFO)])
    assert lines[0].startswith("::notice ")


def test_file_and_line_in_annotation():
    lines = format_annotations([_finding(Severity.HIGH)])
    assert "file=src/main.py" in lines[0]
    assert "line=42" in lines[0]


def test_title_in_annotation():
    lines = format_annotations([_finding(Severity.HIGH, title="Bad key")])
    assert "title=Bad key" in lines[0]


def test_description_after_separator():
    lines = format_annotations([_finding(Severity.HIGH, description="Found leak")])
    assert lines[0].endswith("::Found leak")


def test_finding_without_file():
    lines = format_annotations([_finding(Severity.HIGH, file_path=None, line_number=None)])
    assert "file=" not in lines[0]
    assert "title=Test issue" in lines[0]


def test_multiple_findings():
    findings = [
        _finding(Severity.CRITICAL),
        _finding(Severity.LOW),
    ]
    lines = format_annotations(findings)
    assert len(lines) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/test_github_annotations.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement GitHub annotations module**

Create `src/skills_verified/output/github_annotations.py`:

```python
from skills_verified.core.models import Finding, Severity

SEVERITY_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "notice",
}


def format_annotations(findings: list[Finding]) -> list[str]:
    lines: list[str] = []
    for f in findings:
        level = SEVERITY_LEVELS[f.severity]
        params = []
        if f.file_path:
            params.append(f"file={f.file_path}")
            if f.line_number:
                params.append(f"line={f.line_number}")
        params.append(f"title={f.title}")
        param_str = ",".join(params)
        lines.append(f"::{level} {param_str}::{f.description}")
    return lines


def print_annotations(findings: list[Finding]) -> None:
    for line in format_annotations(findings):
        print(line)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/test_github_annotations.py -v`
Expected: all 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/skills_verified/output/github_annotations.py tests/test_github_annotations.py
git commit -m "feat: add GitHub Actions annotations output module"
```

---

### Task 3: Code Climate Output Module

**Files:**
- Create: `src/skills_verified/output/codeclimate.py`
- Create: `tests/test_codeclimate.py`

- [ ] **Step 1: Write failing tests for Code Climate output**

Create `tests/test_codeclimate.py`:

```python
import json
from pathlib import Path

from skills_verified.core.models import Category, Finding, Severity
from skills_verified.output.codeclimate import (
    generate_codeclimate,
    save_codeclimate,
)


def _finding(
    severity: Severity = Severity.HIGH,
    file_path: str | None = "src/main.py",
    line_number: int | None = 42,
    title: str = "Test issue",
    category: Category = Category.CODE_SAFETY,
) -> Finding:
    return Finding(
        title=title,
        description="Test desc",
        severity=severity,
        category=category,
        file_path=file_path,
        line_number=line_number,
        analyzer="test_analyzer",
    )


def test_severity_mapping_critical():
    issues = generate_codeclimate([_finding(Severity.CRITICAL)])
    assert issues[0]["severity"] == "blocker"


def test_severity_mapping_high():
    issues = generate_codeclimate([_finding(Severity.HIGH)])
    assert issues[0]["severity"] == "critical"


def test_severity_mapping_medium():
    issues = generate_codeclimate([_finding(Severity.MEDIUM)])
    assert issues[0]["severity"] == "major"


def test_severity_mapping_low():
    issues = generate_codeclimate([_finding(Severity.LOW)])
    assert issues[0]["severity"] == "minor"


def test_severity_mapping_info():
    issues = generate_codeclimate([_finding(Severity.INFO)])
    assert issues[0]["severity"] == "info"


def test_fingerprint_is_hex_string():
    issues = generate_codeclimate([_finding()])
    assert isinstance(issues[0]["fingerprint"], str)
    assert len(issues[0]["fingerprint"]) == 64  # SHA256 hex


def test_location_has_path_and_line():
    issues = generate_codeclimate([_finding()])
    loc = issues[0]["location"]
    assert loc["path"] == "src/main.py"
    assert loc["lines"]["begin"] == 42


def test_missing_file_path_defaults():
    issues = generate_codeclimate([_finding(file_path=None, line_number=None)])
    loc = issues[0]["location"]
    assert loc["path"] == "unknown"
    assert loc["lines"]["begin"] == 1


def test_check_name_is_analyzer():
    issues = generate_codeclimate([_finding()])
    assert issues[0]["check_name"] == "test_analyzer"


def test_description_present():
    issues = generate_codeclimate([_finding()])
    assert issues[0]["description"] == "Test desc"


def test_different_findings_get_different_fingerprints():
    f1 = _finding(title="Issue A", file_path="a.py", line_number=1)
    f2 = _finding(title="Issue B", file_path="b.py", line_number=2)
    issues = generate_codeclimate([f1, f2])
    assert issues[0]["fingerprint"] != issues[1]["fingerprint"]


def test_save_codeclimate(tmp_path):
    path = tmp_path / "gl-code-quality-report.json"
    save_codeclimate([_finding()], path)
    assert path.exists()
    data = json.loads(path.read_text())
    assert isinstance(data, list)
    assert len(data) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/test_codeclimate.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement Code Climate module**

Create `src/skills_verified/output/codeclimate.py`:

```python
import hashlib
import json
from pathlib import Path

from skills_verified.core.models import Category, Finding, Severity

SEVERITY_MAP = {
    Severity.CRITICAL: "blocker",
    Severity.HIGH: "critical",
    Severity.MEDIUM: "major",
    Severity.LOW: "minor",
    Severity.INFO: "info",
}

CATEGORY_MAP = {
    Category.CODE_SAFETY: "Security",
    Category.CVE: "Security",
    Category.GUARDRAILS: "Security",
    Category.PERMISSIONS: "Security",
    Category.SUPPLY_CHAIN: "Security",
    Category.MCP_SECURITY: "Security",
    Category.CONFIG_INJECTION: "Security",
    Category.OBFUSCATION: "Security",
    Category.EXFILTRATION: "Security",
}


def _fingerprint(finding: Finding) -> str:
    raw = f"{finding.analyzer}:{finding.title}:{finding.file_path}:{finding.line_number}"
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_codeclimate(findings: list[Finding]) -> list[dict]:
    issues = []
    for f in findings:
        issues.append({
            "type": "issue",
            "check_name": f.analyzer,
            "description": f.description,
            "categories": [CATEGORY_MAP.get(f.category, "Security")],
            "severity": SEVERITY_MAP[f.severity],
            "fingerprint": _fingerprint(f),
            "location": {
                "path": f.file_path or "unknown",
                "lines": {
                    "begin": f.line_number or 1,
                },
            },
        })
    return issues


def save_codeclimate(findings: list[Finding], path: Path) -> None:
    issues = generate_codeclimate(findings)
    path.write_text(json.dumps(issues, indent=2, ensure_ascii=False))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/test_codeclimate.py -v`
Expected: all 12 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/skills_verified/output/codeclimate.py tests/test_codeclimate.py
git commit -m "feat: add Code Climate output module for GitLab Code Quality"
```

---

### Task 4: Markdown Report Output Module

**Files:**
- Create: `src/skills_verified/output/markdown_report.py`
- Create: `tests/test_markdown_report.py`

- [ ] **Step 1: Write failing tests for Markdown report**

Create `tests/test_markdown_report.py`:

```python
from pathlib import Path

from skills_verified.core.models import (
    Category, CategoryScore, Finding, Grade, Report, Severity,
)
from skills_verified.output.markdown_report import (
    generate_markdown,
    save_markdown,
)


def _make_finding(
    severity: Severity = Severity.HIGH,
    title: str = "Test issue",
    file_path: str | None = "src/main.py",
    line_number: int | None = 42,
    confidence: float = 0.95,
) -> Finding:
    return Finding(
        title=title,
        description="Test desc",
        severity=severity,
        category=Category.CODE_SAFETY,
        file_path=file_path,
        line_number=line_number,
        analyzer="test",
        confidence=confidence,
    )


def _make_report(
    findings: list[Finding] | None = None,
    score: int = 82,
    grade: Grade = Grade.B,
) -> Report:
    if findings is None:
        findings = [_make_finding()]
    return Report(
        repo_url="https://github.com/test/repo",
        overall_score=score,
        overall_grade=grade,
        categories=[
            CategoryScore(Category.CODE_SAFETY, 85, Grade.B, 1, 0, 1),
            CategoryScore(Category.CVE, 100, Grade.A, 0, 0, 0),
        ],
        findings=findings,
        analyzers_used=["test", "cve"],
        llm_used=False,
        scan_duration_seconds=1.5,
    )


def test_full_contains_header():
    md = generate_markdown(_make_report(), style="full")
    assert "## Skills Verified" in md
    assert "B (82/100)" in md


def test_full_contains_summary_table():
    md = generate_markdown(_make_report(), style="full")
    assert "| Severity | Count |" in md
    assert "| HIGH" in md


def test_full_contains_categories_table():
    md = generate_markdown(_make_report(), style="full")
    assert "| Category | Grade | Score |" in md
    assert "Code Safety" in md


def test_full_contains_findings_table():
    md = generate_markdown(_make_report(), style="full")
    assert "| Severity | Title | File | Confidence |" in md
    assert "Test issue" in md
    assert "`src/main.py:42`" in md
    assert "0.95" in md


def test_summary_has_no_findings_table():
    md = generate_markdown(_make_report(), style="summary")
    assert "| Severity | Title | File | Confidence |" not in md
    assert "1 findings found" in md


def test_summary_has_header_and_categories():
    md = generate_markdown(_make_report(), style="summary")
    assert "## Skills Verified" in md
    assert "| Category | Grade | Score |" in md


def test_no_findings():
    report = _make_report(findings=[], score=100, grade=Grade.A)
    md = generate_markdown(report, style="full")
    assert "A (100/100)" in md
    assert "| Severity | Title | File | Confidence |" not in md


def test_finding_without_file():
    f = _make_finding(file_path=None, line_number=None)
    report = _make_report(findings=[f])
    md = generate_markdown(report, style="full")
    assert "N/A" in md


def test_repo_url_in_output():
    md = generate_markdown(_make_report(), style="full")
    assert "test/repo" in md


def test_scan_duration_in_output():
    md = generate_markdown(_make_report(), style="full")
    assert "1.5s" in md


def test_analyzers_count_in_output():
    md = generate_markdown(_make_report(), style="full")
    assert "2" in md


def test_save_markdown(tmp_path):
    path = tmp_path / "report.md"
    save_markdown(_make_report(), style="full", path=path)
    assert path.exists()
    content = path.read_text()
    assert "## Skills Verified" in content
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/test_markdown_report.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement Markdown report module**

Create `src/skills_verified/output/markdown_report.py`:

```python
from pathlib import Path

from skills_verified.core.models import Report, Severity


def generate_markdown(report: Report, style: str = "full") -> str:
    lines: list[str] = []

    lines.append(
        f"## Skills Verified -- Trust Score: "
        f"{report.overall_grade.value} ({report.overall_score}/100)"
    )
    lines.append("")
    lines.append(f"**Repository:** `{report.repo_url}`")
    lines.append(
        f"**Scan duration:** {report.scan_duration_seconds}s | "
        f"**Analyzers:** {len(report.analyzers_used)}"
    )
    lines.append("")

    # Summary table
    severity_counts = {}
    for sev in Severity:
        count = sum(1 for f in report.findings if f.severity == sev)
        severity_counts[sev] = count

    lines.append("### Summary")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in Severity:
        if sev == Severity.INFO:
            continue
        lines.append(f"| {sev.value.upper()} | {severity_counts[sev]} |")
    lines.append("")

    # Categories table
    lines.append("### Categories")
    lines.append("| Category | Grade | Score |")
    lines.append("|----------|-------|-------|")
    for cs in report.categories:
        cat_name = cs.category.value.replace("_", " ").title()
        lines.append(f"| {cat_name} | {cs.grade.value} | {cs.score} |")
    lines.append("")

    # Findings table (full only, skip if no findings)
    if style == "full" and report.findings:
        sorted_findings = sorted(
            report.findings,
            key=lambda f: list(Severity).index(f.severity),
        )
        lines.append("### Findings")
        lines.append("")
        lines.append("| Severity | Title | File | Confidence |")
        lines.append("|----------|-------|------|------------|")
        for f in sorted_findings:
            if f.file_path:
                loc = f"`{f.file_path}"
                if f.line_number:
                    loc += f":{f.line_number}"
                loc += "`"
            else:
                loc = "N/A"
            lines.append(
                f"| {f.severity.value.upper()} | {f.title} | {loc} | {f.confidence} |"
            )
        lines.append("")
    elif style == "summary" and report.findings:
        lines.append(
            f"> {len(report.findings)} findings found. "
            f"Run full scan for details."
        )
        lines.append("")

    return "\n".join(lines)


def save_markdown(report: Report, style: str, path: Path) -> None:
    content = generate_markdown(report, style=style)
    path.write_text(content)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/test_markdown_report.py -v`
Expected: all 12 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/skills_verified/output/markdown_report.py tests/test_markdown_report.py
git commit -m "feat: add Markdown report output module with full/summary styles"
```

---

### Task 5: Threshold Logic and Exit Codes

**Files:**
- Create: `tests/test_threshold.py`
- Modify: `src/skills_verified/cli.py`

- [ ] **Step 1: Write failing tests for threshold logic**

Create `tests/test_threshold.py`:

```python
from skills_verified.core.models import Grade


# Threshold checking is a pure function — extract it from CLI for testability
from skills_verified.cli import check_threshold


def test_no_threshold_passes():
    passed = check_threshold(
        score=30, grade=Grade.F, threshold=None, threshold_grade=None
    )
    assert passed is True


def test_score_threshold_passes():
    passed = check_threshold(
        score=80, grade=Grade.B, threshold=70, threshold_grade=None
    )
    assert passed is True


def test_score_threshold_fails():
    passed = check_threshold(
        score=60, grade=Grade.C, threshold=70, threshold_grade=None
    )
    assert passed is False


def test_score_threshold_exact_boundary_passes():
    passed = check_threshold(
        score=70, grade=Grade.C, threshold=70, threshold_grade=None
    )
    assert passed is True


def test_grade_threshold_passes():
    passed = check_threshold(
        score=85, grade=Grade.B, threshold=None, threshold_grade="C"
    )
    assert passed is True


def test_grade_threshold_exact_match_passes():
    passed = check_threshold(
        score=70, grade=Grade.C, threshold=None, threshold_grade="C"
    )
    assert passed is True


def test_grade_threshold_fails():
    passed = check_threshold(
        score=45, grade=Grade.F, threshold=None, threshold_grade="C"
    )
    assert passed is False


def test_both_thresholds_both_pass():
    passed = check_threshold(
        score=90, grade=Grade.A, threshold=70, threshold_grade="B"
    )
    assert passed is True


def test_both_thresholds_score_fails():
    passed = check_threshold(
        score=60, grade=Grade.C, threshold=70, threshold_grade="D"
    )
    assert passed is False


def test_both_thresholds_grade_fails():
    passed = check_threshold(
        score=90, grade=Grade.A, threshold=70, threshold_grade="A"
    )
    # score=90 >= 70: OK. grade=A >= A: OK. Both pass.
    assert passed is True


def test_both_thresholds_grade_fails_d_vs_c():
    passed = check_threshold(
        score=80, grade=Grade.D, threshold=50, threshold_grade="C"
    )
    # score=80 >= 50: OK. grade=D worse than C: FAIL.
    assert passed is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/test_threshold.py -v`
Expected: FAIL — `ImportError: cannot import name 'check_threshold'`

- [ ] **Step 3: Add `check_threshold` function to cli.py**

Add the following function at the top of `src/skills_verified/cli.py`, after the imports and before the `console = Console()` line:

```python
GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


def check_threshold(
    score: int,
    grade: Grade,
    threshold: int | None,
    threshold_grade: str | None,
) -> bool:
    if threshold is None and threshold_grade is None:
        return True
    if threshold is not None and score < threshold:
        return False
    if threshold_grade is not None:
        if GRADE_ORDER[grade.value] > GRADE_ORDER[threshold_grade]:
            return False
    return True
```

This requires adding `Grade` to the existing import from `skills_verified.core.models` (it's already imported via `scorer` but not directly — add to the import that uses `Pipeline`). Actually, `Grade` is not directly imported in `cli.py`. Add it:

In `src/skills_verified/cli.py`, add this import at the top with the other imports:

```python
from skills_verified.core.models import Grade
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/test_threshold.py -v`
Expected: all 11 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tests/test_threshold.py src/skills_verified/cli.py
git commit -m "feat: add check_threshold function with score and grade support"
```

---

### Task 6: CLI Integration — New Flags, Format Dispatch, Exit Codes

**Files:**
- Modify: `src/skills_verified/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write failing CLI tests for new flags**

Append to `tests/test_cli.py`:

```python
import json


def test_cli_threshold_pass(fake_repo_path):
    runner = CliRunner()
    result = runner.invoke(main, [
        str(fake_repo_path), "--only", "guardrails", "--threshold", "0",
    ])
    assert result.exit_code == 0


def test_cli_threshold_fail(fake_repo_path):
    runner = CliRunner()
    result = runner.invoke(main, [
        str(fake_repo_path), "--only", "guardrails", "--threshold", "100",
    ])
    assert result.exit_code == 1


def test_cli_threshold_grade_pass(fake_repo_path):
    runner = CliRunner()
    result = runner.invoke(main, [
        str(fake_repo_path), "--only", "guardrails", "--threshold-grade", "F",
    ])
    assert result.exit_code == 0


def test_cli_threshold_grade_fail(fake_repo_path):
    runner = CliRunner()
    result = runner.invoke(main, [
        str(fake_repo_path), "--only", "guardrails", "--threshold-grade", "A",
        "--threshold", "100",
    ])
    # Unless the repo is perfect, this should fail
    assert result.exit_code == 1


def test_cli_format_badge(fake_repo_path, tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, [
        str(fake_repo_path), "--only", "guardrails",
        "--format", "badge", "--output-dir", str(tmp_path),
    ])
    assert result.exit_code == 0
    badge_path = tmp_path / "badge.json"
    assert badge_path.exists()
    data = json.loads(badge_path.read_text())
    assert data["schemaVersion"] == 1


def test_cli_format_markdown(fake_repo_path, tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, [
        str(fake_repo_path), "--only", "guardrails",
        "--format", "markdown", "--output-dir", str(tmp_path),
    ])
    assert result.exit_code == 0
    md_path = tmp_path / "report.md"
    assert md_path.exists()
    assert "## Skills Verified" in md_path.read_text()


def test_cli_format_codeclimate(fake_repo_path, tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, [
        str(fake_repo_path), "--only", "guardrails",
        "--format", "codeclimate", "--output-dir", str(tmp_path),
    ])
    assert result.exit_code == 0
    cc_path = tmp_path / "gl-code-quality-report.json"
    assert cc_path.exists()
    data = json.loads(cc_path.read_text())
    assert isinstance(data, list)


def test_cli_markdown_style_summary(fake_repo_path, tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, [
        str(fake_repo_path), "--only", "guardrails",
        "--format", "markdown", "--output-dir", str(tmp_path),
        "--markdown-style", "summary",
    ])
    assert result.exit_code == 0
    md_path = tmp_path / "report.md"
    content = md_path.read_text()
    assert "| Severity | Title | File | Confidence |" not in content


def test_cli_error_exit_code():
    runner = CliRunner()
    result = runner.invoke(main, ["/nonexistent/path/xyz123"])
    assert result.exit_code == 2
```

- [ ] **Step 2: Run new tests to verify they fail**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/test_cli.py::test_cli_threshold_pass tests/test_cli.py::test_cli_format_badge -v`
Expected: FAIL — unrecognized option `--threshold` / `--format`

- [ ] **Step 3: Update CLI with new options and format dispatch**

Replace the entire `src/skills_verified/cli.py` with:

```python
import sys
from pathlib import Path

import click
from rich.console import Console

from skills_verified.analyzers.bandit_analyzer import BanditAnalyzer
from skills_verified.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skills_verified.analyzers.config_injection_analyzer import ConfigInjectionAnalyzer
from skills_verified.analyzers.cve_analyzer import CveAnalyzer
from skills_verified.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from skills_verified.analyzers.guardrails_analyzer import GuardrailsAnalyzer
from skills_verified.analyzers.known_threats_analyzer import KnownThreatsAnalyzer
from skills_verified.analyzers.llm_analyzer import LlmAnalyzer, LlmConfig
from skills_verified.analyzers.mcp_analyzer import MCPAnalyzer
from skills_verified.analyzers.metadata_analyzer import MetadataAnalyzer
from skills_verified.analyzers.obfuscation_analyzer import ObfuscationAnalyzer
from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.analyzers.permissions_analyzer import PermissionsAnalyzer
from skills_verified.analyzers.privilege_analyzer import PrivilegeAnalyzer
from skills_verified.analyzers.reverse_shell_analyzer import ReverseShellAnalyzer
from skills_verified.analyzers.semgrep_analyzer import SemgrepAnalyzer
from skills_verified.analyzers.supply_chain_analyzer import SupplyChainAnalyzer
from skills_verified.core.models import Grade
from skills_verified.core.pipeline import Pipeline
from skills_verified.output.badge import save_badge
from skills_verified.output.codeclimate import save_codeclimate
from skills_verified.output.console import render_report
from skills_verified.output.github_annotations import print_annotations
from skills_verified.output.json_report import save_json_report
from skills_verified.output.markdown_report import save_markdown
from skills_verified.repo.fetcher import fetch_repo, is_git_url

console = Console()

GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


def check_threshold(
    score: int,
    grade: Grade,
    threshold: int | None,
    threshold_grade: str | None,
) -> bool:
    if threshold is None and threshold_grade is None:
        return True
    if threshold is not None and score < threshold:
        return False
    if threshold_grade is not None:
        if GRADE_ORDER[grade.value] > GRADE_ORDER[threshold_grade]:
            return False
    return True


@click.command("skills-verified")
@click.argument("source")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save JSON report to file")
@click.option("--skip", type=str, default=None, help="Comma-separated analyzer names to skip")
@click.option("--only", type=str, default=None, help="Comma-separated analyzer names to run exclusively")
@click.option("--llm-url", type=str, default=None, envvar="SV_LLM_URL", help="OpenAI-compatible API base URL")
@click.option("--llm-model", type=str, default=None, envvar="SV_LLM_MODEL", help="LLM model name")
@click.option("--llm-key", type=str, default=None, envvar="SV_LLM_KEY", help="LLM API key")
@click.option("--threshold", type=click.IntRange(0, 100), default=None, help="Minimum trust score (0-100); exit 1 if below")
@click.option("--threshold-grade", type=click.Choice(["A", "B", "C", "D", "F"], case_sensitive=False), default=None, help="Minimum grade; exit 1 if worse")
@click.option("--format", "formats", type=click.Choice(["json", "codeclimate", "badge", "github", "markdown"], case_sensitive=False), multiple=True, help="Output formats (repeatable)")
@click.option("--output-dir", type=click.Path(file_okay=False), default=".", help="Directory for format artifacts")
@click.option("--markdown-style", type=click.Choice(["full", "summary"], case_sensitive=False), default="full", help="Markdown report detail level")
def main(
    source: str,
    output: str | None,
    skip: str | None,
    only: str | None,
    llm_url: str | None,
    llm_model: str | None,
    llm_key: str | None,
    threshold: int | None,
    threshold_grade: str | None,
    formats: tuple[str, ...],
    output_dir: str,
    markdown_style: str,
) -> None:
    """Skills Verified -- AI Agent Trust Scanner.

    Analyze a repository for vulnerabilities and compute a Trust Score.

    SOURCE can be a GitHub URL or a local path.
    """
    llm_config = None
    if llm_url and llm_model and llm_key:
        llm_config = LlmConfig(url=llm_url, model=llm_model, key=llm_key)

    all_analyzers = [
        PatternAnalyzer(),
        CveAnalyzer(),
        BanditAnalyzer(),
        SemgrepAnalyzer(),
        GuardrailsAnalyzer(),
        PermissionsAnalyzer(),
        SupplyChainAnalyzer(),
        LlmAnalyzer(config=llm_config),
        ObfuscationAnalyzer(),
        ReverseShellAnalyzer(),
        ExfiltrationAnalyzer(),
        BehavioralAnalyzer(),
        MCPAnalyzer(),
        ConfigInjectionAnalyzer(),
        MetadataAnalyzer(),
        KnownThreatsAnalyzer(),
        PrivilegeAnalyzer(),
    ]

    skip_set = set(skip.split(",")) if skip else set()
    only_set = set(only.split(",")) if only else None

    analyzers = []
    for a in all_analyzers:
        if a.name in skip_set:
            continue
        if only_set is not None and a.name not in only_set:
            continue
        analyzers.append(a)

    try:
        repo_path = fetch_repo(source)
    except (ValueError, Exception) as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(2)

    pipeline = Pipeline(analyzers=analyzers)
    report = pipeline.run(
        repo_path=repo_path,
        repo_url=source,
        llm_used=llm_config is not None,
    )

    render_report(report, console=console)

    if output:
        save_json_report(report, Path(output))
        console.print(f"  [dim]JSON report saved to {output}[/dim]\n")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if "json" in formats and not output:
        save_json_report(report, out / "report.json")
        console.print(f"  [dim]JSON report saved to {out / 'report.json'}[/dim]\n")

    if "codeclimate" in formats:
        save_codeclimate(report.findings, out / "gl-code-quality-report.json")
        console.print("  [dim]Code Climate report saved[/dim]\n")

    if "badge" in formats:
        save_badge(
            score=report.overall_score,
            grade=report.overall_grade,
            path=out / "badge.json",
        )
        console.print("  [dim]Badge JSON saved[/dim]\n")

    if "github" in formats:
        print_annotations(report.findings)

    if "markdown" in formats:
        save_markdown(report, style=markdown_style, path=out / "report.md")
        console.print("  [dim]Markdown report saved[/dim]\n")

    passed = check_threshold(
        score=report.overall_score,
        grade=report.overall_grade,
        threshold=threshold,
        threshold_grade=threshold_grade,
    )
    if not passed:
        console.print(
            f"  [red bold]THRESHOLD FAILED:[/red bold] "
            f"score={report.overall_score}, grade={report.overall_grade.value}"
        )
        if threshold is not None:
            console.print(f"    Required score >= {threshold}")
        if threshold_grade is not None:
            console.print(f"    Required grade >= {threshold_grade}")
        console.print()
        sys.exit(1)
```

- [ ] **Step 4: Run all CLI tests**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/test_cli.py -v`
Expected: all tests PASS (old and new)

- [ ] **Step 5: Run full test suite to check for regressions**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/ -v --ignore=tests/test_integration.py`
Expected: all tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/skills_verified/cli.py tests/test_cli.py
git commit -m "feat: add threshold flags, format dispatch, and exit codes to CLI"
```

---

### Task 7: Reusable GitHub Action

**Files:**
- Create: `action.yml`

- [ ] **Step 1: Create action.yml**

Create `action.yml` in the repository root:

```yaml
name: 'Skills Verified — AI Agent Trust Scanner'
description: 'Scan a repository for vulnerabilities and compute a Trust Score'
branding:
  icon: 'shield'
  color: 'blue'

inputs:
  source:
    description: 'Path or URL to scan'
    required: false
    default: '.'
  threshold:
    description: 'Minimum trust score (0-100)'
    required: false
  threshold-grade:
    description: 'Minimum grade (A/B/C/D/F)'
    required: false
  skip:
    description: 'Comma-separated analyzer names to skip'
    required: false
  only:
    description: 'Comma-separated analyzer names to run exclusively'
    required: false
  use-docker:
    description: 'Use Docker image instead of pip install'
    required: false
    default: 'false'
  python-version:
    description: 'Python version (when not using Docker)'
    required: false
    default: '3.11'
  comment-on-pr:
    description: 'Post Markdown comment on PR'
    required: false
    default: 'true'
  comment-style:
    description: 'Comment detail level: full or summary'
    required: false
    default: 'full'
  generate-badge:
    description: 'Generate badge.json artifact'
    required: false
    default: 'true'

outputs:
  score:
    description: 'Overall trust score (0-100)'
    value: ${{ steps.scan.outputs.score }}
  grade:
    description: 'Overall grade (A-F)'
    value: ${{ steps.scan.outputs.grade }}
  passed:
    description: 'Whether the threshold check passed'
    value: ${{ steps.scan.outputs.passed }}
  report-path:
    description: 'Path to the JSON report'
    value: ${{ steps.scan.outputs.report_path }}

runs:
  using: 'composite'
  steps:
    - name: Setup Python
      if: inputs.use-docker != 'true'
      uses: actions/setup-python@v5
      with:
        python-version: ${{ inputs.python-version }}

    - name: Install skills-verified (pip)
      if: inputs.use-docker != 'true'
      shell: bash
      run: |
        pip install -e "${{ github.action_path }}[dev]" bandit semgrep pip-audit

    - name: Pull Docker image
      if: inputs.use-docker == 'true'
      shell: bash
      run: |
        docker build -t skills-verified "${{ github.action_path }}"

    - name: Run scan
      id: scan
      shell: bash
      run: |
        set +e
        REPORT_DIR="${{ runner.temp }}/sv-reports"
        mkdir -p "$REPORT_DIR"

        FORMATS="github"
        if [ "${{ inputs.generate-badge }}" = "true" ]; then
          FORMATS="$FORMATS --format badge"
        fi
        if [ "${{ inputs.comment-on-pr }}" = "true" ]; then
          FORMATS="$FORMATS --format markdown"
        fi

        CMD_ARGS="${{ inputs.source }}"
        CMD_ARGS="$CMD_ARGS --output $REPORT_DIR/report.json"
        CMD_ARGS="$CMD_ARGS --format $FORMATS"
        CMD_ARGS="$CMD_ARGS --output-dir $REPORT_DIR"
        CMD_ARGS="$CMD_ARGS --markdown-style ${{ inputs.comment-style }}"

        if [ -n "${{ inputs.threshold }}" ]; then
          CMD_ARGS="$CMD_ARGS --threshold ${{ inputs.threshold }}"
        fi
        if [ -n "${{ inputs.threshold-grade }}" ]; then
          CMD_ARGS="$CMD_ARGS --threshold-grade ${{ inputs.threshold-grade }}"
        fi
        if [ -n "${{ inputs.skip }}" ]; then
          CMD_ARGS="$CMD_ARGS --skip ${{ inputs.skip }}"
        fi
        if [ -n "${{ inputs.only }}" ]; then
          CMD_ARGS="$CMD_ARGS --only ${{ inputs.only }}"
        fi

        if [ "${{ inputs.use-docker }}" = "true" ]; then
          docker run --rm \
            -v "${{ github.workspace }}:/workspace" \
            -v "$REPORT_DIR:/reports" \
            skills-verified $CMD_ARGS
        else
          skills-verified $CMD_ARGS
        fi
        EXIT_CODE=$?

        # Parse report for outputs
        if [ -f "$REPORT_DIR/report.json" ]; then
          SCORE=$(python3 -c "import json; print(json.load(open('$REPORT_DIR/report.json'))['overall_score'])")
          GRADE=$(python3 -c "import json; print(json.load(open('$REPORT_DIR/report.json'))['overall_grade'])")
          echo "score=$SCORE" >> "$GITHUB_OUTPUT"
          echo "grade=$GRADE" >> "$GITHUB_OUTPUT"
          echo "report_path=$REPORT_DIR/report.json" >> "$GITHUB_OUTPUT"
        fi

        if [ $EXIT_CODE -eq 0 ]; then
          echo "passed=true" >> "$GITHUB_OUTPUT"
        else
          echo "passed=false" >> "$GITHUB_OUTPUT"
        fi

        # Write Job Summary
        if [ -f "$REPORT_DIR/report.md" ]; then
          cat "$REPORT_DIR/report.md" >> "$GITHUB_STEP_SUMMARY"
        fi

        exit $EXIT_CODE

    - name: Comment on PR
      if: always() && inputs.comment-on-pr == 'true' && github.event_name == 'pull_request'
      shell: bash
      env:
        GH_TOKEN: ${{ github.token }}
      run: |
        REPORT_DIR="${{ runner.temp }}/sv-reports"
        if [ -f "$REPORT_DIR/report.md" ]; then
          gh pr comment "${{ github.event.pull_request.number }}" \
            --body-file "$REPORT_DIR/report.md" \
            --repo "${{ github.repository }}"
        fi

    - name: Upload artifacts
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: skills-verified-report
        path: |
          ${{ runner.temp }}/sv-reports/report.json
          ${{ runner.temp }}/sv-reports/badge.json
          ${{ runner.temp }}/sv-reports/report.md
        if-no-files-found: ignore
```

- [ ] **Step 2: Validate YAML syntax**

Run: `cd /home/mr8bit/Project/skills_verified && python3 -c "import yaml; yaml.safe_load(open('action.yml')); print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add action.yml
git commit -m "feat: add reusable GitHub Action for skills-verified"
```

---

### Task 8: GitLab CI Template

**Files:**
- Create: `templates/gitlab-ci-skills-verified.yml`

- [ ] **Step 1: Create templates directory and template file**

Create `templates/gitlab-ci-skills-verified.yml`:

```yaml
# Skills Verified — GitLab CI Template
#
# Usage:
#   include:
#     - remote: 'https://raw.githubusercontent.com/your-org/skills-verified/main/templates/gitlab-ci-skills-verified.yml'
#
#   variables:
#     SV_THRESHOLD: "70"
#     SV_THRESHOLD_GRADE: "C"

variables:
  SV_SOURCE: "."
  SV_THRESHOLD: ""
  SV_THRESHOLD_GRADE: ""
  SV_SKIP: ""
  SV_ONLY: ""
  SV_USE_DOCKER: "false"
  SV_COMMENT_ON_MR: "true"
  SV_COMMENT_STYLE: "full"
  SV_GENERATE_BADGE: "true"

.skills-verified-pip:
  image: python:3.11
  stage: test
  script:
    - pip install -e ".[dev]" bandit semgrep pip-audit
    - |
      CMD="skills-verified ${SV_SOURCE}"
      CMD="$CMD --output report.json"
      CMD="$CMD --format codeclimate --format markdown"
      CMD="$CMD --output-dir ."
      CMD="$CMD --markdown-style ${SV_COMMENT_STYLE}"

      if [ -n "$SV_THRESHOLD" ]; then
        CMD="$CMD --threshold $SV_THRESHOLD"
      fi
      if [ -n "$SV_THRESHOLD_GRADE" ]; then
        CMD="$CMD --threshold-grade $SV_THRESHOLD_GRADE"
      fi
      if [ -n "$SV_SKIP" ]; then
        CMD="$CMD --skip $SV_SKIP"
      fi
      if [ -n "$SV_ONLY" ]; then
        CMD="$CMD --only $SV_ONLY"
      fi
      if [ "$SV_GENERATE_BADGE" = "true" ]; then
        CMD="$CMD --format badge"
      fi

      eval $CMD
      SCAN_EXIT=$?

      # Post MR comment
      if [ "$SV_COMMENT_ON_MR" = "true" ] && [ -n "$CI_MERGE_REQUEST_IID" ] && [ -f report.md ]; then
        BODY=$(cat report.md)
        curl --silent --request POST \
          --header "PRIVATE-TOKEN: ${CI_JOB_TOKEN}" \
          "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/merge_requests/${CI_MERGE_REQUEST_IID}/notes" \
          --data-urlencode "body=${BODY}"
      fi

      exit $SCAN_EXIT
  artifacts:
    paths:
      - report.json
      - report.md
      - badge.json
    reports:
      codequality: gl-code-quality-report.json
    when: always

.skills-verified-docker:
  image: docker:latest
  services:
    - docker:dind
  stage: test
  script:
    - docker build -t skills-verified .
    - |
      DOCKER_CMD="docker run --rm"
      DOCKER_CMD="$DOCKER_CMD -v $(pwd):/workspace"
      DOCKER_CMD="$DOCKER_CMD -v $(pwd)/reports:/reports"

      ARGS="/workspace"
      ARGS="$ARGS --output /reports/report.json"
      ARGS="$ARGS --format codeclimate --format markdown"
      ARGS="$ARGS --output-dir /reports"
      ARGS="$ARGS --markdown-style ${SV_COMMENT_STYLE}"

      if [ -n "$SV_THRESHOLD" ]; then
        ARGS="$ARGS --threshold $SV_THRESHOLD"
      fi
      if [ -n "$SV_THRESHOLD_GRADE" ]; then
        ARGS="$ARGS --threshold-grade $SV_THRESHOLD_GRADE"
      fi
      if [ -n "$SV_SKIP" ]; then
        ARGS="$ARGS --skip $SV_SKIP"
      fi
      if [ -n "$SV_ONLY" ]; then
        ARGS="$ARGS --only $SV_ONLY"
      fi
      if [ "$SV_GENERATE_BADGE" = "true" ]; then
        ARGS="$ARGS --format badge"
      fi

      eval $DOCKER_CMD skills-verified $ARGS
      SCAN_EXIT=$?

      # Copy artifacts from reports dir
      cp reports/* . 2>/dev/null || true

      # Post MR comment
      if [ "$SV_COMMENT_ON_MR" = "true" ] && [ -n "$CI_MERGE_REQUEST_IID" ] && [ -f report.md ]; then
        # Need curl for this — install in docker:latest
        apk add --no-cache curl
        BODY=$(cat report.md)
        curl --silent --request POST \
          --header "PRIVATE-TOKEN: ${CI_JOB_TOKEN}" \
          "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/merge_requests/${CI_MERGE_REQUEST_IID}/notes" \
          --data-urlencode "body=${BODY}"
      fi

      exit $SCAN_EXIT
  artifacts:
    paths:
      - report.json
      - report.md
      - badge.json
    reports:
      codequality: gl-code-quality-report.json
    when: always
```

- [ ] **Step 2: Validate YAML syntax**

Run: `cd /home/mr8bit/Project/skills_verified && python3 -c "import yaml; yaml.safe_load(open('templates/gitlab-ci-skills-verified.yml')); print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add templates/gitlab-ci-skills-verified.yml
git commit -m "feat: add GitLab CI includable template"
```

---

### Task 9: Example Workflows

**Files:**
- Create: `examples/github-actions/basic.yml`
- Create: `examples/github-actions/full.yml`
- Create: `examples/github-actions/monorepo.yml`
- Create: `examples/gitlab-ci/basic.yml`
- Create: `examples/gitlab-ci/full.yml`
- Create: `examples/gitlab-ci/monorepo.yml`
- Create: `examples/README.md`

- [ ] **Step 1: Create GitHub Actions basic example**

Create `examples/github-actions/basic.yml`:

```yaml
# Minimal Skills Verified scan with threshold gate
name: Security Scan

on: [push, pull_request]

jobs:
  trust-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Skills Verified
        uses: your-org/skills-verified@v1
        with:
          threshold: 70
          threshold-grade: C
```

- [ ] **Step 2: Create GitHub Actions full example**

Create `examples/github-actions/full.yml`:

```yaml
# Full-featured Skills Verified scan
# Includes: annotations, PR comment, badge, Docker option
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  trust-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Skills Verified
        id: scan
        uses: your-org/skills-verified@v1
        with:
          threshold: 70
          threshold-grade: C
          comment-on-pr: 'true'
          comment-style: full
          generate-badge: 'true'

      - name: Print results
        if: always()
        run: |
          echo "Score: ${{ steps.scan.outputs.score }}"
          echo "Grade: ${{ steps.scan.outputs.grade }}"
          echo "Passed: ${{ steps.scan.outputs.passed }}"

  # Alternative: Docker-based scan
  trust-scan-docker:
    runs-on: ubuntu-latest
    if: false  # Enable by removing this line
    steps:
      - uses: actions/checkout@v4

      - name: Run Skills Verified (Docker)
        uses: your-org/skills-verified@v1
        with:
          threshold: 70
          use-docker: 'true'
          comment-style: summary
```

- [ ] **Step 3: Create GitHub Actions monorepo example**

Create `examples/github-actions/monorepo.yml`:

```yaml
# Scan multiple directories in a monorepo
name: Security Scan (Monorepo)

on:
  push:
    branches: [main]
  pull_request:

jobs:
  trust-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        path: [services/auth, services/api, plugins/formatter]
      fail-fast: false
    steps:
      - uses: actions/checkout@v4

      - name: Run Skills Verified on ${{ matrix.path }}
        uses: your-org/skills-verified@v1
        with:
          source: ${{ matrix.path }}
          threshold: 70
          threshold-grade: C
          comment-style: summary
```

- [ ] **Step 4: Create GitLab CI basic example**

Create `examples/gitlab-ci/basic.yml`:

```yaml
# Minimal Skills Verified scan with threshold gate
include:
  - remote: 'https://raw.githubusercontent.com/your-org/skills-verified/main/templates/gitlab-ci-skills-verified.yml'

skills-verified:
  extends: .skills-verified-pip
  variables:
    SV_THRESHOLD: "70"
    SV_THRESHOLD_GRADE: "C"
```

- [ ] **Step 5: Create GitLab CI full example**

Create `examples/gitlab-ci/full.yml`:

```yaml
# Full-featured Skills Verified scan
# Includes: MR comment, badge, Code Quality, Docker option
include:
  - remote: 'https://raw.githubusercontent.com/your-org/skills-verified/main/templates/gitlab-ci-skills-verified.yml'

stages:
  - test

# Pip-based scan (default)
skills-verified:
  extends: .skills-verified-pip
  variables:
    SV_THRESHOLD: "70"
    SV_THRESHOLD_GRADE: "C"
    SV_COMMENT_ON_MR: "true"
    SV_COMMENT_STYLE: "full"
    SV_GENERATE_BADGE: "true"

# Docker-based scan (alternative)
# Uncomment to use instead of pip-based
# skills-verified-docker:
#   extends: .skills-verified-docker
#   variables:
#     SV_THRESHOLD: "70"
#     SV_COMMENT_STYLE: "summary"
```

- [ ] **Step 6: Create GitLab CI monorepo example**

Create `examples/gitlab-ci/monorepo.yml`:

```yaml
# Scan multiple directories in a monorepo
include:
  - remote: 'https://raw.githubusercontent.com/your-org/skills-verified/main/templates/gitlab-ci-skills-verified.yml'

stages:
  - test

skills-verified:
  extends: .skills-verified-pip
  parallel:
    matrix:
      - SV_SOURCE:
          - services/auth
          - services/api
          - plugins/formatter
  variables:
    SV_THRESHOLD: "70"
    SV_THRESHOLD_GRADE: "C"
    SV_COMMENT_STYLE: "summary"
```

- [ ] **Step 7: Create examples README**

Create `examples/README.md`:

```markdown
# Examples

Ready-to-use CI/CD configurations for Skills Verified.

## GitHub Actions

| File | Description |
|------|-------------|
| [basic.yml](github-actions/basic.yml) | Minimal scan with threshold gate |
| [full.yml](github-actions/full.yml) | All features: annotations, PR comment, badge |
| [monorepo.yml](github-actions/monorepo.yml) | Matrix strategy for multiple directories |

**Usage:** Copy the desired file to `.github/workflows/` in your repository.

## GitLab CI

| File | Description |
|------|-------------|
| [basic.yml](gitlab-ci/basic.yml) | Minimal scan with threshold and Code Quality |
| [full.yml](gitlab-ci/full.yml) | All features: MR comment, badge, Code Quality |
| [monorepo.yml](gitlab-ci/monorepo.yml) | Parallel matrix for multiple paths |

**Usage:** Copy the desired file content into your `.gitlab-ci.yml`.

## Configuration

All examples use `your-org/skills-verified` as the action/template source.
Replace with your actual repository path.

### Threshold

- `threshold` / `SV_THRESHOLD`: Minimum score (0-100). Job fails if below.
- `threshold-grade` / `SV_THRESHOLD_GRADE`: Minimum grade (A-F). Job fails if worse.
- Both can be used together — job fails if either condition is not met.

### Badge

Badge JSON is generated as an artifact. To display it in your README:

```markdown
![Trust Score](https://img.shields.io/endpoint?url=<URL_TO_BADGE_JSON>)
```

Host `badge.json` via GitHub Pages, GitLab Pages, or any public URL.
```

- [ ] **Step 8: Validate all YAML files**

Run: `cd /home/mr8bit/Project/skills_verified && python3 -c "
import yaml
from pathlib import Path
for f in Path('examples').rglob('*.yml'):
    yaml.safe_load(f.read_text())
    print(f'OK: {f}')
"`
Expected: all files print `OK`

- [ ] **Step 9: Commit**

```bash
git add examples/ templates/
git commit -m "feat: add CI/CD example workflows for GitHub Actions and GitLab CI"
```

---

### Task 10: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Read current CI/CD section of README**

Read `README.md` lines 584-656 (the current CI/CD section).

- [ ] **Step 2: Replace the CI/CD section**

Replace the existing "Интеграция с CI/CD" section (lines 584-656) with updated content that covers:

1. New CLI flags (`--threshold`, `--threshold-grade`, `--format`, etc.)
2. GitHub Action usage via `uses: your-org/skills-verified@v1`
3. GitLab CI template via `include: remote:`
4. Badge setup instructions
5. Links to `examples/` directory

The new section should include:

```markdown
## Интеграция с CI/CD

### Новые CLI-флаги для CI

| Флаг | Описание |
|------|----------|
| `--threshold N` | Минимальный score (0-100). Exit code 1 если ниже |
| `--threshold-grade GRADE` | Минимальный грейд (A/B/C/D/F). Exit code 1 если хуже |
| `--format FORMAT` | Дополнительные форматы: `codeclimate`, `badge`, `github`, `markdown` |
| `--output-dir DIR` | Директория для артефактов (по умолчанию `.`) |
| `--markdown-style STYLE` | Детализация Markdown-отчёта: `full` или `summary` |

Exit codes: `0` — проверка пройдена, `1` — порог не пройден, `2` — ошибка выполнения.

### GitHub Actions

**Reusable Action:**

```yaml
- uses: your-org/skills-verified@v1
  with:
    threshold: 70
    threshold-grade: C
    comment-on-pr: 'true'
    generate-badge: 'true'
```

Подробнее: [`action.yml`](action.yml) | [Примеры](examples/github-actions/)

### GitLab CI

**Includable Template:**

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/your-org/skills-verified/main/templates/gitlab-ci-skills-verified.yml'

skills-verified:
  extends: .skills-verified-pip
  variables:
    SV_THRESHOLD: "70"
    SV_THRESHOLD_GRADE: "C"
```

Подробнее: [`templates/`](templates/) | [Примеры](examples/gitlab-ci/)

### Badge

Добавьте в README:

```markdown
![Trust Score](https://img.shields.io/endpoint?url=<URL_TO_BADGE_JSON>)
```

`badge.json` генерируется через `--format badge` и сохраняется как артефакт.
Разместите его на GitHub Pages, GitLab Pages или любом публичном URL.
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: update CI/CD integration section in README"
```

---

### Task 11: Final Verification

- [ ] **Step 1: Run full test suite**

Run: `cd /home/mr8bit/Project/skills_verified && python -m pytest tests/ -v --ignore=tests/test_integration.py`
Expected: all tests PASS

- [ ] **Step 2: Run linter**

Run: `cd /home/mr8bit/Project/skills_verified && python -m ruff check src/ tests/`
Expected: no errors

- [ ] **Step 3: Test CLI manually with new flags**

Run: `cd /home/mr8bit/Project/skills_verified && python -m skills_verified tests/fixtures/fake_repo --format badge --format markdown --format codeclimate --output-dir /tmp/sv-test --threshold 50 --markdown-style full`

Verify:
- Exit code 0 or 1 depending on score
- `/tmp/sv-test/badge.json` exists and has valid JSON
- `/tmp/sv-test/report.md` exists and has Markdown content
- `/tmp/sv-test/gl-code-quality-report.json` exists and has valid JSON

- [ ] **Step 4: Test threshold failure**

Run: `cd /home/mr8bit/Project/skills_verified && python -m skills_verified tests/fixtures/fake_repo --threshold 100; echo "Exit: $?"`
Expected: `Exit: 1` with "THRESHOLD FAILED" message

- [ ] **Step 5: Verify all new files exist**

Run: `ls -la action.yml templates/ examples/github-actions/ examples/gitlab-ci/`
Expected: all files from the plan are present
