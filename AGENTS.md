# Repository Guidelines

## Project Structure & Module Organization

This is a Python 3.11+ security scanner using a `src` layout. Application code lives in `src/skills_verified/`: `cli.py` defines the Click entry point, `core/` contains models and the scan pipeline, `analyzers/` holds one analyzer per module, `platforms/` detects supported agent environments, and `output/` renders reports. Signature databases are YAML files under `data/`. Tests mirror features in `tests/test_*.py`; deliberately unsafe samples live in `tests/fixtures/fake_repo/`. Keep design notes in `docs/superpowers/`, CI examples in `examples/`, and generated scans out of version control (`reports/` and `workspace/` retain only `.gitkeep`).

## Build, Test, and Development Commands

Create a virtual environment, then install the package and developer tools:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

- `pytest tests/ -v` runs the full suite.
- `pytest tests/test_pattern_analyzer.py -v` runs one module.
- `pytest tests/ --cov=skills_verified --cov-report=term-missing` reports coverage.
- `ruff check src/ tests/` checks lint rules.
- `ruff format --check src/ tests/` verifies formatting; omit `--check` to apply it.
- `skills-verified --help` confirms the editable install and CLI entry point.
- `docker compose build` builds the image with optional external scanners.

## Coding Style & Naming Conventions

Use four-space indentation, Python 3.11 syntax, type hints for public interfaces, and Ruff-compatible formatting. Name modules, functions, and variables `snake_case`; classes use `PascalCase`; constants use `UPPER_SNAKE_CASE`. Analyzer implementations should subclass `Analyzer`, define a stable lowercase `name`, implement `is_available()` and `analyze()`, and be registered in `cli.py`. Prefer focused modules and reuse the shared `Finding`, `Severity`, and `Category` models.

## Testing Guidelines

Use pytest and name tests `test_<behavior>`. Add `tests/test_<analyzer>.py` for each analyzer and extend `tests/fixtures/fake_repo/` only when a realistic repository artifact is required. Follow the documented TDD flow: add a failing focused test, implement the change, then run the full suite. No minimum coverage percentage is configured, but new branches and regressions should be exercised.

## Commit & Pull Request Guidelines

Recent history follows Conventional Commit-style subjects such as `feat: add threshold logic`, `fix: remove unused imports`, and `docs: update CI/CD section`. Keep subjects imperative and scoped to one change. Pull requests should explain the behavior and security impact, link relevant issues, list verification commands, and include sample CLI/report output when output formats or workflows change. Never commit API keys, `.env`, generated reports, or scanned workspace contents.
