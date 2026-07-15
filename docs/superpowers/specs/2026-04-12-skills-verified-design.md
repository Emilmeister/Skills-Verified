# Skills Verified — AI Agent Trust Scanner

> **Status: Superseded.** Исторический документ; не использовать как актуальную спецификацию. Текущий контракт: [Policy-Free Scan Report Roadmap](./2026-07-13-policy-free-scan-report-roadmap.md).

**Date:** 2026-04-12
**Original status:** Approved

## Overview

CLI-утилита для сертификации AI-агентов. На вход принимает GitHub-репозиторий (URL или локальный путь), на выходе — список найденных уязвимостей и Trust Score (грейд A-F).

Стек: Python. Архитектура: Pipeline с плагинами — каждый анализатор реализует единый контракт `Analyzer`, pipeline запускает все доступные анализаторы, scorer вычисляет итоговый грейд.

## Architecture

### Project Structure

```
skills-verified/
├── src/
│   └── skills_verified/
│       ├── __init__.py
│       ├── cli.py                     # Точка входа (click)
│       ├── core/
│       │   ├── models.py              # Finding, Severity, Category, Grade, Report
│       │   ├── analyzer.py            # ABC Analyzer
│       │   ├── pipeline.py            # Запуск анализаторов, сбор результатов
│       │   └── scorer.py              # Trust Score → грейд A-F
│       ├── analyzers/
│       │   ├── pattern_analyzer.py    # Опасные паттерны (eval, exec, secrets)
│       │   ├── cve_analyzer.py        # CVE в зависимостях (pip-audit, npm audit)
│       │   ├── bandit_analyzer.py     # Обёртка над Bandit
│       │   ├── semgrep_analyzer.py    # Обёртка над Semgrep
│       │   ├── guardrails_analyzer.py # Prompt injection, jailbreak
│       │   ├── permissions_analyzer.py# Анализ полномочий агента
│       │   ├── supply_chain_analyzer.py# Typosquatting, подозрительные скрипты
│       │   └── llm_analyzer.py        # Семантический анализ через OpenAI-совместимый API
│       ├── repo/
│       │   └── fetcher.py             # git clone / локальный путь
│       └── output/
│           ├── console.py             # Rich-вывод
│           └── json_report.py         # JSON-отчёт
├── tests/
│   ├── fixtures/fake_repo/
│   ├── test_pattern_analyzer.py
│   ├── test_cve_analyzer.py
│   ├── test_guardrails_analyzer.py
│   ├── test_permissions_analyzer.py
│   ├── test_supply_chain_analyzer.py
│   ├── test_llm_analyzer.py
│   ├── test_scorer.py
│   ├── test_pipeline.py
│   └── test_cli.py
├── pyproject.toml
└── README.md
```

### Data Flow

```
CLI → fetcher (clone repo) → pipeline → [analyzer₁, analyzer₂, ...analyzerₙ] → scorer → output
```

## Data Models

### Enums

- **Severity**: CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Category**: CODE_SAFETY, CVE, GUARDRAILS, PERMISSIONS, SUPPLY_CHAIN
- **Grade**: A (90-100), B (80-89), C (65-79), D (50-64), F (0-49)

### Finding

| Field | Type | Description |
|-------|------|-------------|
| title | str | Краткое описание проблемы |
| description | str | Подробности |
| severity | Severity | Уровень критичности |
| category | Category | Категория проверки |
| file_path | str \| None | Путь к файлу |
| line_number | int \| None | Номер строки |
| analyzer | str | Имя анализатора |
| cve_id | str \| None | CVE-ID если применимо |
| confidence | float | 0.0-1.0, для LLM-анализа |

### CategoryScore

| Field | Type | Description |
|-------|------|-------------|
| category | Category | Категория |
| score | int | 0-100 |
| grade | Grade | A-F |
| findings_count | int | Всего находок |
| critical_count | int | Критических |
| high_count | int | Высоких |

### Report

| Field | Type | Description |
|-------|------|-------------|
| repo_url | str | URL/путь репозитория |
| overall_score | int | 0-100 |
| overall_grade | Grade | A-F |
| categories | list[CategoryScore] | Оценки по категориям |
| findings | list[Finding] | Все находки |
| analyzers_used | list[str] | Использованные анализаторы |
| llm_used | bool | Был ли LLM-анализ |
| scan_duration_seconds | float | Время сканирования |

## Analyzer Contract

```python
class Analyzer(ABC):
    name: str

    @abstractmethod
    def is_available(self) -> bool:
        """True если инструмент установлен / доступен."""

    @abstractmethod
    def analyze(self, repo_path: Path) -> list[Finding]:
        """Запускает анализ, возвращает находки."""
```

- Если `is_available()` возвращает False — анализатор пропускается с предупреждением
- Исключения внутри `analyze()` ловятся pipeline, логируются, возвращается пустой список
- Анализаторы запускаются последовательно

## Analyzers Detail

### pattern_analyzer (встроенный)
- `eval()`, `exec()`, `compile()` с динамическими строками
- `subprocess` с `shell=True`
- Hardcoded секреты (API-ключи, токены, пароли по regex-паттернам)
- `pickle.load`, `yaml.load` без SafeLoader
- `os.system()`, `os.popen()`

### cve_analyzer (внешний: pip-audit, npm audit)
- Парсит `requirements.txt`, `Pipfile`, `pyproject.toml`, `package.json`, `package-lock.json`
- Запускает соответствующий аудит-инструмент
- Маппит результаты на CVE-ID и severity

### bandit_analyzer (внешний: bandit)
- Запускает `bandit -r <repo> -f json`
- Парсит JSON-вывод, маппит на Finding

### semgrep_analyzer (внешний: semgrep)
- Запускает с правилами `p/security-audit` + `p/python`
- Парсит JSON-вывод

### guardrails_analyzer (встроенный)
- Prompt injection: `ignore previous instructions`, `you are now`, `system:`, скрытые Unicode-символы
- Jailbreak-маркеры: `DAN`, `STAN`, `developer mode`
- Инструкции на обход ограничений в текстовых/markdown файлах
- Base64-закодированные подозрительные строки

### permissions_analyzer (встроенный)
- Файловые операции: `shutil.rmtree`, `os.remove`, запись за пределами рабочей директории
- Сетевые: `urllib`, `requests`, `httpx`, `socket`
- Процессы: `subprocess.Popen`, `os.kill`
- Соотношение полномочий с заявленной функцией skill

### supply_chain_analyzer (встроенный)
- Typosquatting: проверка имён пакетов через Levenshtein distance
- Подозрительные `postinstall`/`preinstall` скрипты в `package.json`
- `setup.py` с `os.system`/`subprocess` в install-хуках
- Загрузки из нестандартных источников

### llm_analyzer (опциональный, OpenAI-совместимый API)
- Семантический анализ кода на логические уязвимости
- Батчинг файлов по размеру контекстного окна
- Результаты с `confidence: 0.0-1.0`
- Включается при наличии `--llm-url`, `--llm-key`, `--llm-model`

## Scoring

- Стартовая оценка каждой категории: 100
- Штрафы по severity: CRITICAL = -25, HIGH = -15, MEDIUM = -7, LOW = -3, INFO = 0
- Минимум категории: 0
- Общий Trust Score: средневзвешенное по категориям (равные веса)
- Грейды: A (90-100), B (80-89), C (65-79), D (50-64), F (0-49)

## CLI Interface

```bash
# Базовый запуск
skills-verified https://github.com/user/repo

# С JSON-отчётом
skills-verified https://github.com/user/repo --output report.json

# С LLM-анализом
skills-verified https://github.com/user/repo \
  --llm-url https://api.openai.com/v1 \
  --llm-model gpt-4o \
  --llm-key sk-xxx

# Локальный путь
skills-verified /path/to/local/repo

# Пропустить анализаторы
skills-verified https://github.com/user/repo --skip bandit,semgrep

# Только определённые категории
skills-verified https://github.com/user/repo --only guardrails,supply_chain
```

### Environment Variables

```bash
SV_LLM_URL=https://api.openai.com/v1
SV_LLM_MODEL=gpt-4o
SV_LLM_KEY=sk-xxx
```

Приоритет: CLI-флаги > env-переменные.

## Console Output

Цветной Rich-вывод с таблицей категорий, группировкой findings по severity, прогресс-баром во время сканирования. Итоговый грейд крупно в рамке.

## Dependencies

### Core
- click — CLI
- rich — терминальный вывод
- gitpython — клонирование репо
- Levenshtein — typosquatting-детекция

### Optional [llm]
- openai — клиент для OpenAI-совместимых API

### Optional [dev]
- pytest, pytest-cov — тесты
- ruff — линтинг

### External Tools (опциональные, через subprocess)
- bandit, semgrep, pip-audit, npm

## Testing

- Unit-тесты для каждого анализатора с фикстурами (fake_repo с уязвимым и чистым кодом)
- Unit-тесты для scorer на граничных значениях грейдов
- Интеграционные тесты pipeline на тестовом репо
- Тесты CLI: парсинг аргументов, env-переменные
- Тесты JSON-отчёта: валидность структуры
