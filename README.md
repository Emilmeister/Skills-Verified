# Skills Verified

**AI Agent Trust Scanner** — CLI-утилита для сертификации репозиториев AI-агентов. Сканирует код на уязвимости, известные CVE, prompt injection, чрезмерные полномочия и проблемы supply chain, после чего выдаёт итоговый **Trust Score** в формате грейда A-F с разбивкой по категориям.

Инструмент создан для быстрой оценки безопасности репозиториев со skills, plugins и агентами до того, как их подключат к боевой системе. Работает как автономная CLI-утилита — установил, запустил, получил отчёт.

---

## Оглавление

- [Зачем это нужно](#зачем-это-нужно)
- [Возможности](#возможности)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [Анализаторы](#анализаторы)
- [Использование](#использование)
- [Trust Score](#trust-score)
- [Пример вывода](#пример-вывода)
- [Структура JSON-отчёта](#структура-json-отчёта)
- [Интеграция с CI/CD](#интеграция-с-cicd)
- [Архитектура](#архитектура)
- [Разработка](#разработка)
- [FAQ](#faq)
- [Лицензия](#лицензия)

---

## Зачем это нужно

Современные AI-агенты, skills и плагины часто получают доступ к критической инфраструктуре: файловой системе, сети, процессам, секретам. Код в таких репозиториях может содержать:

- **Опасные паттерны** — `eval`, `exec`, `shell=True`, hardcoded API-ключи, небезопасная десериализация
- **Известные уязвимости** в зависимостях (CVE)
- **Prompt injection** — скрытые инструкции, которые могут перехватить управление LLM
- **Jailbreak-маркеры** — DAN, STAN, developer mode и прочие обходы ограничений
- **Чрезмерные полномочия** — агент может удалить файлы, убить процессы или скачать что-то из интернета, хотя заявлен как "помощник по форматированию"
- **Supply chain атаки** — typosquatting, злонамеренные `postinstall`-скрипты, опасный код в `setup.py`

Skills Verified автоматизирует проверку всего перечисленного и выдаёт одну цифру — Trust Score, по которой легко принять решение: доверять репозиторию или нет.

---

## Возможности

- **8 анализаторов** — 6 встроенных и 2 опциональных (Bandit, Semgrep)
- **Опциональный LLM-анализ** через любой OpenAI-совместимый API (OpenAI, Anthropic через прокси, Ollama, vLLM, LM Studio)
- **Trust Score A-F** с разбивкой по 5 категориям
- **Цветной терминальный вывод** через Rich с таблицами и группировкой по severity
- **JSON-отчёт** для интеграции в CI/CD
- **Работа с GitHub URL** — автоматический `git clone --depth=1` во временный каталог
- **Работа с локальным путём** — сканирование уже скачанного репо
- **Фильтрация анализаторов** — `--skip` для исключения, `--only` для запуска только нужных
- **Graceful degradation** — если внешний инструмент (Bandit/Semgrep/pip-audit) не установлен, анализатор пропускается с предупреждением, остальные продолжают работу

---

## Установка

### Требования

- Python 3.11+
- git (для клонирования удалённых репозиториев)

### Базовая установка

```bash
git clone <repo-url> skills-verified
cd skills-verified

python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

pip install -e ".[dev]"
```

### С поддержкой LLM

```bash
pip install -e ".[llm]"
```

Устанавливает `openai` — клиент для OpenAI-совместимых API. Без этого ключа `llm_analyzer` не будет работать, даже если передать `--llm-url`.

### Внешние инструменты (опционально)

Эти инструменты необязательны — если они не установлены, соответствующие анализаторы будут автоматически пропущены. Но для максимального покрытия рекомендуется:

```bash
pip install bandit        # Статический анализ Python (Task B***)
pip install semgrep       # Semantic grep для security-audit правил
pip install pip-audit     # Проверка Python-зависимостей на CVE
# npm уже должен быть в системе для npm audit
```

### Проверка установки

```bash
skills-verified --help
```

Должна появиться справка с описанием всех флагов.

---

## Быстрый старт

```bash
# Просканировать GitHub-репозиторий одной командой
skills-verified https://github.com/Nikolay-Shirokov/cc-1c-skills

# Сохранить JSON-отчёт рядом с выводом в консоль
skills-verified https://github.com/user/repo --output report.json

# Запустить только быстрые анализаторы
skills-verified https://github.com/user/repo --skip bandit,semgrep,cve
```

---

## Анализаторы

### 1. Pattern Analyzer (встроенный, `pattern`)

Regex-поиск опасных паттернов в исходниках. Работает без внешних зависимостей.

**Что ищет:**

| Паттерн | Severity | Почему опасно |
|---|---|---|
| `eval()` | CRITICAL | Исполнение произвольного кода |
| `exec()` | CRITICAL | Исполнение произвольного кода |
| `compile()` | HIGH | Может использоваться для обхода eval |
| `shell=True` | HIGH | Shell injection |
| `os.system()` | HIGH | Shell injection |
| `os.popen()` | HIGH | Shell injection |
| `pickle.load()` | HIGH | Десериализация произвольного кода |
| `yaml.load()` без SafeLoader | MEDIUM | Десериализация произвольного кода |
| Hardcoded API keys/passwords | HIGH | Утечка секретов |

Сканирует: `.py`, `.js`, `.mjs`, `.ts`, `.sh`, `.bash`, `.ps1`, `.rb`

### 2. CVE Analyzer (внешний, `cve`)

Проверяет зависимости на известные CVE через официальные инструменты.

**Как работает:**
- Находит `requirements*.txt`, `Pipfile`, `pyproject.toml` → запускает `pip-audit`
- Находит `package-lock.json` → запускает `npm audit`
- Парсит JSON-вывод, маппит severity в единую шкалу, извлекает CVE-ID

**Требует:** `pip-audit` для Python, `npm` для Node.js

### 3. Bandit Analyzer (внешний, `bandit`)

Обёртка над [Bandit](https://github.com/PyCQA/bandit) — стандартным статическим анализатором Python от OpenStack. Находит вещи, которые regex не поймает: use-after-free в контекстах, подозрительные импорты, weak crypto и т.д.

**Требует:** `pip install bandit`

**Severity mapping:** Bandit HIGH → HIGH, MEDIUM → MEDIUM, LOW → LOW

### 4. Semgrep Analyzer (внешний, `semgrep`)

Обёртка над [Semgrep](https://semgrep.dev) с правилами `p/security-audit` и `p/python`. Semantic-grep — находит уязвимости на уровне AST, а не regex.

**Требует:** `pip install semgrep`

### 5. Guardrails Analyzer (встроенный, `guardrails`)

Поиск атак на LLM в текстовых файлах. Ключевой анализатор для AI-агентов.

**Что ищет:**

**Prompt injection паттерны:**
- `ignore (previous|prior|above) instructions` → CRITICAL
- `disregard your instructions` → CRITICAL
- `you are now ...` (роль-override) → HIGH
- `ignore all safety guidelines` → CRITICAL
- `output your system prompt` → HIGH

**Jailbreak маркеры:**
- `developer mode` → CRITICAL
- `DAN ... do anything` → CRITICAL
- `STAN ... strive to avoid` → CRITICAL

**Скрытые Unicode символы:** U+202A–U+202E (bidi-override), U+2066–U+2069, U+200B–U+200D (zero-width), U+FEFF (BOM), U+2060 (word joiner)

**Base64-инъекции:** декодирует подозрительные base64-строки и проверяет декодированное содержимое на ключевые слова (`ignore`, `system`, `prompt`, `jailbreak`, `override`)

Сканирует: `.md`, `.txt`, `.yaml`, `.yml`, `.json`, `.toml`, `.py`, `.js`, `.ts`

### 6. Permissions Analyzer (встроенный, `permissions`)

Анализ того, какие системные ресурсы использует код. Помогает оценить, соответствуют ли полномочия заявленной функции.

**Что ищет:**

| Категория | Паттерны | Severity |
|---|---|---|
| Деструктивные FS-операции | `shutil.rmtree` | HIGH |
| Удаление файлов | `os.remove`, `os.unlink`, `os.rmdir` | MEDIUM |
| Запуск процессов | `subprocess.Popen` | MEDIUM |
| Убийство процессов | `os.kill` | HIGH |
| HTTP-запросы | `requests.*`, `urllib.request.*`, `httpx.*` | LOW |
| Низкоуровневая сеть | `socket.socket` | MEDIUM |

### 7. Supply Chain Analyzer (встроенный, `supply_chain`)

Ищет атаки на цепочку поставок зависимостей.

**Что ищет:**

- **Typosquatting** — сравнивает имена зависимостей с популярными пакетами через расстояние Левенштейна. Пример: `reqeusts` vs `requests` (distance 1), `loadsh` vs `lodash` (distance 2)
- **Подозрительные lifecycle-скрипты** в `package.json` — `preinstall`, `postinstall`, `preuninstall`, `postuninstall` с командами `curl`, `wget`, `bash`, `sh`, `eval`, `exec`
- **Код в `setup.py`** — `os.system`, `subprocess.run/call/Popen`, `exec` — всё, что исполняется при установке пакета

Списки популярных пакетов — встроенные (20 для Python, 20 для npm). Легко расширяются в `supply_chain_analyzer.py`.

### 8. LLM Analyzer (опциональный, `llm`)

Семантический анализ кода через LLM. Находит логические ошибки, которые не ловят регулярки и AST-анализаторы:

- SQL injection через конкатенацию
- Race conditions
- Логические ошибки в авторизации
- Information disclosure
- Unsafe data handling в бизнес-логике

**Как работает:**

1. Собирает файлы с расширениями `.py`, `.js`, `.ts`, `.sh`, `.ps1`, `.rb`
2. Батчит их по размеру (по умолчанию 50 000 символов на батч)
3. Отправляет каждый батч в LLM с системным промптом, требующим JSON-ответ
4. Парсит ответ (поддерживает markdown code blocks), извлекает находки
5. Низкая confidence (<0.5) автоматически понижает CRITICAL/HIGH до MEDIUM

**Включается только при наличии всех трёх параметров:** `--llm-url`, `--llm-model`, `--llm-key`. Работает с любым OpenAI-совместимым API.

---

## Использование

### Базовые команды

```bash
# GitHub URL (автоматический clone)
skills-verified https://github.com/user/repo

# SSH URL
skills-verified git@github.com:user/repo.git

# Локальный путь
skills-verified /path/to/local/repo
skills-verified ./relative/path
skills-verified .
```

### Флаги

| Флаг | Описание |
|---|---|
| `--output, -o PATH` | Сохранить JSON-отчёт в файл |
| `--skip NAMES` | Пропустить анализаторы (через запятую) |
| `--only NAMES` | Запустить только указанные анализаторы |
| `--llm-url URL` | Base URL OpenAI-совместимого API |
| `--llm-model NAME` | Имя модели |
| `--llm-key KEY` | API-ключ |
| `--help` | Показать справку |

**Доступные имена анализаторов:** `pattern`, `cve`, `bandit`, `semgrep`, `guardrails`, `permissions`, `supply_chain`, `llm`

### Примеры

```bash
# Минимальная проверка — только встроенные анализаторы
skills-verified /path/to/repo --skip bandit,semgrep,cve,llm

# Только безопасность агентов (prompt injection + полномочия)
skills-verified /path/to/repo --only guardrails,permissions

# Только проверка зависимостей
skills-verified /path/to/repo --only cve,supply_chain

# Полная проверка с JSON-отчётом
skills-verified https://github.com/user/repo --output /tmp/report.json

# С LLM-анализом через OpenAI
skills-verified https://github.com/user/repo \
  --llm-url https://api.openai.com/v1 \
  --llm-model gpt-4o \
  --llm-key sk-xxx

# С локальным Ollama
skills-verified /path/to/repo \
  --llm-url http://localhost:11434/v1 \
  --llm-model qwen2.5-coder:32b \
  --llm-key ollama

# С vLLM
skills-verified /path/to/repo \
  --llm-url http://localhost:8000/v1 \
  --llm-model meta-llama/Llama-3.3-70B-Instruct \
  --llm-key EMPTY
```

### Переменные окружения

Все `--llm-*` флаги имеют соответствующие env-переменные:

```bash
export SV_LLM_URL=https://api.openai.com/v1
export SV_LLM_MODEL=gpt-4o
export SV_LLM_KEY=sk-xxx

# Теперь LLM-анализ включается автоматически
skills-verified https://github.com/user/repo
```

**Приоритет:** CLI-флаги > env-переменные. Удобно держать URL+модель в env, а ключ передавать флагом.

---

## Trust Score

### Система штрафов

Каждая из 5 категорий стартует со 100 баллов. За каждую находку вычитаются баллы в зависимости от severity:

| Severity | Штраф |
|---|---|
| CRITICAL | −25 |
| HIGH | −15 |
| MEDIUM | −7 |
| LOW | −3 |
| INFO | 0 |

Минимум категории: 0 (ниже не упадёт). **Общий Trust Score** — среднее арифметическое по 5 категориям.

### Грейды

| Балл | Грейд | Интерпретация |
|---|---|---|
| 90-100 | **A** | Репозиторий выглядит безопасным, проблем почти нет |
| 80-89 | **B** | Незначительные проблемы, допустимо с ручным ревью |
| 65-79 | **C** | Заметные проблемы, требуется внимательная проверка |
| 50-64 | **D** | Серьёзные проблемы, не рекомендуется к использованию |
| 0-49 | **F** | Критические проблемы, не использовать |

### Пример расчёта

Репозиторий найдено: 1 CRITICAL в Code Safety, 2 HIGH в Permissions, ничего в остальных категориях.

```
Code Safety:  100 − 25 = 75  (C)
CVE:          100          (A)
Guardrails:   100          (A)
Permissions:  100 − 15 − 15 = 70  (C)
Supply Chain: 100          (A)

Overall: (75 + 100 + 100 + 70 + 100) / 5 = 89  → Grade B
```

---

## Пример вывода

### Консоль

```
╭──────────────────────────────────────────────────────────────╮
│ Skills Verified — AI Agent Trust Scanner                     │
╰──────────────────────────────────────────────────────────────╯

  Repository: https://github.com/Nikolay-Shirokov/cc-1c-skills
  Analyzers:  pattern, guardrails, permissions, supply_chain
  LLM analyzer: skipped

╭──────────────────────────────────────────────────────────────╮
│   TRUST SCORE:  D  (60/100)                                  │
╰──────────────────────────────────────────────────────────────╯
  Code Safety     F (0)      43 findings
  Cve             A (100)     0 findings
  Guardrails      A (100)     0 findings
  Permissions     F (0)      34 findings
  Supply Chain    A (100)     0 findings

  CRITICAL (6) | HIGH (56) | MEDIUM (13) | LOW (2)

  [CRITICAL] Unsafe exec() call
    pattern | .claude/skills/web-test/scripts/browser.mjs:495
    exec() executes arbitrary code and should not be used with untrusted input.

  [CRITICAL] Unsafe eval() call
    pattern | .claude/skills/web-test/scripts/browser.mjs:2805
    eval() executes arbitrary code and should not be used with untrusted input.

  [HIGH] Destructive file operation — shutil.rmtree
    permissions | scripts/switch.py:103
    Recursively deletes directory trees. Dangerous with user-controlled paths.

  ...

  Scan completed in 3.49s
```

---

## Структура JSON-отчёта

```json
{
  "repo_url": "https://github.com/user/repo",
  "overall_score": 60,
  "overall_grade": "D",
  "categories": [
    {
      "category": "code_safety",
      "score": 0,
      "grade": "F",
      "findings_count": 43,
      "critical_count": 6,
      "high_count": 37
    },
    {
      "category": "cve",
      "score": 100,
      "grade": "A",
      "findings_count": 0,
      "critical_count": 0,
      "high_count": 0
    }
  ],
  "findings": [
    {
      "title": "Unsafe eval() call",
      "description": "eval() executes arbitrary code and should not be used with untrusted input.",
      "severity": "critical",
      "category": "code_safety",
      "file_path": "scripts/browser.mjs",
      "line_number": 2805,
      "analyzer": "pattern",
      "cve_id": null,
      "confidence": 1.0
    }
  ],
  "analyzers_used": ["pattern", "guardrails", "permissions", "supply_chain"],
  "llm_used": false,
  "scan_duration_seconds": 3.49
}
```

**Поля верхнего уровня:**

| Поле | Тип | Описание |
|---|---|---|
| `repo_url` | string | URL или путь репозитория |
| `overall_score` | int | Общий балл 0-100 |
| `overall_grade` | string | Грейд A/B/C/D/F |
| `categories` | array | Оценки по категориям |
| `findings` | array | Все найденные проблемы |
| `analyzers_used` | array | Запущенные анализаторы |
| `llm_used` | bool | Был ли LLM-анализ |
| `scan_duration_seconds` | float | Длительность сканирования |

**Поля findings:**

| Поле | Тип | Описание |
|---|---|---|
| `title` | string | Краткое описание |
| `description` | string | Подробности |
| `severity` | string | critical/high/medium/low/info |
| `category` | string | code_safety/cve/guardrails/permissions/supply_chain |
| `file_path` | string\|null | Относительный путь к файлу |
| `line_number` | int\|null | Номер строки |
| `analyzer` | string | Имя анализатора |
| `cve_id` | string\|null | CVE-ID если применимо |
| `confidence` | float | 0.0-1.0 (для LLM-находок) |

---

## Интеграция с CI/CD

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  trust-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Skills Verified
        run: |
          git clone https://github.com/your-org/skills-verified.git /tmp/sv
          pip install -e "/tmp/sv[dev]" bandit semgrep pip-audit

      - name: Run scan
        run: |
          skills-verified . --output trust-report.json

      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: trust-report
          path: trust-report.json

      - name: Fail on low Trust Score
        run: |
          python -c "
          import json, sys
          r = json.load(open('trust-report.json'))
          if r['overall_grade'] in ('D', 'F'):
              print(f'Trust Score too low: {r[\"overall_grade\"]}')
              sys.exit(1)
          "
```

### GitLab CI

```yaml
trust_scan:
  image: python:3.11
  script:
    - pip install -e "." bandit semgrep pip-audit
    - skills-verified . --output trust-report.json
  artifacts:
    paths:
      - trust-report.json
    when: always
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: skills-verified
        name: Skills Verified scan
        entry: skills-verified . --only pattern,guardrails
        language: system
        pass_filenames: false
```

---

## Архитектура

Pipeline с плагинами. Ядро определяет ABC `Analyzer`, каждый анализатор — отдельный модуль с единым контрактом.

### Структура проекта

```
skills-verified/
├── src/skills_verified/
│   ├── cli.py                      # Click CLI, точка входа
│   ├── core/
│   │   ├── models.py               # Severity, Category, Grade, Finding, Report
│   │   ├── analyzer.py             # ABC Analyzer
│   │   ├── pipeline.py             # Pipeline: запуск анализаторов, сбор findings
│   │   └── scorer.py               # Scorer: расчёт баллов и грейдов
│   ├── analyzers/
│   │   ├── pattern_analyzer.py     # Regex-паттерны
│   │   ├── cve_analyzer.py         # pip-audit / npm audit
│   │   ├── bandit_analyzer.py      # Обёртка над Bandit
│   │   ├── semgrep_analyzer.py     # Обёртка над Semgrep
│   │   ├── guardrails_analyzer.py  # Prompt injection, jailbreak, unicode
│   │   ├── permissions_analyzer.py # FS, net, process
│   │   ├── supply_chain_analyzer.py# Typosquat, postinstall, setup.py
│   │   └── llm_analyzer.py         # OpenAI-совместимый API
│   ├── repo/
│   │   └── fetcher.py              # git clone / локальный путь
│   └── output/
│       ├── console.py              # Rich-вывод
│       └── json_report.py          # JSON-сериализация
├── tests/
│   ├── fixtures/fake_repo/         # Тестовый репо с уязвимостями
│   ├── conftest.py                 # Shared фикстуры pytest
│   └── test_*.py                   # 83 теста
├── docs/superpowers/
│   ├── specs/                      # Design spec
│   └── plans/                      # Implementation plan
├── pyproject.toml
└── README.md
```

### Поток данных

```
CLI → fetcher (clone/validate) → Pipeline
                                    │
                                    ├─► PatternAnalyzer
                                    ├─► CveAnalyzer
                                    ├─► BanditAnalyzer
                                    ├─► SemgrepAnalyzer      ──► findings
                                    ├─► GuardrailsAnalyzer
                                    ├─► PermissionsAnalyzer
                                    ├─► SupplyChainAnalyzer
                                    └─► LlmAnalyzer
                                             │
                                             ▼
                                         Scorer → CategoryScores
                                             │
                                             ▼
                                          Report
                                             │
                        ┌────────────────────┴────────────────────┐
                        ▼                                          ▼
                 console.render_report                   json_report.save
```

### Контракт Analyzer

```python
class Analyzer(ABC):
    name: str

    @abstractmethod
    def is_available(self) -> bool:
        """True если анализатор может работать (инструменты установлены)."""

    @abstractmethod
    def analyze(self, repo_path: Path) -> list[Finding]:
        """Запускает анализ, возвращает список находок."""
```

**Правила:**
- `is_available() == False` → анализатор пропускается с предупреждением в лог
- Исключения внутри `analyze()` ловятся Pipeline, логируются, возвращается `[]`
- Анализаторы запускаются последовательно (параллельный запуск — будущая оптимизация)

### Добавление нового анализатора

1. Создать `src/skills_verified/analyzers/my_analyzer.py`:
   ```python
   from pathlib import Path
   from skills_verified.core.analyzer import Analyzer
   from skills_verified.core.models import Category, Finding, Severity

   class MyAnalyzer(Analyzer):
       name = "my_analyzer"

       def is_available(self) -> bool:
           return True

       def analyze(self, repo_path: Path) -> list[Finding]:
           # ... your logic
           return []
   ```

2. Добавить в `cli.py` в список `all_analyzers`
3. Написать тесты в `tests/test_my_analyzer.py`

---

## Разработка

### Запуск тестов

```bash
# Все тесты
pytest tests/ -v

# Конкретный анализатор
pytest tests/test_pattern_analyzer.py -v

# С покрытием
pytest tests/ --cov=skills_verified --cov-report=term-missing

# Только быстрые (без интеграционных)
pytest tests/ -v --ignore=tests/test_integration.py
```

### Линтинг

```bash
ruff check src/ tests/
ruff format src/ tests/
```

### TDD workflow

Проект следует TDD — тесты пишутся перед имплементацией. Пример добавления паттерна в `pattern_analyzer.py`:

```bash
# 1. Добавить тест
vim tests/test_pattern_analyzer.py

# 2. Убедиться, что он падает
pytest tests/test_pattern_analyzer.py::test_new_pattern -v

# 3. Добавить паттерн в PATTERNS list
vim src/skills_verified/analyzers/pattern_analyzer.py

# 4. Убедиться, что тест проходит
pytest tests/test_pattern_analyzer.py::test_new_pattern -v

# 5. Запустить всю сьют
pytest tests/ -v
```

### Тестовый репо

`tests/fixtures/fake_repo/` содержит файлы с намеренно уязвимым кодом:
- `dangerous.py` — eval, exec, shell=True, hardcoded secrets, pickle.load
- `clean.py` — безопасный код (для проверки отсутствия ложных срабатываний)
- `package.json` — typosquat + suspicious postinstall
- `setup.py` — os.system при установке
- `skill_inject.md` — prompt injection паттерны
- `requirements.txt` — зависимости для CVE-анализа

---

## FAQ

**Q: Почему мой код помечен как HIGH, хотя он безопасен?**

A: Паттерн-анализаторы работают на регулярках — они могут давать false positives. Используй `--skip pattern` или добавь проверку вручную. Для семантического анализа используй `--only llm` с LLM-ключом.

**Q: Можно ли добавить свой список "популярных пакетов" для typosquatting?**

A: Пока нет, списки захардкожены в `supply_chain_analyzer.py`. Это несложно расширить — можно добавить чтение из YAML/JSON-файла.

**Q: LLM-анализатор требует OpenAI?**

A: Нет, любой OpenAI-совместимый API подойдёт: Ollama, vLLM, LM Studio, llama.cpp server, локальные прокси. Тестировалось с OpenAI API, но совместимость должна работать везде.

**Q: Сколько стоит LLM-анализ?**

A: Зависит от размера репо и модели. Для GPT-4o средний репо (~50 файлов, ~200KB кода) — примерно $0.05-0.20. Для локальной модели через Ollama — бесплатно.

**Q: Trust Score слишком строгий, мой репо получил F.**

A: Веса штрафов и границы грейдов захардкожены в `scorer.py`. Их можно настроить под свой контекст. В будущей версии планируется поддержка конфига.

**Q: Как исключить папку `tests/` или `vendor/` из сканирования?**

A: Пока нет встроенной поддержки исключений. Как workaround — клонируй репо вручную, удали ненужные папки, запусти на локальном пути.

**Q: Поддерживается ли git-submodules?**

A: Клонирование делается с `depth=1`, submodules не подтягиваются. Если нужно — сделай `git clone --recurse-submodules` вручную и передай локальный путь.

---

## Лицензия

MIT
