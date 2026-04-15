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
- [Использование через MCP](#использование-через-mcp)
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
- **Shadow AI-активы** — неучтённые модели, эмбеддинги, MCP-серверы и системные промпты, попавшие в проект без ревью

Skills Verified автоматизирует проверку всего перечисленного и выдаёт одну цифру — Trust Score, по которой легко принять решение: доверять репозиторию или нет.

---

## Возможности

- **11 анализаторов** — 6 встроенных (pattern, taint, guardrails, permissions, supply_chain, aibom) и 5 опциональных с внешними тулами (bandit, semgrep, cve, container, llm)
- **Опциональный LLM-анализ** через любой OpenAI-совместимый API (OpenAI, Anthropic через прокси, Ollama, vLLM, LM Studio)
- **CodeReduce** (`--llm-reduce`) — delta-debugging минимизация контекста для LLM, экономит токены на больших файлах
- **LlmVerifier** (`--llm-verify`) — closed-loop верификация: LLM генерирует патч, статический анализатор перезапускается, подтверждённые находки помечаются `[verified]`
- **AI-BOM** — инвентаризация AI-активов (LLM, эмбеддинги, MCP-серверы, системные промпты, endpoints) с экспортом в CycloneDX 1.6 JSON, встроенным в финальный отчёт
- **MCP-сервер** — `skills-verified mcp` запускает stdio MCP-сервер для подключения к Claude Code и другим MCP-клиентам
- **Trust Score A-F** с разбивкой по 6 категориям (включая AI_BOM)
- **CI/CD gate** — `--fail-on strict|standard|relaxed` или **natural-language политика** через LLM (например: `--fail-on "не более 1 критического риска и нет shadow models"`)
- **Сканирование контейнеров** — `--image` для проверки Docker-образов через Grype
- **Кастомные Semgrep-правила** для AI-навыков: hardcoded ключи OpenAI/Anthropic/HuggingFace, unsafe deserialization, prompt injection через f-strings
- **Цветной терминальный вывод** через Rich с таблицами и группировкой по severity
- **JSON-отчёт** для интеграции в CI/CD
- **Работа с GitHub URL** — автоматический `git clone --depth=1` во временный каталог
- **Работа с локальным путём** — сканирование уже скачанного репо
- **Фильтрация анализаторов** — `--skip` для исключения, `--only` для запуска только нужных
- **Graceful degradation** — если внешний инструмент (Bandit/Semgrep/pip-audit/Grype) не установлен, анализатор пропускается с предупреждением, остальные продолжают работу
- **Docker-образ** — `Dockerfile` с предустановленными bandit, pip-audit, semgrep

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
pip install bandit        # Статический анализ Python
pip install semgrep       # Semantic grep для security-audit правил
pip install pip-audit     # Проверка Python-зависимостей на CVE
# npm уже должен быть в системе для npm audit

# Grype — сканирование контейнеров и SBOM (ставится отдельно)
# macOS: brew install grype
# Linux: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
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
| `compile()` (кроме `re.compile`) | HIGH | Может использоваться для обхода eval |
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
| Insecure HTTP URL | `http://` (кроме localhost) | MEDIUM |

### 7. Supply Chain Analyzer (встроенный, `supply_chain`)

Ищет атаки на цепочку поставок зависимостей.

**Что ищет:**

- **Typosquatting** — сравнивает имена зависимостей с популярными пакетами через расстояние Левенштейна. Пример: `reqeusts` vs `requests` (distance 1), `loadsh` vs `lodash` (distance 2)
- **Подозрительные lifecycle-скрипты** в `package.json` — `preinstall`, `postinstall`, `preuninstall`, `postuninstall` с командами `curl`, `wget`, `bash`, `sh`, `eval`, `exec`
- **Код в `setup.py`** — `os.system`, `subprocess.run/call/Popen`, `exec` — всё, что исполняется при установке пакета

Списки популярных пакетов — встроенные (20 для Python, 21 для npm). Легко расширяются в `supply_chain_analyzer.py`.

### 8. LLM Analyzer (опциональный, `llm`)

Семантический анализ кода и текстовых файлов через LLM. Находит то, что не ловят регулярки и AST-анализаторы:

- SQL injection через конкатенацию
- Race conditions
- Логические ошибки в авторизации
- Information disclosure
- Unsafe data handling в бизнес-логике
- Prompt injection / jailbreak, скрытые в текстовых и конфиг-файлах
- Hardcoded secrets в любых файлах

**Как работает:**

1. Собирает файлы кода (`.py`, `.js`, `.ts`, `.sh`, `.ps1`, `.rb`) и текстовые файлы (`.md`, `.txt`, `.yaml`, `.yml`, `.json`, `.toml`, `.cfg`, `.ini`, `.env`)
2. Батчит их по размеру (по умолчанию 50 000 символов на батч)
3. Отправляет каждый батч в LLM с системным промптом, требующим JSON-ответ
4. Парсит ответ (поддерживает markdown code blocks), извлекает находки
5. Низкая confidence (<0.5) автоматически понижает CRITICAL/HIGH до MEDIUM

**Включается только при наличии всех трёх параметров:** `--llm-url`, `--llm-model`, `--llm-key`. Работает с любым OpenAI-совместимым API.

**Расширения:**

- **CodeReduce** (`--llm-reduce`) — delta-debugging минимизация контекста. Сохраняет строку-якорь вокруг seed-находки, режет остальное → существенная экономия токенов на больших файлах.
- **LlmVerifier** (`--llm-verify`) — closed-loop верификация: LLM генерирует патч для своей же находки, статический анализатор перезапускается, и если находка ушла — она помечается `[verified]` в описании. Снимает большую часть ложных срабатываний.
- **`--llm-passes N`** — multi-pass consensus (рекомендуется `3` для CI/CD): несколько проходов с majority voting.

### 9. Container Analyzer (внешний, `container`)

Сканирование контейнерных образов и директорий через [Grype](https://github.com/anchore/grype).

**Как работает:**
- Без `--image`: сканирует директорию репо (`grype dir:<path>`) — находит уязвимости в lockfiles
- С `--image python:3.11-slim`: сканирует указанный Docker-образ, включая системные пакеты

**Требует:** `grype` (ставится через brew или curl)

### 10. AI-BOM Analyzer (встроенный, `aibom`)

Инвентаризация AI-активов проекта (категория **AI_BOM**) с экспортом в **CycloneDX 1.6 JSON**. Детектит:

- **LLM-модели** — OpenAI/Anthropic через regex (`gpt-4o`, `claude-3-5-sonnet-*` и т.п.), HuggingFace через **whitelist из 39 организаций** (`meta-llama`, `mistralai`, `BAAI`, `t-tech`, `ai-forever`, `IlyaGusev`, `cointegrated` и т.д.). Whitelist убирает false positives от случайных `word/word` в документации
- **Эмбеддинги** — отдельный regex для `sentence-transformers/*`, `BAAI/bge-*`, `text-embedding-3-*`
- **MCP-серверы** — из `mcp.json`, `.claude/settings.json`, `.codex/config.toml`
- **Системные промпты** — по паттернам `you are a/an ...`, `SYSTEM_PROMPT`, `"role": "system"`
- **API endpoints** — host'ы инференс-провайдеров

**Обогащение через реестр рисков** (`data/model_risk_registry.yaml`) — 75 моделей (10 OpenAI, 5 Anthropic, 52 HuggingFace включая русскоязычные `t-tech` / `ai-forever` / `IlyaGusev` / `cointegrated`, 4 Voyage, 3 Cohere, 1 Google). Включены embedding-семейства: Qwen3-Embedding, e5, gte, nomic-embed, jina-embeddings, mxbai, arctic-embed, LaBSE, voyage, cohere embed. Высокий overall-риск поднимает severity находки до HIGH/CRITICAL.

**Флаги:**
- `--aibom-strict` — shadow-компоненты (модель без pinned version, MCP без auth) получают severity LOW вместо INFO

AI-BOM в формате CycloneDX 1.6 автоматически встраивается в JSON-отчёт (`--output`) под ключом `aibom` — отдельный файл не нужен.

### 11. Taint Analyzer (встроенный, `taint`)

AST-based source→sink анализ с санитайзерами для Python (категория **CODE_SAFETY**). Понимает f-strings и `BinOp`-конкатенацию.

| Тип | Пример | Severity / класс уязвимости |
|---|---|---|
| **Sources** | `input()`, `os.environ[...]`, `sys.argv`, Flask/FastAPI `request.*` | — |
| **Sinks** | `subprocess.*`, `os.system` | HIGH — command injection |
| | `eval`, `exec` | CRITICAL |
| | `pickle.loads` | HIGH |
| | `urlopen`, `requests.*` | HIGH — SSRF |
| | `open()` | MEDIUM — path traversal |
| **Sanitizers** | `shlex.quote`, `werkzeug.secure_filename`, `html.escape`, `os.path.abspath` | гасят находку |

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
| `--fail-on POLICY` | CI/CD gate: `strict`, `standard`, `relaxed` или **natural-language** политика (exit 1 при нарушении) |
| `--image IMAGE` | Docker-образ для сканирования через Grype |
| `--branch, -b BRANCH` | Git branch для clone (например `main`) |
| `--aibom-strict` | Shadow-компоненты (модель без pinned version, MCP без auth) — severity LOW вместо INFO |
| `--llm-url URL` | Base URL OpenAI-совместимого API |
| `--llm-model NAME` | Имя модели |
| `--llm-key KEY` | API-ключ |
| `--llm-passes N` | Multi-pass consensus, рекомендуется 3 для CI/CD |
| `--llm-reduce` | Включить CodeReduce (минимизация контекста) |
| `--llm-verify` | Включить LlmVerifier (closed-loop верификация) |
| `--help` | Показать справку |

**Доступные имена анализаторов:** `pattern`, `cve`, `bandit`, `semgrep`, `guardrails`, `permissions`, `supply_chain`, `container`, `llm`, `aibom`, `taint`

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

Каждая из 6 категорий (`code_safety`, `cve`, `guardrails`, `permissions`, `supply_chain`, `ai_bom`) стартует со 100 баллов. За каждую находку вычитаются баллы в зависимости от severity:

| Severity | Штраф |
|---|---|
| CRITICAL | −25 |
| HIGH | −15 |
| MEDIUM | −7 |
| LOW | −3 |
| INFO | 0 |

Минимум категории: 0 (ниже не упадёт). **Общий Trust Score** — среднее арифметическое по 6 категориям.

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
CVE:          100            (A)
Guardrails:   100            (A)
Permissions:  100 − 15 − 15 = 70  (C)
Supply Chain: 100            (A)
AI-BOM:       100            (A)

Overall: (75 + 100 + 100 + 70 + 100 + 100) / 6 ≈ 91  → Grade A
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
    },
    {
      "category": "ai_bom",
      "score": 93,
      "grade": "A",
      "findings_count": 1,
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
    },
    {
      "title": "Shadow LLM model: openai/gpt-4o (no pinned version)",
      "description": "Model referenced without a pinned version. Behaviour can drift silently.",
      "severity": "low",
      "category": "ai_bom",
      "file_path": "agent/config.py",
      "line_number": 12,
      "analyzer": "aibom",
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

Если AI-BOM-анализатор не был пропущен, в JSON-отчёт под ключом `aibom` встраивается полный **CycloneDX 1.6 BOM** (формат `application/vnd.cyclonedx+json`): `components` — модели и эмбеддинги, `services` — MCP-серверы, системные промпты и endpoints — как `properties` в `metadata`. Отдельный файл не создаётся — всё в одном отчёте.

**Поля findings:**

| Поле | Тип | Описание |
|---|---|---|
| `title` | string | Краткое описание |
| `description` | string | Подробности |
| `severity` | string | critical/high/medium/low/info |
| `category` | string | code_safety/cve/guardrails/permissions/supply_chain/ai_bom |
| `file_path` | string\|null | Относительный путь к файлу |
| `line_number` | int\|null | Номер строки |
| `analyzer` | string | Имя анализатора |
| `cve_id` | string\|null | CVE-ID если применимо |
| `confidence` | float | 0.0-1.0 (для LLM-находок) |

---

## Интеграция с CI/CD

Skills-Verified работает как **одна джоба** в вашем пайплайне. Флаг `--fail-on` управляет exit code:

| Политика | Блокирует (exit 1) при | Для кого |
|----------|----------------------|----------|
| `--fail-on strict` | Grade < A, или любой CRITICAL | Production |
| `--fail-on standard` | Grade < C, или любой CRITICAL | Staging |
| `--fail-on relaxed` | Grade F, или > 2 CRITICAL | Разработка |
| `--fail-on "<NL>"` | Любое условие на естественном языке (через LLM) | Кастомные правила |
| _(без флага)_ | Никогда (exit 0) | Просто отчёт |

#### Natural-language политики

Помимо встроенных пресетов, в `--fail-on` можно передать политику на естественном языке:

```bash
skills-verified . --fail-on "не более 1 критического риска и нет shadow models"
skills-verified . --fail-on "fail if guardrails grade is below B or any AI-BOM critical"
```

LLM транслирует текст в булево Python-выражение. Выражение валидируется **sandboxed AST** (whitelist узлов, без `Call`/`eval`, без атрибутов с `__`) и исполняется кастомным visitor-ом — никакого `eval()`. Доступные поля:

- `report.overall_score`, `report.overall_grade`
- `report.criticals`, `report.highs`, `report.findings_count`
- `report.categories.code_safety.score` / `.grade` (и аналоги для `cve`, `guardrails`, `permissions`, `supply_chain`, `ai_bom`)
- `report.shadow_models` — число неучтённых моделей из AI-BOM

Требует `--llm-*` флагов. При невалидной политике скан возвращает exit code `2`.

### GitHub Actions

```yaml
name: Skill Security Review

on:
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"

      - name: Install skills-verified
        run: pip install skills-verified bandit pip-audit

      - name: Run security scan
        run: |
          skills-verified . \
            --output report.json \
            --fail-on standard

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: report.json
```

### GitLab CI

```yaml
skill-security:
  stage: test
  image: python:3.13-slim
  before_script:
    - pip install skills-verified bandit pip-audit
  script:
    - skills-verified . --output report.json --fail-on standard
  artifacts:
    when: always
    paths:
      - report.json
  rules:
    - if: $CI_MERGE_REQUEST_ID
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: skills-verified
        name: Skill Security Scan
        entry: skills-verified . --only pattern,guardrails,supply_chain --fail-on relaxed
        language: python
        pass_filenames: false
        additional_dependencies: ["skills-verified"]
```

Подробная документация по CI/CD: [`docs/CI_CD_INTEGRATION.md`](docs/CI_CD_INTEGRATION.md)
Описание процесса оценки: [`PROCESS.md`](PROCESS.md)
Как поддерживать сканер актуальным: [`UPDATE.md`](UPDATE.md)

---

## Использование через MCP

Skills-Verified умеет работать как **stdio MCP-сервер**, чтобы Claude Code (или любой другой MCP-клиент) мог вызывать сканер как инструмент.

```bash
skills-verified mcp
```

Сервер экспортирует 4 tools:

| Tool | Что делает |
|---|---|
| `skills_verified_scan` | Полный скан репозитория (URL или путь), возвращает Trust Score + findings |
| `skills_verified_scan_file` | Сканирует одиночный файл |
| `skills_verified_aibom` | Возвращает AI-BOM (CycloneDX 1.6) для репозитория |
| `skills_verified_version` | Версия пакета |

### Подключение в Claude Code

```json
{
  "mcpServers": {
    "skills-verified": {
      "command": "skills-verified",
      "args": ["mcp"]
    }
  }
}
```

Положи это в `.claude/settings.json` (проектный) или `~/.claude/settings.json` (глобальный). После рестарта Claude Code MCP-tools станут доступны.

CLI и MCP переиспользуют общий модуль `core/runner.py` — нет дубли логики, поведение идентично.

---

## Архитектура

Pipeline с плагинами. Ядро определяет ABC `Analyzer`, каждый анализатор — отдельный модуль с единым контрактом.

### Структура проекта

```
skills-verified/
├── src/skills_verified/
│   ├── cli.py                       # Click CLI, точка входа, --fail-on gate
│   ├── mcp_server.py                # stdio MCP-сервер (skills-verified mcp)
│   ├── core/
│   │   ├── models.py                # Severity, Category, Grade, Finding, Report
│   │   ├── analyzer.py              # ABC Analyzer + find_tool()
│   │   ├── pipeline.py              # Pipeline: запуск анализаторов, сбор findings
│   │   ├── runner.py                # Общий runner для CLI и MCP (ScanOptions, run_scan)
│   │   ├── policy_engine.py         # NL-политики --fail-on: LLM → AST sandbox
│   │   ├── code_reduce.py           # Delta-debugging минимизация контекста для LLM
│   │   ├── llm_verifier.py          # Closed-loop верификация патчем
│   │   ├── model_risk.py            # Реестр рисков моделей
│   │   └── scorer.py                # Scorer: расчёт баллов и грейдов
│   ├── analyzers/
│   │   ├── pattern_analyzer.py      # Regex-паттерны
│   │   ├── cve_analyzer.py          # pip-audit / npm audit
│   │   ├── bandit_analyzer.py       # Обёртка над Bandit
│   │   ├── semgrep_analyzer.py      # Обёртка над Semgrep + AI rules
│   │   ├── guardrails_analyzer.py   # Prompt injection, jailbreak, unicode
│   │   ├── permissions_analyzer.py  # FS, net, process, HTTPS/TLS
│   │   ├── supply_chain_analyzer.py # Typosquat, postinstall, setup.py
│   │   ├── container_analyzer.py    # Grype: Docker-образы, SBOM
│   │   ├── aibom_analyzer.py        # Инвентаризация AI-активов
│   │   ├── taint_analyzer.py        # AST source→sink + санитайзеры
│   │   └── llm_analyzer.py          # OpenAI-совместимый API
│   ├── data/
│   │   └── model_risk_registry.yaml # 75 моделей: OpenAI/Anthropic/HF/Voyage/Cohere/Google + риски
│   ├── rules/
│   │   └── ai-skills.yml            # Кастомные Semgrep-правила для AI
│   ├── repo/
│   │   └── fetcher.py               # git clone / локальный путь
│   └── output/
│       ├── console.py               # Rich-вывод
│       ├── json_report.py           # JSON-сериализация
│       └── aibom_export.py          # CycloneDX 1.6 AI-BOM экспорт
├── tests/
│   ├── fixtures/fake_repo/          # Тестовый репо с уязвимостями
│   ├── conftest.py                  # Shared фикстуры pytest
│   └── test_*.py                    # 167 тестов
├── docs/
│   ├── CI_CD_INTEGRATION.md         # Подробный гайд по CI/CD
│   └── superpowers/
│       ├── specs/                   # Design spec
│       └── plans/                   # Implementation plan
├── PROCESS.md                       # Описание процесса оценки с диаграммами
├── Dockerfile                       # Multi-stage образ со всеми тулами
├── .github/workflows/ci.yml         # CI проекта
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
                                    ├─► SemgrepAnalyzer (+ ai-skills.yml)
                                    ├─► GuardrailsAnalyzer    ──► findings
                                    ├─► PermissionsAnalyzer
                                    ├─► SupplyChainAnalyzer
                                    ├─► ContainerAnalyzer
                                    ├─► AiBomAnalyzer
                                    ├─► TaintAnalyzer
                                    └─► LlmAnalyzer (+ CodeReduce, LlmVerifier)
                                             │
                                             ▼
                                         Scorer → CategoryScores (×6)
                                             │
                                             ▼
                                          Report
                                             │
              ┌──────────┬──────────┬────────┴────────┬──────────────┐
              ▼              ▼                       ▼              ▼
          Console      JSON + AI-BOM (CDX)    --fail-on gate    MCP tools
          (Rich)           (-o path)         (builtin или NL)  (skills-verified mcp)
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

**Q: Как добавить новую модель в реестр рисков AI-BOM?**

A: Реестр живёт в `src/skills_verified/data/model_risk_registry.yaml` — добавь запись с полями provider/family/risk. Подробный workflow поддержки актуальности (модели, CVE, MCP-каталоги) — в [`UPDATE.md`](UPDATE.md).

**Q: AI-BOM детектит модель `word/word` из моих доков как HuggingFace-модель — false positive.**

A: HuggingFace-детектор использует **whitelist из 33 организаций** (`meta-llama`, `mistralai`, `BAAI`, `t-tech`, `ai-forever`, `IlyaGusev`, `cointegrated` и т.д.) — без него любая пара `slug/slug` ловилась бы как модель. Если твоя организация не в whitelist — добавь её в `aibom_analyzer.py` (`HF_ORGS_WHITELIST`). Если же находка вообще нежелательна — `--skip aibom`.

**Q: Как использовать сканер из Claude Code?**

A: Запусти MCP-сервер (`skills-verified mcp`) и пропиши его в `.claude/settings.json` (см. раздел [Использование через MCP](#использование-через-mcp)). Claude получит 4 tools: `skills_verified_scan`, `skills_verified_scan_file`, `skills_verified_aibom`, `skills_verified_version`. Реализация в `src/skills_verified/mcp_server.py`, общая логика с CLI — в `core/runner.py`.

**Q: Сколько тестов в проекте?**

A: 167 тестов (`pytest tests/`). Покрывают все 11 анализаторов, runner, policy_engine, MCP-сервер, AI-BOM экспорт.

---

## Лицензия

MIT
