# Процесс оценки безопасности ИИ-навыков

## Общая архитектура

```
                        skills-verified <SOURCE>
                                 |
                    +------------+------------+
                    |                         |
              GitHub URL               Локальный путь
                    |                         |
              git clone --depth=1             |
                    |                         |
                    +------------+------------+
                                 |
                          repo_path/
                                 |
        +========================+========================+
        |              PIPELINE (последовательно)          |
        |                                                  |
        |  +--------------------------------------------+  |
        |  |  Уровень 1: СТАТИЧЕСКИЙ АНАЛИЗ КОДА        |  |
        |  |                                            |  |
        |  |  PatternAnalyzer ----> CODE_SAFETY         |  |
        |  |  TaintAnalyzer  -----> CODE_SAFETY         |  |
        |  |  BanditAnalyzer  ----> CODE_SAFETY         |  |
        |  |  SemgrepAnalyzer ----> CODE_SAFETY         |  |
        |  |  LlmAnalyzer    ----> CODE_SAFETY          |  |
        |  |    (+CodeReduce, +LlmVerifier)             |  |
        |  +--------------------------------------------+  |
        |                                                  |
        |  +--------------------------------------------+  |
        |  |  Уровень 2: АНАЛИЗ ЗАВИСИМОСТЕЙ            |  |
        |  |                                            |  |
        |  |  CveAnalyzer -------> CVE                  |  |
        |  |    (pip-audit, npm audit)                  |  |
        |  |  ContainerAnalyzer -> CVE                  |  |
        |  |    (grype: image / lockfiles)              |  |
        |  +--------------------------------------------+  |
        |                                                  |
        |  +--------------------------------------------+  |
        |  |  Уровень 3: СПЕЦИФИКА ИИ-АГЕНТОВ           |  |
        |  |                                            |  |
        |  |  GuardrailsAnalyzer -> GUARDRAILS          |  |
        |  |    (prompt injection, jailbreak, unicode)  |  |
        |  +--------------------------------------------+  |
        |                                                  |
        |  +--------------------------------------------+  |
        |  |  Уровень 4: ЦЕПОЧКА ПОСТАВОК               |  |
        |  |                                            |  |
        |  |  PermissionsAnalyzer -> PERMISSIONS        |  |
        |  |  SupplyChainAnalyzer -> SUPPLY_CHAIN       |  |
        |  +--------------------------------------------+  |
        |                                                  |
        |  +--------------------------------------------+  |
        |  |  Уровень 5: AI-BOM ИНВЕНТАРИЗАЦИЯ          |  |
        |  |                                            |  |
        |  |  AibomAnalyzer ------> AI_BOM              |  |
        |  |    (модели, embeddings, MCP, промпты,      |  |
        |  |     endpoints; CycloneDX 1.6 export;       |  |
        |  |     ModelRiskRegistry enrichment)          |  |
        |  +--------------------------------------------+  |
        |                                                  |
        +========================+=========================+
                                 |
                           list[Finding]
                                 |
                    +------------+------------+
                    |        SCORER           |
                    |                         |
                    |  6 категорий x 100 pts  |
                    |  штрафы по severity     |
                    |  overall = среднее по 6 |
                    +------------+------------+
                                 |
                    +------------+------------+
                    |         REPORT          |
                    |                         |
                    |  Trust Score: A-F       |
                    |  Category Scores        |
                    |  Findings list          |
                    +-------------------------+
                                 |
                    +------+-----+------+
                    |      |            |
                 Console  JSON     Exit Code
                 (Rich)   файл    (CI/CD gate)
```

## Этапы оценки

### Этап 1 — Получение исходного кода

| Источник | Действие |
|----------|----------|
| `https://github.com/...` или `git@...` | Shallow clone (`--depth=1`) во временную директорию |
| `/path/to/local/repo` | Используется напрямую |

### Этап 2 — Статический анализ кода (CODE_SAFETY)

Несколько уровней глубины, каждый следующий дополняет предыдущий:

```
PatternAnalyzer    TaintAnalyzer      BanditAnalyzer       SemgrepAnalyzer       LlmAnalyzer
(всегда доступен)  (всегда доступен)  (нужен bandit)       (нужен semgrep)       (нужен LLM key)
      |                  |                 |                      |                     |
  Regex-паттерны     AST taint flow   AST-анализ            Семантические правила  Семантическое
  eval, exec,        source -> sink   контекст вызова       p/security-audit       LLM-ревью
  pickle, shell=True санитайзеры      слабые хэши,          p/python               + CodeReduce
  hardcoded secrets  f-string,        SSL без verify,       + rules/ai-skills.yml  + LlmVerifier
                     route handlers   tempfile race                                (closed-loop)
      |                  |                 |                      |                     |
  ~мс на файл        ~10-100мс        ~1-5 сек              ~5-30 сек              ~сек на находку
```

**PatternAnalyzer** — быстрый regex-скан (9 паттернов), ловит очевидные опасности. Сканирует расширения: `.py`, `.js`, `.mjs`, `.ts`, `.sh`, `.bash`, `.ps1`, `.rb`.
- `eval()`, `exec()` — CRITICAL
- `shell=True`, `os.system()`, `pickle.load()` — HIGH
- `yaml.load()` без SafeLoader — MEDIUM
- Hardcoded secrets (`API_KEY = "sk-..."`) — HIGH

**TaintAnalyzer** — AST-анализ потоков данных source → sink с учётом санитайзеров:
- **Sources:** `input()`, `os.environ`, `sys.argv`, `request.args/form/json/files` (Flask), `request.query_params/path_params` (FastAPI), параметры route-хендлеров.
- **Sinks:** `subprocess.*`, `os.system`, `os.popen` (HIGH); `eval`, `exec`, `compile` (CRITICAL); `pickle.loads`, `yaml.load` (HIGH); `urllib.request.urlopen`, `requests.*` (SSRF, MEDIUM/HIGH); `open` (path traversal, MEDIUM).
- **Sanitizers:** `shlex.quote`, `werkzeug.utils.secure_filename`, `html.escape`, `urllib.parse.quote` — поток помечается чистым.
- Понимает f-strings, `BinOp` (конкатенация), присваивания через атрибуты, route handlers Flask/FastAPI.
- 13 sinks, 7 санитайзеров; файлы > 10 000 строк пропускаются.

**BanditAnalyzer** — Python AST-анализ, понимает контекст (timeout 300с):
- SSL без верификации, слабые хэши, tempfile race conditions
- Фильтрация шума: B105 с пустыми значениями `password: ""` отбрасывается как false positive

**SemgrepAnalyzer** — семантический анализ с кастомными правилами:
- Стандартные наборы: `p/security-audit`, `p/python`
- Кастомные AI-правила (`rules/ai-skills.yml`, 7 правил): hardcoded OpenAI/Anthropic ключи, unsafe deserialization, prompt injection через f-strings

**LlmAnalyzer** (опциональный) — отправляет код и текстовые файлы в LLM для семантического ревью:
- Сканирует код (`.py`, `.js`, `.ts`, `.sh`, `.ps1`, `.rb`) и текст (`.md`, `.txt`, `.yaml`, `.yml`, `.json`, `.toml`, `.cfg`, `.ini`, `.env`)
- Находит логические ошибки, auth flaws, race conditions
- Находит prompt injection и hardcoded secrets в текстовых/конфиг-файлах
- Confidence scoring: находки с confidence < 0.5 понижаются в severity
- **CodeReduce** (`code_reduce.py`, флаг `--llm-reduce`) — delta-debugging миниатюризация контекста перед отправкой в LLM. Сохраняет якорную (anchor) строку находки и режет всё остальное, пока находка остаётся воспроизводимой. Экономит токены на больших файлах.
- **LlmVerifier** (`llm_verifier.py`, флаг `--llm-verify`) — closed-loop верификация LLM-находок. Алгоритм: LLM генерирует патч → патч применяется во временной копии репо → перезапускаются статические анализаторы (`PatternAnalyzer`, `BanditAnalyzer`, `SemgrepAnalyzer`) → если оригинальная находка исчезла, в `Finding.title` дописывается метка `[verified]`, что повышает доверие к LLM-результату.
- **Consensus** (`--llm-passes N`, default 1) — несколько проходов LLM, результаты объединяются для повышения recall.

### Этап 3 — Анализ зависимостей (CVE)

```
requirements.txt ──> pip-audit ──> CVE database
Pipfile          ──> pip-audit ──> (pypi advisory)
pyproject.toml   ──>
                                           ──> Finding(category=CVE)
package-lock.json -> npm audit  ──> npm advisory db

Docker image ────> grype ──> SBOM + Vulnerability DB
repo directory ──> grype ──> (сканирует lockfiles)
```

**CveAnalyzer** — сканирует Python и Node.js зависимости (timeout 120с):
- pip-audit: ищет requirements*.txt, Pipfile, pyproject.toml и проверяет на известные CVE
- npm audit: проверяет package-lock.json

**ContainerAnalyzer** — сканирует контейнерные образы или директорию (timeout 300с):
- grype: target = `dir:<path>` (по умолчанию) либо image при явном указании
- Флаг `--image python:3.11-slim` для прямого сканирования образа

### Этап 4 — Специфика ИИ-агентов (GUARDRAILS)

```
.md, .txt, .yaml, .json, .py, .js, .ts
              |
     GuardrailsAnalyzer
              |
     +--------+--------+-----------+
     |        |        |           |
  Prompt   Jailbreak  Hidden    Base64
  Injection  markers   Unicode   encoded
  patterns   DAN/STAN  U+202A   payloads
     |        |        |           |
  CRITICAL  CRITICAL   HIGH       HIGH
```

**GuardrailsAnalyzer** — детектирует атаки на LLM:
- "ignore previous instructions" — CRITICAL
- "developer mode", DAN/STAN — CRITICAL
- Скрытые Unicode символы (bidi override, zero-width) — HIGH
- Base64-закодированные инъекции — HIGH

### Этап 5 — Цепочка поставок (PERMISSIONS + SUPPLY_CHAIN)

**PermissionsAnalyzer** (11 паттернов) — что навык делает с системой:
- Файловые операции: `shutil.rmtree` (HIGH), `os.remove` (MEDIUM)
- Процессы: `os.kill` (HIGH), `subprocess.Popen` (MEDIUM)
- Сеть: requests/httpx/urllib (LOW), `socket.socket` (MEDIUM)
- Insecure HTTP: `http://` URLs кроме localhost (MEDIUM)

**SupplyChainAnalyzer** — атаки через зависимости:
- Typosquatting: Levenshtein distance <= 2 от 20 популярных Python-пакетов и 21 npm-пакета (HIGH)
- Подозрительные lifecycle scripts (postinstall и т.п.): `curl | bash` (CRITICAL)
- Опасный код в setup.py: `exec`, `os.system()`, `subprocess` (CRITICAL)

### Этап 6 — Инвентаризация AI-компонентов (AI_BOM)

Шестая категория — **AI Bill of Materials**: что именно «ИИ-шного» использует репо. Цель — увидеть теневых LLM-провайдеров, неучтённые модели и MCP-серверы, и экспортировать SBOM-совместимый артефакт для аудита.

```
   repo/
     |
     +-- *.py / *.js / *.ts / *.json / *.toml / *.yaml  --+
     +-- *.md / *.txt  (только промпты, не модели)        |
     +-- mcp.json, .claude/settings.json,                 |
         .codex/config.toml                               |
                                                          v
                                                AibomAnalyzer
                                                          |
        +-------------+--------+--------+-----------+-----+------+
        |             |        |        |           |            |
     LLM-модели  Embeddings  MCP-     Системные   AI-          Опциональное
     OPENAI_RX   модели      серверы  промпты     endpoints    обогащение
     ANTHROPIC_RX            (configs)            (api urls)   ModelRiskRegistry
     HF whitelist                                              (75 моделей,
     (39 орг)                                                  overall: low|
                                                                medium|high|
                                                                critical)
                                                          |
                                            Inventory + list[Finding]
                                                          |
                                  +-----------------------+--------+
                                  |                                |
                          AI_BOM scoring                  CycloneDX 1.6 JSON
                          (категорийный                   (--aibom report.cdx.json)
                           score 0-100)
```

**AibomAnalyzer** (встроенный, без внешних зависимостей):
- **Модели LLM** — детектируются через regex (`OPENAI_MODEL_RX` для `gpt-4*`, `gpt-3.5-turbo*`, `o1-mini`, `o1-preview`, `o3-mini`; `ANTHROPIC_MODEL_RX` для `claude-*`) и по whitelist из 39 HuggingFace-организаций (meta-llama, mistralai, BAAI, Qwen, deepseek-ai, google, microsoft, openai-community, stabilityai, tiiuae, NousResearch, HuggingFaceH4, CohereForAI, intfloat, THUDM, bigscience, EleutherAI, allenai, Salesforce, facebook, nvidia, apple, ibm-granite, openchat, teknium, WizardLM, 01-ai, xai-org, t-tech, ai-forever, IlyaGusev, cointegrated, sentence-transformers, thenlper, Alibaba-NLP, nomic-ai, jinaai, mixedbread-ai, Snowflake). HF-модели детектируются **только** в файлах с расширениями `MODEL_REF_EXTENSIONS` (не `.md`/`.txt`), при условии что в файле также присутствует `HF_CONTEXT_RX`, и org из whitelist. Имена с hallmark-подстроками (`embed`, `rerank`, `bge-`, `gte-`, `e5-`, `labse`, `rubert`, `mpnet`, `minilm`, `sentence-`, `arctic-embed`, `nomic-embed`) автоматически классифицируются как embeddings.
- **Embeddings** — regex `EMBEDDING_RX` покрывает семейства HF (`sentence-transformers/*`, `BAAI/bge*`, `Qwen/Qwen3-Embedding-*`, `intfloat/(multilingual-)?e5-*`, `thenlper|Alibaba-NLP/gte-*`, `nomic-ai/nomic-embed-*`, `jinaai/jina-embeddings-*`, `mixedbread-ai/mxbai-embed-*`, `Snowflake/snowflake-arctic-embed-*`, `cointegrated/LaBSE*|rubert-*`, `google/embeddinggemma-*`) и API-провайдеров (`text-embedding-[23]-*`, `text-embedding-ada-*`, `text-embedding-gecko-*`, `voyage-*`, `embed-(english|multilingual)(-light)?-v*`).
- **MCP-серверы** — парсинг `mcp.json`, `.mcp.json`, `.claude/settings.json`, `.claude/settings.local.json`, `.codex/config.toml`: имя сервера, command, args, env.
- **Системные промпты** — в коде через `SYSTEM_PROMPT_CODE_RX` (ищет `system_prompt`, `"role": "system"`); в `.md`/`.txt` через `SYSTEM_PROMPT_TEXT_RX` (фразы вида "you are a/an/the", "your role is").
- **AI endpoints** — кастомные base_url, не относящиеся к мейнстрим-провайдерам (теневой Ollama/vLLM/прокси).
- **Strict-режим** (`--aibom-strict`) — поднимает severity находок без явного указания версии модели.

**ModelRiskRegistry** (`data/model_risk_registry.yaml`, опц. enrichment, по умолчанию включён):
- YAML с 75 записями (10 OpenAI + 5 Anthropic + 52 HuggingFace + 4 Voyage + 3 Cohere + 1 Google). Распределение по `overall`: 44 low / 18 medium / 12 high / 1 critical. Покрывает LLM и embedding-семейства (Qwen3-Embedding, e5, gte, nomic-embed, jina-embeddings, mxbai, arctic-embed, voyage, cohere embed). Плюс под-метки (jailbreak resistance, training data, license).
- Lookup: сначала exact match по имени, затем prefix match (реестр отсортирован по длине ключа desc).
- Работает для findings с titles `AI model reference: ...` и `Embedding model reference: ...`.
- Правила enrichment: `low`/`medium`/`unknown` не меняют severity; `high` поднимает до HIGH; `critical` до CRITICAL.

**Экспорт CycloneDX 1.6** (`output/aibom_export.py`):
- Флаг CLI `--aibom report.cdx.json` или MCP-тул `skills_verified_aibom`.
- Каждая модель/embedding/MCP-сервер становится `component` типа `machine-learning-model` (где применимо), с metadata, license, evidence.

---

## Система оценки

### Штрафы по severity

```
Severity       Штраф     Пример
──────────────────────────────────────────────────────
CRITICAL        -25      eval(), prompt injection, postinstall: curl|bash
HIGH            -15      shell=True, hardcoded secrets, missing risk_tier
MEDIUM           -7      yaml.load(), insecure HTTP URL
LOW              -3      network access, subprocess import
INFO              0      информационные заметки
```

### Расчет Trust Score

```
Каждая категория стартует с 100 баллов.

CODE_SAFETY:   100 - (сумма штрафов code_safety findings)  = score₁
CVE:           100 - (сумма штрафов cve findings)           = score₂
GUARDRAILS:    100 - (сумма штрафов guardrails findings)    = score₃
PERMISSIONS:   100 - (сумма штрафов permissions findings)   = score₄
SUPPLY_CHAIN:  100 - (сумма штрафов supply_chain findings)  = score₅
AI_BOM:        100 - (сумма штрафов ai_bom findings)        = score₆

Минимум категории: 0 (не уходит в минус; score = max(0, 100 - sum штрафов))

Overall Score = round(mean(score₁, score₂, ..., score₆))
```

### Категории и их анализаторы

| Категория      | Анализаторы                                          |
|----------------|------------------------------------------------------|
| `CODE_SAFETY`  | pattern, taint, bandit, semgrep, llm                 |
| `CVE`          | cve (pip-audit, npm audit), container (grype)        |
| `GUARDRAILS`   | guardrails                                           |
| `PERMISSIONS`  | permissions                                          |
| `SUPPLY_CHAIN` | supply_chain                                         |
| `AI_BOM`       | aibom (+ ModelRiskRegistry enrichment)               |

### Грейды

```
Score     Grade     Значение
───────────────────────────────────────────────────────────
90-100      A       Безопасен. Можно публиковать.
80-89       B       В целом безопасен. Минорные замечания.
65-79       C       Есть проблемы. Требуется ревью.
50-64       D       Серьезные проблемы. Не публиковать без исправлений.
 0-49       F       Опасен. Блокировать.
───────────────────────────────────────────────────────────
```

---

## Как понимать результаты

### Безопасный навык (Grade A-B)

```
TRUST SCORE:  A  (95/100)

  Code Safety     A (100)    0 findings
  Cve             A (100)    0 findings
  Guardrails      A (100)    0 findings
  Permissions     B (88)     2 findings     <-- только LOW network access
  Supply Chain    A (100)    0 findings
  Ai Bom          A (100)    3 findings     <-- INFO: gpt-4o, text-embedding-3-small
```

Признаки безопасного навыка:
- 0 CRITICAL и 0 HIGH findings
- Все категории B или выше
- Зависимости без известных CVE
- Нет prompt injection паттернов

### Требует внимания (Grade C)

```
TRUST SCORE:  C  (72/100)

  Code Safety     D (55)     5 findings     <-- есть HIGH: hardcoded key
  Cve             B (85)     1 findings     <-- CVE в зависимости
  Guardrails      A (100)    0 findings
  Permissions     C (70)     4 findings     <-- rmtree, os.kill
  Supply Chain    A (100)    0 findings
  Ai Bom          C (78)     6 findings     <-- shadow Ollama endpoint, неучтённая модель
```

Красные флаги:
- Любая категория D или F
- HIGH findings в CODE_SAFETY (hardcoded secrets, shell=True)
- CVE в зависимостях

### Опасный навык (Grade D-F)

```
TRUST SCORE:  F  (28/100)

  Code Safety     F (0)      8 findings     <-- eval, exec, pickle
  Cve             F (25)     5 findings     <-- критические CVE
  Guardrails      F (0)      4 findings     <-- prompt injection, jailbreak
  Permissions     F (10)     6 findings     <-- rmtree, kill, raw sockets
  Supply Chain    F (0)      3 findings     <-- typosquat + curl|bash
  Ai Bom          F (40)     9 findings     <-- модель из реестра с overall: critical
```

Блокирующие критерии (любой из них = не публиковать):
- Overall Grade F
- CRITICAL findings в GUARDRAILS (prompt injection)
- CRITICAL findings в SUPPLY_CHAIN (typosquat, malicious scripts)
- Более 2 CRITICAL findings в любой категории
- CVE с severity CRITICAL

---

## Матрица принятия решений для CI/CD

Реализована через встроенный флаг `--fail-on`:

```
skills-verified <SOURCE> --fail-on <strict|standard|relaxed>
```

```
                        ┌─────────────┐
                        │ Overall     │
                        │ Grade?      │
                        └──────┬──────┘
                               │
                 ┌─────────────┼─────────────┐
                 │             │             │
              A или B         C          D или F
                 │             │             │
            ┌────┴────┐  ┌────┴────┐   ┌────┴────┐
            │ CRITICAL│  │ Ручной  │   │  БЛОК   │
            │ = 0?    │  │ ревью   │   │         │
            └────┬────┘  └─────────┘   └─────────┘
                 │
           Да    │    Нет
            ┌────┴────────────┐
            │                 │
       ┌────┴────┐      ┌────┴────┐
       │ ПУБЛИКА-│      │ РЕВЬЮ   │
       │ ЦИЯ     │      │ required│
       └─────────┘      └─────────┘
```

### Три встроенные политики `--fail-on`

| Политика | Эквивалентное выражение | Для кого |
|----------|-------------------------|----------|
| `strict` | `report.overall_grade == 'A' and report.criticals == 0` | Production, публичные платформы |
| `standard` | `report.overall_grade in ('A','B','C') and report.criticals == 0` | Staging, внутренние сервисы |
| `relaxed` | `report.overall_grade != 'F' and report.criticals <= 2` | Разработка, эксперименты |
| _(без флага)_ | — | Просто отчёт, exit 0 |

### Natural-language policies

`--fail-on` принимает не только три ключевых слова, но и **свободный английский текст**. В этом случае строка отправляется в LLM, который транслирует её в одно булево Python-выражение. Перед исполнением выражение проходит sandboxed-валидацию AST:

- Whitelist узлов (`BoolOp`, `Compare`, `Name`, `Attribute`, `Constant`, `Subscript`, `Tuple`, `List`, `In`/`NotIn`, `USub`).
- Запрещены `Call`, `eval`, `exec`, импорты, любые имена/атрибуты с префиксом `__`.
- Исполняется кастомным `_SafeEvaluator`-visitor-ом, **не через `eval()`**.

Доступные поля (видны как атрибуты `report.*`):

| Поле | Тип | Описание |
|------|-----|----------|
| `report.overall_score` | int | 0–100 |
| `report.overall_grade` | str | `'A'..'F'` |
| `report.criticals` | int | число CRITICAL findings |
| `report.highs` | int | число HIGH findings |
| `report.findings_count` | int | всего findings |
| `report.categories.<cat>.score` | int | per-category score (`code_safety`, `cve`, `guardrails`, `permissions`, `supply_chain`, `ai_bom`) |
| `report.categories.<cat>.grade` | str | per-category grade |
| `report.shadow_models` | int | число findings с `analyzer=="aibom"` и severity в (LOW, HIGH, CRITICAL) |

### Примеры

```bash
# Встроенные политики
skills-verified /path/to/skill --fail-on strict --output report.json
skills-verified /path/to/skill --fail-on standard
skills-verified /path/to/skill --fail-on relaxed

# Natural-language (нужен LLM-ключ для трансляции)
skills-verified /path/to/skill \
  --fail-on "block if any shadow models or guardrails grade is below B" \
  --llm-url https://api.openai.com/v1 --llm-model gpt-4o-mini --llm-key $OPENAI_KEY

skills-verified /path/to/skill \
  --fail-on "fail unless overall grade is A and ai_bom score is at least 90"
```

### Вывод при блокировке

```
  TRUST SCORE:  F  (38/100)
  ...
  BLOCKED (standard): Grade F is below C
```

Exit code 1 — CI/CD пайплайн останавливается.

---

## Выход в MCP-режиме

Помимо CLI, скан запускается как **stdio MCP-сервер**:

```bash
skills-verified mcp     # требует extras: pip install 'skills-verified[mcp]'
```

В этом режиме нет ни Rich-консоли, ни JSON-файла — есть только tool-responses, возвращаемые MCP-клиенту (Claude Code, Codex, и т.д.) как JSON-словари.

| MCP-тул | Что делает | Возвращает |
|---------|------------|------------|
| `skills_verified_scan(path, skip?, only?)` | Полный скан pipeline-а | summary: `overall_score`, `overall_grade`, `categories`, `findings_count`, `findings_by_severity`, `findings_by_category`, `top_findings` (top-10), `analyzers_used`, `scan_duration_seconds` |
| `skills_verified_scan_file(path, analyzer)` | Запуск **одного** анализатора на файле/мини-репо (для in-IDE feedback) | `{analyzer, path, findings:[…]}` |
| `skills_verified_aibom(path)` | Только AI-BOM, экспорт CycloneDX 1.6 | полный CycloneDX JSON-документ |
| `skills_verified_version()` | Версия | строка |

### Общий runner

И CLI, и MCP-сервер используют один модуль `core/runner.py`:

```
core/runner.py
├── ScanOptions         dataclass с флагами (llm_config, llm_passes, llm_reduce,
│                       llm_verify, aibom_strict, model_risk_enrichment,
│                       image, skip, only, branch)
├── build_analyzers()   собирает список Analyzer-ов по ScanOptions, применяет
│                       skip/only-фильтры; возвращает (analyzers, aibom_instance)
└── run_scan()          fetch_repo() → Pipeline.run() → (Report, AibomAnalyzer, repo_path)
```

Никакой дубли кода между CLI и MCP — всё, что добавляется в `ScanOptions`, автоматически становится доступно в обоих интерфейсах.
