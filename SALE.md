# Skills Verified — AI Agent Trust Scanner

**Одна команда. Один Trust Score A-F. Один бинарный ответ: пускать в прод или нет.**

Skills Verified — первый сканер, заточенный именно под репозитории AI-агентов, skills и плагинов. Не адаптированный SAST «на скорую руку», а покрытие 11 анализаторами шести категорий риска с учётом специфики LLM-приложений: prompt injection, jailbreak, shadow AI-компоненты, слабые модели, открытые MCP-серверы.

---

## Зачем это бизнесу

Вы подключаете чужой AI-агент или skill к продуктивной системе. Что он делает на самом деле?

- Имеет ли доступ к файловой системе, сети, процессам
- Какие LLM-модели зовёт, у каких провайдеров, с какими ключами
- Нет ли в промптах скрытых инструкций
- Нет ли CVE в зависимостях и подменённых typosquat-пакетов
- Выдержит ли системный промпт атаку jailbreak-ом

Ответы на эти вопросы вручную — это день работы безопасника на каждый репозиторий. Skills Verified даёт ответ за 5-30 секунд одной командой.

**Результат — грейд A-F и JSON-отчёт.** CI/CD-пайплайн сам блокирует опасные мерджи через `--fail-on`. Никаких обсуждений «как интерпретировать 47 находок» — бинарный signal: прошло или нет.

---

## Чем мы отличаемся от других сканеров

Обычные SAST-инструменты (Bandit, Semgrep, SonarQube) проверяют «классический» код. Мы дополняем их специфичными для AI-агентов слоями, которых у них просто нет.

| Слой | Обычный SAST | Skills Verified |
|---|---|---|
| Eval / shell-injection | ✅ | ✅ (pattern + Bandit + Semgrep) |
| Data-flow taint analysis | ⚠️ только дорогие enterprise | ✅ встроен, pure-Python AST |
| CVE в зависимостях | частично | ✅ pip-audit + npm audit + Grype |
| Prompt injection в текстах и кодe | ❌ | ✅ regex + unicode + base64 |
| Jailbreak-маркеры (DAN / STAN / developer mode) | ❌ | ✅ |
| AI-BOM (инвентарь моделей, MCP, промптов) | ❌ | ✅ CycloneDX 1.6 |
| Реестр рисков LLM (OWASP LLM Top 10) | ❌ | ✅ 75 моделей (LLM + embeddings) |
| Typosquat / malicious postinstall | частично | ✅ Levenshtein + lifecycle-scripts |
| Natural-language CI-политики | ❌ | ✅ через LLM в sandbox |

Мы не заменяем Bandit или Semgrep — мы их оркестрируем и добавляем сверху то, чего у них нет.

---

## Ключевые фичи

### 1. AI-BOM — инвентаризация всего AI в репозитории

Автоматически находит и документирует:

- **LLM-модели** — OpenAI (`gpt-4*`, `o1-*`, `o3-*`), Anthropic (`claude-*`), HuggingFace (33 whitelisted-организации, чтобы не ловить мусор)
- **Эмбеддинги** — `sentence-transformers/*`, `BAAI/bge-*`, OpenAI `text-embedding-*`
- **MCP-серверы** — парсит `mcp.json`, `.claude/settings.json`, `.codex/config.toml`, детектит отсутствие аутентификации
- **Системные промпты** — в коде и в текстовых файлах
- **Внешние AI-эндпоинты** — `api.openai.com`, `api.anthropic.com`, HF inference endpoints

Экспорт в **CycloneDX 1.6 JSON** — ваш compliance-отдел получает стандартный SBOM-совместимый артефакт для аудита.

```bash
skills-verified . -o report.json
```

### 2. Реестр рисков моделей (75 моделей)

Встроенная база с публичными оценками HarmBench, AgentHarm, OWASP LLM Top 10:

- **10 OpenAI**, **5 Anthropic**, **52 HuggingFace**, **4 Voyage**, **3 Cohere**, **1 Google**
- Распределение по риску: **44 low / 18 medium / 12 high / 1 critical**
- Покрыты LLM и embeddings: Qwen3-Embedding, e5/gte/nomic/jina/mxbai/arctic, voyage, cohere embed
- Включает **русскоязычные модели** (`t-tech/T-lite`, `ai-forever/ruGPT`, `IlyaGusev/saiga`, `cointegrated/*`)

Если в репозитории зовётся модель с `overall: critical` — Trust Score автоматически снижается. Модель с известными jailbreak-уязвимостями не может тихо попасть в прод.

### 3. Taint-анализ потоков данных

Pure-Python AST-анализатор, без внешних тулов:

- **10 sources**: `input()`, `os.environ`, `sys.argv`, `request.*` (Flask/FastAPI)
- **13 sinks**: `subprocess.*`, `eval`/`exec`, `pickle.loads`, `urllib`/`requests` (SSRF), `open` (path traversal)
- **7 sanitizers**: `shlex.quote`, `secure_filename`, `html.escape`, `os.path.abspath` — taint очищается
- Понимает **f-strings, BinOp, if-expressions**, автоматически маркирует аргументы handler-функций Flask/FastAPI как tainted

Это то, что Bandit и Semgrep делают только частично или через платные версии.

### 4. LLM-анализатор с closed-loop верификацией

Семантический анализ через любой OpenAI-совместимый API (OpenAI, Anthropic через прокси, Ollama, vLLM, LM Studio):

- **Consensus через `--llm-passes 3`** — несколько проходов, голосование, снижает false-positive
- **CodeReduce (`--llm-reduce`)** — delta-debugging минимизация контекста: в LLM уходит не весь файл, а минимальный скелет вокруг anchor-строки. Экономия токенов в разы на больших файлах.
- **Closed-loop verify (`--llm-verify`)** — LLM генерирует патч, статические анализаторы перезапускаются. Если после патча находка исчезает — она **`[verified]`**. Отсеивает галлюцинации.

### 5. CI/CD-политики на естественном языке

Три встроенные политики (`strict`, `standard`, `relaxed`) — достаточно для 90% случаев. Для остальных 10% — **natural-language policy**:

```bash
skills-verified . --fail-on "не более 1 критического риска и нет shadow models" \
  --llm-url ... --llm-model ... --llm-key ...
```

LLM транслирует текст в булево Python-выражение. Выражение валидируется через **sandboxed AST** (whitelist узлов, никаких `Call`, никаких `__` атрибутов) и исполняется **кастомным visitor-ом, не `eval()`**. Безопасно для прод-CI.

Доступные поля: `report.overall_score`, `overall_grade`, `criticals`, `highs`, `findings_count`, `categories.<cat>.score/grade`, `shadow_models`.

### 6. Single Trust Score

6 категорий × 100 баллов, штрафы по severity, грейд A-F:

| Балл | Грейд | Значение |
|---|---|---|
| 90-100 | A | Безопасен. Пускаем. |
| 80-89 | B | Минорные замечания. Допустимо с ревью. |
| 65-79 | C | Проблемы. Нужна внимательная проверка. |
| 50-64 | D | Серьёзные проблемы. Не пускаем. |
| 0-49 | F | Критические проблемы. Блок. |

Одна цифра — одно решение. Не 200-страничный PDF-отчёт, который никто не читает.

---

## Интеграции

### CLI — по умолчанию

```bash
# Один бинарник, один флаг — и готово
skills-verified https://github.com/user/repo --fail-on standard

# С единым JSON-отчётом (содержит Trust Score, findings и встроенный CycloneDX 1.6 AI-BOM)
skills-verified . -o report.json --fail-on strict
```

### MCP-сервер — для Claude Desktop, Cursor, любых MCP-клиентов

```bash
skills-verified mcp
```

Запускает stdio MCP-сервер с 4 tools: `skills_verified_scan`, `skills_verified_scan_file`, `skills_verified_aibom`, `skills_verified_version`. Конфигурируется одной строкой в `.claude/settings.json`:

```json
{
  "mcpServers": {
    "skills-verified": { "command": "skills-verified", "args": ["mcp"] }
  }
}
```

Агент Claude Code теперь может сам скнировать репозитории и рассуждать о рисках. CLI и MCP разделяют общий модуль — никакой дубли кода, никакого дрифта поведения.

### Docker — для CI без установки зависимостей

Готовый `Dockerfile` с предустановленными Bandit, Semgrep, pip-audit. В пайплайне — одна строка.

### GitHub Actions, GitLab CI, pre-commit

Примеры в README. Exit code 0/1 управляется через `--fail-on` — обычная CI-интеграция, без специальных плагинов.

---

## Технические характеристики

- **Язык:** Python 3.11+
- **Зависимости ядра:** click, rich, gitpython, Levenshtein, pyyaml — всё
- **Внешние тулы (опционально, graceful degradation):** Bandit, Semgrep, pip-audit, npm, Grype
- **Тесты:** 167 тестов, pytest + ruff
- **Архитектура:** plugin-based, новый анализатор добавляется в 3 файлах
- **Лицензия:** MIT
- **Производительность:** 5-30 секунд на средний репо (50 файлов, 200KB кода) без LLM; +30-120 секунд с LLM-анализом

---

## Кому это нужно

### AI-маркетплейсы (skill stores, plugin stores, agent hubs)
Автоматическая предпубликационная проверка. Skill с Grade F не попадает в каталог. Skill с Grade D требует ручного ревью.

### Enterprise, подключающие внешних AI-агентов
Ваша AppSec-команда получает стандартный compliance-артефакт (CycloneDX AI-BOM) на каждого агента до интеграции. Прозрачность для аудита.

### CI/CD платформы для AI-команд
Gate на уровне PR. Typosquat в `requirements.txt` или hardcoded OpenAI-ключ не смогут попасть в main.

### AppSec consultancies
Готовый инструмент для быстрой оценки репозиториев клиента. Вместо ручного «посмотрим что там» — грейд за минуту плюс 200-страничный JSON для детального разбора.

### Developers и maintainers AI-продуктов
Pre-commit hook или локальный `skills-verified .` перед пушем. Не ждать code review, чтобы узнать, что забыл `SafeLoader` или оставил `shell=True`.

---

## Что делает Skills Verified **уникальным**

1. **Это единственный сканер**, который в одном бинарнике сочетает классический SAST, CVE-аудит, prompt-injection детекцию, AI-BOM инвентарь и risk-scoring LLM-моделей.
2. **Единственный**, который экспортирует **CycloneDX 1.6 AI-BOM** с моделями как `machine-learning-model` и MCP-серверами как `services`.
3. **Единственный**, поддерживающий **natural-language CI-политики** с LLM-трансляцией и **безопасным AST-исполнением** (не `eval`!).
4. **Единственный**, предлагающий **closed-loop LLM-верификацию**: сначала патч, потом перезапуск статических анализаторов для подтверждения находки.
5. **Единственный**, у которого **встроенный реестр рисков 52 LLM** с учётом русскоязычных моделей (`t-tech`, `ai-forever`, `IlyaGusev`).
6. **Единственный**, одинаково живущий в **CLI, CI/CD-пайплайне и MCP-среде** из одного кодовой базы.

---

## Roadmap-hint для интересующихся

Мы поддерживаем сканер актуальным — см. [`UPDATE.md`](UPDATE.md) с workflow обновления CVE-баз, реестра моделей и Semgrep-правил. Архитектура даёт расширяемость: новый анализатор — три файла, новый LLM-провайдер — одна запись в реестре плюс regex.

---

## С чего начать

```bash
git clone <repo>
cd skills-verified
pip install -e ".[dev,llm,mcp]"

# Первый скан
skills-verified .

# Интеграция в CI
skills-verified . --fail-on standard --output report.json
```

Полная документация:
- [`README.md`](README.md) — установка, флаги, примеры
- [`PROCESS.md`](PROCESS.md) — описание процесса оценки с диаграммами
- [`UPDATE.md`](UPDATE.md) — как поддерживать сканер актуальным
- [`docs/CI_CD_INTEGRATION.md`](docs/CI_CD_INTEGRATION.md) — гайд по CI/CD

---

**Skills Verified. One scanner. One score. One decision.**
