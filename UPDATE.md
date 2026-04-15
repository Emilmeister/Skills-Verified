# UPDATE.md — гайд по поддержке skills-verified в актуальном состоянии

## Введение

Skills-verified — сканер доверия для AI-скиллов и репозиториев. Его выводы напрямую зависят от свежести нескольких внешних и внутренних источников: баз CVE, реестров моделей LLM, Semgrep-правил и whitelist-ов. **Без регулярного обновления сканер протухает за 2-3 месяца:** новые модели OpenAI/Anthropic появляются каждый месяц, CVE-фиды меняются ежедневно, классы LLM-уязвимостей публикуются волнами после крупных security-конференций.

Рекомендуемая частота обновлений:

- **CVE-базы (pip-audit, npm audit, grype DB):** ежедневно, автоматически в CI.
- **SAST-движки (bandit, semgrep):** раз в квартал.
- **Реестр моделей (`model_risk_registry.yaml`):** раз в месяц или сразу после анонса крупной модели.
- **Pattern rules, Semgrep AI rules:** ad-hoc, по мере появления новых классов уязвимостей.
- **Typosquat-лексикон:** раз в полгода.

Этот документ описывает, **что именно** и **как** обновлять. Все пути даны относительно корня репозитория.

---

## Что обновлять и как часто

| Компонент | Источник истины | Частота | Способ обновления | Ломающие изменения? |
|---|---|---|---|---|
| CVE-базы pip-audit | PyPI advisory DB | auto на каждом запуске | `pip install -U pip-audit` | нет |
| CVE-базы npm | npm registry | auto | `npm audit` подтягивает свежее | нет |
| Grype vulnerability DB | Anchore | auto при запуске | `grype db update` | нет |
| Bandit | PyPI | раз в квартал | `pip install -U bandit` | возможно (новые правила, новые FP) |
| Semgrep rules | semgrep.dev + локальные `rules/ai-skills.yml` | раз в месяц | `semgrep --config p/security-audit --update` + `git pull` | нет |
| Model Risk Registry | вручную из HarmBench/AgentHarm + OWASP LLM Top 10 | раз в квартал | правка `src/skills_verified/data/model_risk_registry.yaml` | нет |
| HF Orgs Whitelist | публичные релизы HuggingFace | по запросу | правка `HF_ORGS_WHITELIST` в `aibom_analyzer.py` | нет |
| Pattern rules | CVE-дисклоузеры, security research | ad-hoc | правка `pattern_analyzer.py` | возможен регресс FP |
| Semgrep AI rules | security research | ad-hoc | правка `src/skills_verified/rules/ai-skills.yml` | нет |
| Typosquat popular packages | PyPI/npm top-N | раз в полгода | правка списков в `supply_chain_analyzer.py` | нет |

---

## Как обновлять реестр моделей (Model Risk Registry)

Файл: `src/skills_verified/data/model_risk_registry.yaml`

### Схема записи

```yaml
- id: "org/model-name"          # точный или префиксный идентификатор
  provider: "openai"            # openai | anthropic | huggingface | google | ...
  risk:
    jailbreak_resistance: 0.7   # опционально, 0.0-1.0, выше = безопаснее
    prompt_injection: 0.5
    data_leak: 0.3
    overall: "medium"           # low | medium | high | critical | unknown
  owasp_llm_top10:
    - "LLM01_prompt_injection: high"
    - "LLM06_sensitive_information_disclosure: medium"
  notes: "Краткий комментарий со ссылкой на источник оценки"
```

### Workflow добавления новой модели

1. Проверь свежие оценки на [HarmBench](https://www.harmbench.org/), [AgentHarm](https://github.com/centerforaisafety/agentharm) и публичные security-репорты вендора.
2. Зафиксируй `overall` **консервативно** — в сомнении ставь `high`, а не `medium`. Лучше FP, чем пропустить риск.
3. В `notes` обязательно сошлись на конкретный источник (URL, дата, эталонный бенчмарк).
4. Если есть mapping на OWASP LLM Top 10 — добавь строки в `owasp_llm_top10`.
5. **Используй prefix-match.** Запись с `id: "gpt-4"` покроет `gpt-4-0125-preview`, `gpt-4-turbo` и т.д. через lookup в `model_risk.py`. Не плоди дубли — сначала добавляй общий префикс, потом override-ы для конкретных вариантов.
6. Прогони тесты: `pytest tests/`.
7. Прогони на реальном репо: `skills-verified <repo>` и убедись, что новые модели подхватываются с правильным риском (смотри AI-BOM секцию вывода).

### Влияние `overall` на severity

| `overall` | Итоговый Severity AI-BOM finding |
|---|---|
| `critical` | CRITICAL |
| `high` | HIGH |
| `medium` / `low` / `unknown` | без изменений (severity не поднимается) |

Важно: `enrich_findings()` бустит severity **только вверх** — если текущая severity уже выше, чем буст от `overall`, она не трогается. `enrich_findings()` обрабатывает findings с titles `"AI model reference: <id>"` и `"Embedding model reference: <id>"`.

---

## Как добавить нового LLM-провайдера

Когда появляется новый провайдер, не покрытый текущими regex-ами (например, Google Gemini, Mistral, Cohere), нужно:

1. **Regex для моделей.** Добавь в `src/skills_verified/analyzers/aibom_analyzer.py`:

   ```python
   GOOGLE_MODEL_RX = re.compile(r"\b(gemini-[a-z0-9.\-]+)\b")
   ```

2. **Зарегистрируй в `detect()`.** В цикле по строкам файла добавь `finditer` и вызов:

   ```python
   for m in GOOGLE_MODEL_RX.finditer(line):
       self._record_model(model_index, m.group(0), "google", rel, line_number)
   ```

3. **Добавь записи в registry** — как описано в предыдущем разделе.

4. **Добавь endpoint-regex**, если провайдер использует свой API-хост (например, `generativelanguage.googleapis.com`) — в `EXTERNAL_ENDPOINT_RX`.

5. **Тесты.** Дополни `tests/fixtures/fake_repo/` файлом с примером использования и добавь ассерт в `tests/test_aibom_analyzer.py`.

### Для HuggingFace-подобных провайдеров

Провайдеры с форматом `org/model` (HuggingFace, Replicate частично) обрабатываются единым regex. Чтобы добавить новую org:

- **Не добавляй новый regex** — добавь имя организации в `HF_ORGS_WHITELIST` в `aibom_analyzer.py`.
- Whitelist отсеивает false positives от произвольных `word/word` вхождений в текстах (`tests/fixtures`, `path/to/file` и т.д.).

---

## Как обновить Semgrep-правила AI (`rules/ai-skills.yml`)

Файл: `src/skills_verified/rules/ai-skills.yml` — кастомные правила для AI-скиллов, которых нет в публично-доступных наборах semgrep.dev.

При добавлении нового правила:

1. Пиши **узкие** правила с низким FP. Используй `patterns:` (комбинация условий с контекстом), а не голый `pattern:` с одной строкой.
2. Укажи `severity: ERROR | WARNING | INFO` — в `semgrep_analyzer.py` это маппится в `Severity.HIGH | MEDIUM | LOW` соответственно.
3. Тестируй на `tests/fixtures/fake_repo/`: правило должно срабатывать на намеренно уязвимом файле и **не срабатывать** на `clean.py`.
4. Локальная проверка:

   ```bash
   semgrep --config src/skills_verified/rules/ai-skills.yml tests/fixtures/fake_repo/
   ```

---

## Как обновить `pattern_analyzer.py`

TDD-воркфлоу:

1. Добавь тест в `tests/test_pattern_analyzer.py` для нового паттерна с ожидаемым `severity`.
2. Убедись, что тест **падает**:

   ```bash
   pytest tests/test_pattern_analyzer.py::test_my_new_pattern -v
   ```

3. Добавь паттерн в `PATTERNS` в `src/skills_verified/analyzers/pattern_analyzer.py`. Категория обычно `Category.CODE_SAFETY`.
4. Регрессия: `pytest tests/` — убедись, что не сломал ничего на clean-фикстурах.

### Когда НЕ добавлять в pattern_analyzer

- Если паттерн требует контекста (AST, поток данных) — место в `taint_analyzer.py` или Semgrep-правиле.
- Если паттерн уже ловится Bandit — не дублируй (получишь двойные finding-и).
- Если паттерн вообще не Python-специфичный, но требует семантики — лучше Semgrep.

---

## Как обновить typosquat-лексикон

В `src/skills_verified/analyzers/supply_chain_analyzer.py` есть встроенные списки `POPULAR_PYPI` и `POPULAR_NPM`. Раз в полгода:

1. Возьми top-100 c [PyPI stats](https://pypi.org/stats/) и [npm popularity](https://www.npmjs.com/search?ranking=popularity).
2. Обнови списки. **Не раздувай:** сравнение идёт по Levenshtein distance ≤ 2, и слишком длинный список даёт FP (легитимные пакеты внезапно становятся «typosquat» популярных).
3. Регрессия: `pytest tests/test_supply_chain_analyzer.py`.

---

## Обновление CI/CD-интеграции

Рекомендация: запускать обновление баз **отдельным scheduled workflow** раз в сутки, не на каждом PR-сканировании. Это даёт свежие данные без дёрганья кэша CI на каждом коммите.

GitHub Actions пример:

```yaml
name: Refresh scanner DBs
on:
  schedule:
    - cron: "0 4 * * *"   # каждый день в 04:00 UTC
  workflow_dispatch:

jobs:
  refresh:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Refresh scanner DBs
        run: |
          pip install -U pip-audit bandit semgrep
          grype db update
      - name: Smoke run
        run: skills-verified . -o report.json
```

---

## Чеклист ежеквартального обслуживания

- [ ] Обновить `bandit`, `semgrep`, `pip-audit` до последних версий
- [ ] Просмотреть OWASP LLM Top 10 на новые риски (раздел News/Updates)
- [ ] Добавить 3-5 свежих моделей в `model_risk_registry.yaml` (или ре-оценить существующие)
- [ ] Проверить `HF_ORGS_WHITELIST` — нет ли новых крупных org, чьи модели массово появились в проде
- [ ] Прогнать сканер на 3-5 реальных репозиториях, сравнить Trust Score «до/после» — убедиться в отсутствии регрессий
- [ ] Обновить число тестов и список анализаторов в `README.md`, если что-то добавил

---

## Источники, которые стоит отслеживать

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [HarmBench](https://www.harmbench.org/)
- [JailbreakBench](https://jailbreakbench.github.io/)
- [Anchore Grype releases](https://github.com/anchore/grype/releases)
- [Bandit CHANGELOG](https://github.com/PyCQA/bandit/blob/main/CHANGELOG.md)
- [Semgrep Registry](https://semgrep.dev/r)
- [PyPA Advisory Database](https://github.com/pypa/advisory-database)
- [HuggingFace Trending Models](https://huggingface.co/models)
- [OpenAI Models Reference](https://platform.openai.com/docs/models)
- [Anthropic Claude Models](https://docs.anthropic.com/en/docs/about-claude/models)

---

## Политика обратной совместимости

- **Маппинг severity** при обновлении не менять без major version bump. Пользователи строят CI-гейты на конкретных уровнях.
- **Веса `scorer.py`** (штрафы CRITICAL=-25, HIGH=-15, MEDIUM=-7, LOW=-3) — стабильны. Любое изменение ломает baseline у пользователей, которые сравнивают Trust Score между версиями.
- **При добавлении новой `Category`** — добавь её в `Report`, `Scorer`, `cli.py` и во все тесты в одном PR. Частичный merge сломает агрегацию.
- При удалении правила/паттерна — оставь его помеченным `deprecated` хотя бы на один минорный релиз, чтобы пользователи увидели в diff'е отчёта, что finding пропал не из-за «фикса», а из-за изменения сканера.
