# Skills Verified

`skills-verified` — CLI для статической проверки репозиториев AI-agent skills.
Утилита принимает локальный каталог или HTTPS Git URL и печатает в `stdout`
policy-free JSON: найденные проблемы, evidence, охваченный scope и технический
статус каждого анализатора.

Scanner не вычисляет рейтинг доверия и не решает, публиковать ли skill. Такое
решение принимает внешний сервис по собственным правилам. Подробное устройство
pipeline описано в [ARCH.md](ARCH.md), JSON-контракт — в
[`report.schema.json`](src/skills_verified/report.schema.json).

## Быстрый запуск

Нужен Python 3.11+ и Git. Из корня проекта:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

skills-verified /path/to/skill \
  --skip llm,bandit,shellcheck,semgrep \
  > report.json
```

Для PowerShell virtualenv активируется командой
`.venv\Scripts\Activate.ps1`.

Проверить результат:

```bash
jq '{status: .scan.status, summary, analyzer_runs, diagnostics}' report.json
```

`scan.status=complete` означает только, что выбранные проверки завершились. Ноль
findings не является гарантией безопасности.

## Установка

| Команда | Что устанавливается |
|---|---|
| `python -m pip install -e .` | Основной CLI и встроенные анализаторы |
| `python -m pip install -e ".[scanners]"` | CLI, Bandit, ShellCheck и Semgrep |
| `python -m pip install -e ".[dev,scanners]"` | Полное окружение разработчика |

Bandit, ShellCheck и Semgrep необязательны. LLM-анализатор использует стандартный
OpenAI-compatible HTTP API и не требует отдельного Python SDK.

Проверка установки:

```bash
skills-verified --help
```

## Как запускать

### Локальный репозиторий

Базовый запуск без необязательных анализаторов:

```bash
skills-verified ./skill-repository \
  --skip llm,bandit,shellcheck,semgrep \
  > report.json
```

После установки `.[scanners]` полный детерминированный прогон без передачи кода
в LLM запускается так:

```bash
skills-verified ./skill-repository \
  --skip llm \
  > report.json
```

Bandit и Semgrep сначала ищутся рядом с Python-интерпретатором, запустившим CLI,
а затем в `PATH`, поэтому scanner не подхватывает случайную глобальную версию.
Semgrep использует встроенные зафиксированные rulesets, проверяет их SHA-256 и
передаёт инструменту локальные YAML; сеть и изменяемый Registry не нужны:

```bash
skills-verified ./skill-repository \
  --only semgrep \
  > semgrep-report.json
```

Полностью offline-проверка не должна запускать только OSV и LLM:

```bash
skills-verified ./skill-repository \
  --skip cve,llm \
  > offline-report.json
```

Установленные Bandit, ShellCheck и Semgrep работают локально, поэтому их можно
оставить в offline-наборе.

### Удалённый репозиторий

CLI принимает только HTTPS URL, делает shallow clone и удаляет временный каталог
после анализа:

```bash
skills-verified https://github.com/example/skill.git \
  --skip llm,bandit,shellcheck,semgrep \
  > report.json
```

HTTP, URL со встроенными credentials, private/reserved IP и SSH через публичный
CLI отклоняются. SSH доступен только программным вызовом
`fetch_repo(..., allow_ssh=True)`.
Для крупных доверенно выбранных репозиториев лимит shallow clone можно поднять,
не отключая остальные проверки: `--max-clone-mib 512` или
`SV_MAX_CLONE_MIB=512` (допустимо `1..4096`).
Для медленного большого clone задайте `--clone-timeout 240` или
`SV_CLONE_TIMEOUT=240`.
Если рабочее дерево превышает inventory limit, отдельно задайте
`--max-scan-mib 256` или `SV_MAX_SCAN_MIB=256` (допустимо `1..1024`).

```bash
skills-verified https://github.com/example/large-skills.git \
  --skip llm \
  --clone-timeout 240 \
  --max-clone-mib 512 \
  --max-scan-mib 512 \
  > report.json
```

### Выбор анализаторов

```bash
skills-verified ./skill --only 'pattern,guardrails,mcp' > report.json
skills-verified ./skill --skip 'cve,llm,semgrep' > report.json
```

Доступные имена в стабильном порядке `analyzer_runs`:

```text
pattern, cve, bandit, shellcheck, semgrep, guardrails, permissions, supply_chain,
llm, obfuscation, reverse_shell, exfiltration, behavioral, mcp,
config_injection, metadata, known_threats, privilege
```

Неизвестное имя, пересечение `--only` и `--skip` или пустой итоговый набор дают
CLI-ошибку с кодом `2`.

По умолчанию одновременно запускаются до трёх независимых анализаторов. Лимит
задаётся через `--analyzer-concurrency` или `SV_ANALYZER_CONCURRENCY` (`1..18`);
значение `1` включает последовательный режим. Порядок завершения не влияет на
порядок runs и diagnostics в JSON. Это отдельный пул верхнего уровня;
`--llm-concurrency` ограничивает HTTP-запросы внутри LLM-анализатора.

Для интерактивного запуска прогресс включается автоматически, если `stderr` —
терминал. Его можно явно включить или отключить:

```bash
skills-verified ./skill --progress --analyzer-concurrency 3 > report.json
skills-verified ./skill --no-progress > report.json
```

Старт, статус, время каждого анализатора и прогресс LLM batches печатаются только
в `stderr`, поэтому перенаправленный `stdout` остаётся валидным JSON.
Итоговые времена доступны в `scan.duration_ms` и `analyzer_runs[].duration_ms`:

```bash
jq '{total_ms: .scan.duration_ms, analyzers: [.analyzer_runs[] | {name, status, duration_ms}]}' report.json
```

Из-за параллельного запуска сумма времён анализаторов может быть больше общего
времени scan.

### Shell-анализ

ShellCheck запускается для `.sh`, `.bash` и файлов без расширения с shebang
`sh`/`bash` только внутри обнаруженных skill roots:

```bash
skills-verified ./skill --only shellcheck,pattern > shell-report.json
```

ShellCheck принимает `error`, `warning` и два security-relevant `info` rules:
`SC2029` (remote-command expansion) и `SC2035` (option injection через glob).
Остальные `info/style` отбрасываются как code-quality шум. `pattern` дополняет
его узкими flow-проверками для dynamic `eval`, caller-controlled `source`,
непроверенной распаковки и predictable temporary files. Repository
`.shellcheckrc`, `SHELLCHECK_OPTS` и inline `# shellcheck disable=...` не могут
скрыть результат. Произвольные `source`-файлы не подключаются, scripts никогда
не исполняются. Rule IDs имеют вид `SV-SHELLCHECK-SC2115`, а фактическая версия
инструмента сохраняется в `analyzer_runs[].version`.

### LLM-анализ

LLM является явным opt-in, потому что выбранному endpoint передаётся содержимое
исходных файлов после redaction очевидных литеральных секретов. Выражения вроде
`os.getenv("TOKEN")` и `config["password"]` не скрываются: они не содержат само
значение секрета и нужны для корректного source-to-sink анализа.

```bash
export SV_LLM_URL='https://llm.example.com/v1'
export SV_LLM_MODEL='security-model'
export SV_LLM_KEY='replace-with-secret'
export SV_LLM_CONCURRENCY=3

skills-verified ./skill --only llm --progress > llm-report.json
```

LLM получает явное требование писать человекочитаемые `title` и `description`
на русском; общая `remediation` для LLM findings также русская. Стабильные
машинные ключи и enum (`severity`, `verification.status`, `rule_id`), пути и
точная evidence-цитата не переводятся, чтобы JSON оставался совместимым со
схемой и внешними сервисами.

Те же значения принимаются через `--llm-url`, `--llm-model` и `--llm-key`, но
секрет рекомендуется задавать только через `SV_LLM_KEY`: CLI-аргументы могут
быть видны другим локальным процессам.
По умолчанию candidate и verification запросы содержат provider-side
`response_format` с JSON Schema и `strict: true`. Та же схема повторно проверяется
локально: невалидный ответ не попадает в `findings` и отмечается diagnostic
`llm_response_invalid`.

Если обнаружены skill roots, LLM получает только файлы внутри них; `SKILL.md`
и затем `scripts/` идут первыми. Для репозитория без skills анализируется весь
допустимый inventory. Проверка выполняется в два этапа. Первый запрос создаёт
кандидатов, после чего каждый кандидат привязывается к существующему пути и
exact-цитате в этом файле
после нормализации переносов, пустых строк и внешних отступов. Реальный диапазон
не более 20 строк вычисляется из найденной цитаты; номера строк модели служат
только подсказкой при нескольких совпадениях. Равноудалённая неоднозначность и
цитаты, отсутствующие в файле, отклоняются. Перепривязка фиксируется diagnostic
`llm_evidence_rebound` без сохранения исходного кода. Затем три разных
adversarial-lens запроса пытаются опровергнуть кандидата. Результат записывается
в `finding.verification.status`:

Отклонение отдельного claim с невалидными полями или evidence считается штатной
фильтрацией: `llm_finding_rejected` и `llm_evidence_mismatch` имеют уровень
`info` и не переводят полностью выполненный LLM run в `partial`.

- `corroborated` — не менее двух из трёх проверок подтвердили прямое evidence;
- `disputed` — не менее двух проверок отвергли утверждение;
- `unverified` — консенсуса нет, проверка отключена или завершилась не полностью.

Это не score и не решение о публикации. `confidence` остаётся исходной оценкой
модели и не участвует в консенсусе. Даже `corroborated` означает согласие
проверок, а не математическую гарантию отсутствия hallucination.
Кандидаты с валидным evidence остаются findings при любом verification status:
внешний сервис сам решает, отклонять ли `disputed` или `unverified`.
`candidate_id` включает claim, severity, путь, полный диапазон и evidence, поэтому
разные утверждения на одной строке проверяются независимо. Если evidence содержит
заменённый секрет, его `kind` равен `redacted_source`, а hash фактического LLM
prompt хранится в provenance.

Ответы с `finish_reason`, отличным от `stop`, отсутствующим candidate ID или
неполной/невалидной структурой не считаются чистым результатом и переводят run в
`partial`. В отчёте сохраняется requested model; фактически сообщённые provider
model/system fingerprint находятся в provenance diagnostics.
Candidate request с wall-clock timeout или неполным provider response получает
ровно один bounded retry: исходный batch детерминированно делится на две меньшие
line-aware части, а их общий wall-clock budget не превышает budget одной попытки.
Retry одной волны остаются параллельными, координаты строк и hash каждого
фактического prompt фиксируются в `llm_batch_provenance`. Остальные API и
validation errors не повторяются автоматически. Retry не рекурсивен: если хотя
бы одна из двух частей снова не завершилась, LLM run остаётся `partial`.

Endpoint, который не поддерживает `response_format`, запускается так:

```bash
skills-verified ./skill \
  --only llm \
  --no-llm-structured-output \
  > llm-report.json
```

Для медленных reasoning-моделей можно увеличить лимиты запроса и ответа:

```bash
skills-verified ./skill --only llm \
  --llm-timeout 180 \
  --llm-total-timeout 1800 \
  --llm-max-tokens 16384 \
  --llm-token-parameter max_completion_tokens \
  --llm-reasoning-effort minimal \
  --llm-concurrency 3 \
  --llm-verification-runs 3 \
  > llm-report.json
```

Те же параметры доступны через `SV_LLM_TIMEOUT`, `SV_LLM_TOTAL_TIMEOUT` и
`SV_LLM_MAX_TOKENS`. По умолчанию одновременно выполняются три LLM-запроса;
лимит `1..8` задаётся через `--llm-concurrency` или `SV_LLM_CONCURRENCY`.
Значение `1` включает прежний последовательный режим. Число проверок задаётся через
`SV_LLM_VERIFICATION_RUNS` (от `0` до `5`). Значение `0` отключает consensus и
оставляет кандидатов в статусе `unverified`. По умолчанию LLM получает все batch
всех подходящих файлов; большие файлы делятся на сегменты с исходными номерами
строк и не обрезаются.
Опциональный бюджет можно задать через `--llm-max-batches` или
`SV_LLM_MAX_BATCHES` положительным целым числом. Значение `0` не имеет особого
смысла и отклоняется CLI. Если batch больше явно заданного лимита, run становится
`partial` с diagnostic `llm_batch_limit_exceeded`.

Общий deadline по умолчанию не установлен: каждый запрос всё равно ограничен
`--llm-timeout`. При необходимости общий бюджет задаётся явно через
`--llm-total-timeout` или `SV_LLM_TOTAL_TIMEOUT`; незавершённое покрытие отражается
как `partial`.

По умолчанию лимит отправляется как `max_tokens` для совместимости с Ollama,
LM Studio и legacy endpoints. Для моделей, требующих новый параметр, используйте
`--llm-token-parameter max_completion_tokens` или
`SV_LLM_TOKEN_PARAMETER=max_completion_tokens`.
Reasoning effort передаётся только по явной настройке:
`--llm-reasoning-effort minimal` или
`SV_LLM_REASONING_EFFORT=minimal`. Не задавайте её для endpoint, который не
поддерживает OpenAI-compatible поле `reasoning_effort`.

Для корпоративного CA worker учитывает `SSL_CERT_FILE`.

### Сохранение результата

По умолчанию JSON печатается в `stdout`. `--output` дополнительно сохраняет ту же
структуру в файл; вывод в `stdout` при этом остаётся:

```bash
skills-verified ./skill \
  --skip llm,bandit,shellcheck,semgrep \
  --output reports/report.json \
  >/dev/null

skills-verified ./skill --compact > report.min.json
```

### Просмотр JSON в браузере

Откройте автономный `report-viewer.html` и выберите любой JSON-отчёт через кнопку
«Выбрать JSON» или перетащите файл в окно:

```bash
open report-viewer.html
```

Viewer обрабатывает файл только в браузере, показывает фактические findings,
категории, analyzer runs и diagnostics и не вычисляет score или verdict.

## Статусы и коды завершения

`scan.status` описывает качество выполнения, а не публикационную политику:

- `complete` — все выбранные анализаторы завершились полностью;
- `partial` — анализатор или часть scope были пропущены либо ограничены;
- `failed` — безопасный inventory не построен или ни один анализатор не дал
  результата.

Каждый элемент `analyzer_runs` имеет собственный статус: `completed`, `partial`,
`skipped` или `failed`. Причины находятся в `reason` и `diagnostics`.

| Exit code | Значение |
|---:|---|
| `0` | JSON сформирован; `scan.status` равен `complete` или `partial` |
| `2` | Ошибка аргументов, source или подготовки репозитория |
| `3` | Scan имеет статус `failed` или не записан `--output` |

## JSON-контракт

Отчёт содержит:

- `source` — исходный input, commit SHA и hash реально проверенного artifact;
- `scope` и `platforms` — какие файлы, skill roots и платформы обнаружены;
- `analyzer_runs` — версии, длительность, статус и число findings;
- `findings` — стабильные `rule_id`, fingerprint, severity, confidence, location,
  evidence, remediation, references и для LLM-кандидатов typed `verification`;
- `diagnostics` — parse errors, ограничения, недоступные или частичные проверки;
- `summary` — только агрегированное число findings по severity, без score/verdict.

Пример выборки для внешнего сервиса:

```bash
jq '{
  schema_version,
  status: .scan.status,
  artifact: .source.artifact_sha256,
  scope,
  analyzer_runs,
  findings,
  diagnostics
}' report.json
```

Потребитель обязан учитывать `scan.status`, `scope`, `analyzer_runs` и
`diagnostics`; отсутствие findings само по себе не означает безопасный skill.

## Docker

Образ включает Bandit, ShellCheck и Semgrep:

```bash
docker build -t skills-verified .

docker run --rm \
  -v "/absolute/path/to/skill:/input:ro" \
  skills-verified /input \
  --skip llm,semgrep \
  > report.json
```

Удалённый репозиторий не требует volume:

```bash
docker run --rm skills-verified \
  https://github.com/example/skill.git \
  --skip llm,semgrep \
  > report.json
```

Для Docker Compose положите проверяемые файлы в `workspace/`:

```bash
docker compose build
docker compose run --rm skills-verified \
  /workspace \
  --skip llm,semgrep \
  --output /reports/report.json \
  >/dev/null
```

## CI

[`action.yml`](action.yml) запускает тот же CLI и возвращает `report-path`,
`scan-status` и `findings-count`. Примеры для GitHub Actions и GitLab CI находятся
в [`examples/`](examples/). Они сохраняют JSON, но не принимают решение о
публикации.

## Разработка

```bash
python -m pip install -e ".[dev,scanners]"
pytest tests/ -v
pytest tests/ --cov=skills_verified --cov-report=term-missing
ruff check src/ tests/
ruff format --check src/ tests/
```

Новый анализатор наследует `Analyzer`, задаёт стабильное lowercase-имя, возвращает
`Finding` и регистрируется в `cli.py`. Тесты должны проверять location, evidence,
diagnostics и analyzer run status. Правила разработки описаны в
[AGENTS.md](AGENTS.md).

## Проверочный corpus

[`tests/corpora/blind-60/`](tests/corpora/blind-60/) содержит 50 намеренно
уязвимых и 10 безопасных скиллов. Не запускайте их scripts и не устанавливайте
dependencies. `ground_truth.json` расположен вне сканируемого `repo/`: передавайте
CLI только отдельный каталог `repo/skills/<skill>`, например:

```bash
skills-verified tests/corpora/blind-60/repo/skills/shell-backup \
  --skip llm --compact > report.json
```

[Сравнительный отчёт](tests/corpora/blind-60/REPORT.md) фиксирует семь режимов:
обычные анализаторы и шесть Cloud.ru LLM. Он отдельно показывает raw detection,
результат при допуске только deterministic/`corroborated`, ложные claims,
полноту runs и время. Это benchmark snapshot, а не score или публикационная
политика. Raw JSON остаётся в игнорируемом каталоге `reports/`.

## Безопасность и ограничения

Репозиторий считается недоверенным. Scanner не исполняет его scripts и не запускает
dependency resolver. Pinned Python/npm dependencies разбираются статически, а OSV
получает только ecosystem, package name и version.

Основные лимиты:

- acquisition: 120 секунд, shallow clone и 128 MiB оценочного места по умолчанию
  (`--clone-timeout` и `--max-clone-mib` позволяют явно поднять лимиты);
- inventory: 10 000 файлов и 50 MiB суммарно по умолчанию; отдельного лимита на
  один файл нет (`--max-scan-mib` позволяет явно поднять общий бюджет до
  1024 MiB), 10 секунд;
- CVE: 10 000 manifest records и 1 000 dependencies; найденные OSV records
  обогащаются параллельно без искусственного лимита на detail-запросы;
- LLM: сегменты до 50 000 символов, все batch по умолчанию, 30 секунд на запрос,
  опциональный общий deadline и до 100 findings на batch.

Внутренние symlink aliases покрываются через их каноническую цель; внешние,
битые и ведущие в исключённые каталоги ссылки отклоняются. Special files не
анализируются, обычные файлы копируются в отдельный временный workspace, а внешние
workers имеют собственные deadlines и size limits. Dynamic
sandbox execution, подписи, attestation и публикационная политика не входят в core.

Актуальная спецификация: [policy-free scan report roadmap](docs/superpowers/specs/2026-07-13-policy-free-scan-report-roadmap.md).
