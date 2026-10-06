# Ошибки и диагностика в JSON-отчёте skills-verified

## 1. Модель ошибок

Утилита не формирует отдельный формат ответа для прогонов со сбоями. Во всех
случаях, включая полный отказ, на выходе формируется отчёт одной и той же схемы
(`schema_version: "1.0"`). Информация о сбоях размещается в трёх полях:

| Поле | Назначение |
|---|---|
| `scan.status` | Общая полнота выполнения |
| `analyzer_runs[]` | Статус каждого анализатора по отдельности |
| `diagnostics[]` | Перечень конкретных отклонений с указанием кода и файла |

Отсутствие элементов в `findings` не является признаком безопасности
проверяемого артефакта и подлежит интерпретации только совместно с полями выше.

## 2. Значения `scan.status`

| Значение | Условие возникновения | Пригодность отчёта |
|---|---|---|
| `complete` | Все выбранные анализаторы выполнены полностью, охват не сокращён | Полная |
| `partial` | Хотя бы один анализатор не в статусе `completed`, либо часть файлов исключена из охвата, либо присутствует диагностика уровня `error` | Ограниченная |
| `failed` | Ни один анализатор не выдал результата | Отсутствует |

Статус `partial` возникает в том числе при успешном завершении всех
анализаторов — например, когда файл исключён из охвата по превышению лимита
размера (см. пример 6.2).

## 3. Структура `analyzer_runs[]`

```json
{
  "name": "bandit",
  "status": "partial",
  "duration_ms": 150,
  "findings_count": 0,
  "reason": "analyzer_reported_diagnostics",
  "version": "1.9.4"
}
```

Допустимые значения `status`: `completed`, `partial`, `skipped`, `failed`.

Типовые значения `reason`:

| Значение | Интерпретация |
|---|---|
| `analyzer_reported_diagnostics` | Анализатор выполнен, но зафиксировал хотя бы одну диагностику уровня `warning` или `error`. Диагностики уровня `info` статус не понижают |
| `not_available` | Анализатор не запущен: инструмент отсутствует или не сконфигурирован |
| `source_fetch_failed` | Исходники не получены, выполнение не начиналось |
| `analyzer_crashed:<ТипИсключения>` | Анализатор завершён аварийно |
| `availability_check_failed:<ТипИсключения>` | Проверка доступности анализатора завершена аварийно |
| `repository_inventory_failed` | Не построен перечень файлов, выполнение не начиналось |
| `scan_execution_failed` | Непредвиденный сбой сканера, выполнение не начиналось |

## 4. Структура `diagnostics[]`

Единая форма для всех отклонений:

```json
{
  "code": "python_parse_error",
  "message": "Could not parse Python source at line 1: invalid syntax",
  "level": "warning",
  "analyzer": "behavioral",
  "path": "broken.py",
  "details": { "line": 1, "offset": 7 }
}
```

| Поле | Описание |
|---|---|
| `code` | Стабильный идентификатор. Единственное поле, пригодное для автоматической обработки |
| `message` | Текст произвольной формы, подлежит изменению между версиями |
| `level` | `error` — нарушено покрытие; `warning` — данные частично пропущены; `info` — протокольная отметка |
| `analyzer` | Имя анализатора либо `null` для диагностик уровня сканера |
| `path` | Путь относительно корня проверяемого репозитория либо `null` |
| `details` | Структурированные параметры, состав зависит от `code` |

## 5. Коды завершения процесса

| Код | Условие | Действие |
|---:|---|---|
| `0` | `scan.status` равен `complete` или `partial` | Обработать отчёт |
| `2` | Ошибка аргументов либо получения исходников | Проверить источник, доступы, лимиты клонирования |
| `3` | `scan.status` равен `failed` либо не записан `--output` | Проанализировать `diagnostics` уровня `error` |

Отчёт выводится в `stdout` во всех случаях, когда сканирование было начато,
включая коды завершения 2 и 3. Исключение — ошибки разбора аргументов командной
строки (неизвестный параметр, неизвестное имя анализатора в `--only` / `--skip`):
процесс завершается кодом 2 до формирования отчёта, вывод в `stdout` отсутствует.
Служебные сообщения направляются в `stderr`.

## 6. Примеры

### 6.1. Полный отказ (`failed`, код завершения 2)

```json
{
  "scan": { "status": "failed", "duration_ms": 0, "started_at": "2026-09-02T10:09:30.139315Z" },
  "source": {
    "input": "/nonexistent/path/to/skill",
    "commit_sha": null,
    "artifact_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "scope": { "skill_roots": [], "files_scanned": 0, "files_skipped": 0, "bytes_scanned": 0 },
  "analyzer_runs": [
    { "name": "pattern", "status": "skipped", "reason": "source_fetch_failed",
      "duration_ms": 0, "findings_count": 0, "version": "0.2.0" }
  ],
  "findings": [],
  "diagnostics": [
    { "code": "source_fetch_failed", "level": "error", "analyzer": null, "path": null,
      "message": "ValueError: Local path does not exist: /nonexistent/path/to/skill",
      "details": {} }
  ]
}
```

Признаки: нулевые значения в `scope`, `artifact_sha256` равен хеш-сумме пустой
последовательности, все элементы `analyzer_runs` в статусе `skipped` с общей
причиной.

### 6.2. Сокращение охвата (`partial`, код завершения 0)

Анализаторы завершены успешно, часть файлов исключена:

```json
{
  "scan": { "status": "partial" },
  "scope": { "skill_roots": ["."], "files_scanned": 1, "files_skipped": 1, "bytes_scanned": 33 },
  "analyzer_runs": [
    { "name": "pattern", "status": "completed", "reason": null,
      "duration_ms": 0, "findings_count": 0, "version": "0.2.0" }
  ],
  "diagnostics": [
    { "code": "repository_path_skipped", "level": "warning", "analyzer": null, "path": "blob.txt",
      "message": "Repository path was skipped: file_too_large",
      "details": { "reason": "file_too_large", "size_bytes": 2097152, "target": null } }
  ]
}
```

### 6.3. Аварийное завершение анализатора

Пример получен принудительным вызовом исключения в анализаторе; имя `boom`
синтетическое.

```json
{
  "scan": { "status": "failed" },
  "analyzer_runs": [
    { "name": "boom", "status": "failed", "reason": "analyzer_crashed:TypeError",
      "duration_ms": 1, "findings_count": 0, "version": "9.9.9" }
  ],
  "diagnostics": [
    { "code": "analyzer_failed", "level": "error", "analyzer": "boom", "path": null,
      "message": "Analyzer boom failed: TypeError: Boom.analyze() got multiple values for argument 'context'",
      "details": {} }
  ]
}
```

При наличии других работоспособных анализаторов статус сканирования составил бы
`partial`.

## 7. Причины, по которым файл не прочитан или не проанализирован

Файл может выпасть из проверки на любом из пяти этапов. Ниже перечислены все
случаи с указанием того, как они отражаются в отчёте.

### 7.1. Файл не включён в перечень при обходе репозитория

Обход выполняется до запуска анализаторов и не следует по символическим ссылкам.

| Причина | `details.reason` | Отражение в отчёте |
|---|---|---|
| Каталог входит в список исключаемых: `.git`, `.hg`, `.svn`, `.tox`, `.venv`, `venv`, `node_modules`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache` | `excluded_directory` | Не учитывается в `scope.files_skipped`, диагностика не формируется |
| Символическая ссылка внутри репозитория на файл, который проверяется отдельно | `internal_symlink_alias` | `repository_internal_symlink_alias`, уровень `info`. Содержимое покрыто целевым файлом |
| Размер файла превышает `--max-scan-mib` | `file_too_large` | `repository_path_skipped`, `scope.files_skipped` увеличивается, `scan.status` понижается до `partial` |
| Не обычный файл: сокет, устройство, именованный канал | `special_file` | То же |
| Символическая ссылка ведёт за пределы репозитория | `symlink_outside_repository` | То же |
| Символическая ссылка не разрешается | `symlink_unresolvable` | То же |
| Символическая ссылка ведёт в исключаемый каталог | `symlink_target_excluded` | То же |
| Путь после разрешения оказался вне репозитория | `outside_repository` | То же |
| Не получены атрибуты файла | `stat_error:<errno>` | То же |
| Путь не разрешается | `resolve_error:<errno>` | То же |

Отдельная группа причин прерывает обход целиком: сканирование завершается
статусом `failed` с диагностикой `repository_inventory_failed`.

| Причина | Порог |
|---|---|
| Превышено число файлов | 10 000 |
| Превышен суммарный размер | значение `--max-scan-mib`, по умолчанию 50 МиБ |
| Превышено время обхода | 10 секунд |
| Ошибка обхода дерева каталогов | — |
| Корень репозитория не является каталогом | — |

### 7.2. Файл не скопирован в изолированную копию

После обхода файлы копируются в изолированный каталог, из которого работают
анализаторы. Файл, изменившийся или ставший недоступным между обходом и
копированием, из проверки исключается: формируется `repository_file_copy_failed`,
`scope.files_skipped` увеличивается, статус понижается до `partial`.

### 7.3. Файл не выбран анализатором

Наиболее частая причина отсутствия результатов, при которой **диагностика не
формируется**: файл присутствует в `scope.files_scanned`, но ни один анализатор
его не рассматривает.

Каждый анализатор обрабатывает собственный перечень расширений:

| Анализатор | Обрабатываемые файлы |
|---|---|
| `pattern` | `.py`, `.js`, `.mjs`, `.ts`, `.sh`, `.bash`, `.ps1`, `.rb`, `.json`, `.yaml`, `.yml`, `.toml`, `.md`, `.txt` |
| `llm` | `.py`, `.js`, `.mjs`, `.ts`, `.sh`, `.ps1`, `.rb`, `.json`, `.yaml`, `.yml`, `.toml`, `.md`, `.txt` |
| `reverse_shell` | `.py`, `.js`, `.ts`, `.rb`, `.sh`, `.ps1`, `.pl`, `.php` |
| `obfuscation` | `.py`, `.js`, `.ts`, `.rb`, `.sh`, `.ps1` |
| `permissions` | `.py`, `.js`, `.mjs`, `.ts`, `.sh`, `.bash`, `.ps1` |
| `exfiltration` | `.py`, `.js`, `.ts`, `.rb`, `.sh` |
| `privilege` | `.py`, `.js`, `.ts` |
| `mcp` | `.py`, `.js`, `.mjs`, `.ts`, `.mts` |
| `behavioral` | `.py` для анализа синтаксического дерева |
| `metadata` | `.md` |
| `guardrails` | `.py`, `.js`, `.ts`, `.json`, `.yaml`, `.yml`, `.toml`, `.md`, `.txt` |
| `known_threats` | `.py`, `.js`, `.ts`, `.sh`, `.ps1`, `.rb`, `.json`, `.yaml`, `.yml`, `.md`, `.txt` |
| `cve` | Манифесты зависимостей: `requirements*.txt`, `pyproject.toml`, `Pipfile`, `package-lock.json`, `bun.lock` |
| `supply_chain` | `package.json`, `setup.py`, `requirements.txt` |
| `shellcheck` | Файлы `.sh` и `.bash`, а также файлы без расширения с шебангом `sh`, `dash` или `bash` |
| `bandit` | `.py`, обработка выполняется внешним инструментом |
| `semgrep` | Определяется набором правил, обработка выполняется внешним инструментом |

Файл на языке, не входящем ни в один перечень (например, `.go`, `.rs`, `.java`,
`.c`), попадает в охват, но содержательной проверке подвергается только
средствами Semgrep, если для него существует правило.

Сверх перечня расширений действует ограничение по размеру в анализаторе
`known_threats`: сверка с хеш-суммами известных вредоносных файлов выполняется
только для файлов до 1 МиБ. Файлы большего размера пропускаются без диагностики,
остальные проверки этого анализатора к ним применяются.

Анализатор `shellcheck` пропускает без диагностики файлы, не имеющие расширения
`.sh` или `.bash` и не содержащие поддерживаемого шебанга. Диагностика
формируется только для файлов с расширением `.sh` или `.bash`, шебанг которых не
распознан.

Ещё одна причина того же характера — сокращение области анализа до обнаруженных
корней скиллов. Если определение платформы выделило конкретные подкаталоги,
анализаторы обрабатывают только их, а файлы за их пределами не рассматриваются.
Диагностика при этом не формируется; фактический перечень приведён в
`scope.skill_roots`. При отсутствии обнаруженных корней используется значение
`["."]`, то есть весь репозиторий.

### 7.4. Файл выбран, но не прочитан

| Причина | Код диагностики |
|---|---|
| Ошибка ввода-вывода или прав доступа | `source_read_error` и его аналоги по анализаторам (см. 7.6) |
| Путь оказался символической ссылкой на момент чтения. Проверка выполняется в анализаторах `privilege` и `cve` | `privilege_file_read_failed`, `manifest_parse_error` |
| Размер файла превышает 2 МиБ на операцию чтения. Ограничение действует только в анализаторах `privilege` и `cve`, использующих защищённое чтение; остальные анализаторы читают файл целиком | `privilege_file_read_failed`, `manifest_parse_error` |

### 7.5. Файл прочитан, но не разобран

| Причина | Код диагностики |
|---|---|
| Синтаксическая ошибка в файле `.py` | `python_parse_error`, а для Bandit — `bandit_analysis_error` |
| Некорректный манифест зависимостей | `manifest_parse_error` |
| Зависимость указана без фиксированной версии | `unpinned_dependency`, проверка на уязвимости для неё не выполняется |
| Файл `.sh` или `.bash` с неподдерживаемым шебангом, например `#!/usr/bin/zsh` | `shellcheck_unsupported_dialect` |
| Некорректная конфигурация платформы | `platform_config_parse_failed`, `platform_config_schema_invalid` |
| Конфигурация в формате JSON5 | `platform_config_parse_deferred`, содержимое сохранено, но не разобрано |
| Некорректный YAML-фронтматтер `SKILL.md` | `skill_metadata_invalid` |

### 7.6. Один и тот же файл в нескольких анализаторах

Сбой чтения фиксируется каждым анализатором отдельно, под собственным кодом:

| Анализатор | Код при сбое чтения |
|---|---|
| `pattern`, `behavioral`, `exfiltration`, `guardrails`, `obfuscation`, `permissions`, `reverse_shell`, `known_threats` | `source_read_error` |
| `known_threats`, дополнительно | `file_hash_read_error`, `file_stat_error` |
| `metadata` | `documentation_read_error` |
| `mcp` | `mcp_source_read_failed` |
| `privilege` | `privilege_file_read_failed` |
| `shellcheck` | `shellcheck_file_read_failed` |
| `supply_chain` | `package_json_read_error`, `requirements_read_error`, `setup_py_read_error` |
| `llm` | `llm_file_read_failed` |
| `cve` | `manifest_parse_error`; отдельный код для сбоя чтения не предусмотрен |
| `semgrep` | Диагностика не формируется: при сбое чтения проверка находки возвращает отрицательный результат |

Анализаторы `bandit` и `config_injection` файлы самостоятельно не читают: первый
передаёт пути внешнему инструменту, второй работает с конфигурациями, ранее
разобранными в контексте сканирования.

Выборка всех сбоев чтения независимо от анализатора:

```bash
jq '[.diagnostics[] | select(.code | test("read_(error|failed)$|_stat_error$"))
     | {path, code, analyzer}]' report.json
```

### 7.7. Анализатор не запускался

В этом случае не проверяется ни один файл. Отражается в `analyzer_runs[]`:

| Причина | Статус и причина |
|---|---|
| Анализатор исключён параметрами `--skip` или `--only` | Отсутствует в `analyzer_runs[]` |
| Внешний инструмент не установлен | `skipped`, `not_available` |
| Для `llm` не заданы `--llm-url`, `--llm-model`, `--llm-key` | `skipped`, `not_available` |
| Анализатор завершён аварийно | `failed`, `analyzer_crashed:<ТипИсключения>` |
| Исходники не получены | `skipped`, `source_fetch_failed` |

Для анализатора `llm` дополнительно возможна проверка части репозитория при
заданном `--llm-max-batches`: формируется `llm_batch_limit_exceeded` с указанием
`details.batches_total` и `details.batches_analyzed`.

## 8. Справочник кодов `diagnostics[].code`

### 8.1. Получение и обход репозитория

| Код | Уровень | Описание |
|---|---|---|
| `source_fetch_failed` | error | Исходники не получены: недоступен путь или URL, таймаут, превышен `--max-clone-mib` |
| `repository_inventory_failed` | error | Не построен перечень файлов: превышен суммарный лимит `--max-scan-mib`, превышен лимит времени обхода либо ошибка обхода дерева каталогов |
| `scan_execution_failed` | error | Непредвиденный сбой сканера. Подлежит регистрации как дефект |
| `repository_path_skipped` | warning | Файл исключён из охвата. Причина в `details.reason`: `file_too_large`, `special_file`, `outside_repository`, `symlink_outside_repository`, `symlink_unresolvable`, `symlink_target_excluded`, `stat_error:<errno>`, `resolve_error:<errno>` |
| `repository_file_copy_failed` | warning | Файл не скопирован в изолированную копию |
| `repository_internal_symlink_alias` | info | Внутренний симлинк, содержимое проверено по целевому файлу |
| `output_write_failed` | error | Не записан файл `--output` |
| `no_analyzers_selected` | error | Ни один анализатор не передан в сканирование. Приводит к статусу `failed` и коду завершения 3 |

### 8.2. Определение платформы и метаданных

| Код | Уровень | Описание |
|---|---|---|
| `skill_metadata_invalid` | warning | Некорректный YAML-фронтматтер `SKILL.md` |
| `platform_detection_failed` | error | Платформа не определена |
| `platform_parse_failed` | error | Файл платформы не разобран |
| `platform_config_read_failed` | warning | Конфигурация платформы не прочитана |
| `platform_config_parse_failed` | warning | Конфигурация платформы не разобрана |
| `platform_config_schema_invalid` | warning | Структура конфигурации не соответствует ожидаемой |
| `platform_config_parse_deferred` | warning | Разбор конфигурации отложен: содержимое сохранено, но не разобрано (JSON5) |
| `documentation_read_error` | warning | Файл документации не прочитан |

### 8.3. Чтение и разбор исходных файлов

| Код | Уровень | Описание |
|---|---|---|
| `source_read_error` | warning | Файл не прочитан вследствие ошибки ввода-вывода или прав доступа. Ошибки кодировки к этому коду не приводят |
| `python_parse_error` | warning | Синтаксическая ошибка в файле `.py`, позиция в `details.line` и `details.offset` |
| `file_hash_read_error` | warning | Не вычислена хеш-сумма файла |
| `file_stat_error` | warning | Не получены атрибуты файла |
| `privilege_file_read_failed` | warning | Файл не прочитан при проверке привилегий |
| `mcp_source_read_failed` | warning | Конфигурация MCP не прочитана |
| `mcp_source_path_invalid` | warning | Некорректный путь в конфигурации MCP |

### 8.4. Внешние инструменты

| Код | Уровень | Описание |
|---|---|---|
| `bandit_analysis_error` | warning | Bandit не обработал файл |
| `semgrep_timeout` | warning | Превышен лимит времени Semgrep |
| `semgrep_analysis_error` | warning | Semgrep вернул ошибку |
| `semgrep_partial_parsing` | warning | Semgrep разобрал часть файлов |
| `semgrep_ruleset_provenance` | info | Отметка о хеш-фиксации набора правил, присутствует в штатных прогонах |
| `shellcheck_timeout` | warning | Превышен лимит времени ShellCheck |
| `shellcheck_execution_failed` | error | ShellCheck завершён с ненулевым кодом возврата. Отсутствие исполняемого файла даёт не этот код, а статус `skipped` с причиной `not_available` |
| `shellcheck_incomplete` | warning | Проверены не все shell-скрипты |
| `shellcheck_response_invalid` | error | Некорректный JSON в выводе ShellCheck |
| `shellcheck_location_invalid` | warning | Некорректные координаты находки |
| `shellcheck_file_read_failed` | warning | Скрипт не прочитан |
| `shellcheck_unsupported_dialect` | warning | Диалект shell не поддерживается |
| `shellcheck_suppressions_ignored` | info | Директивы подавления, заданные в проверяемом репозитории, не применены |

### 8.5. Зависимости и уязвимости

| Код | Уровень | Описание |
|---|---|---|
| `osv_lookup_failed` | warning | База OSV недоступна. Анализатор `cve` завершается аварийно, проверка на уязвимости в прогоне не выполняется |
| `osv_detail_lookup_failed` | warning | Не получены детали по уязвимости |
| `unpinned_dependency` | warning | Зависимость без фиксированной версии, проверка на уязвимости не выполнялась |
| `unsupported_requirement` | warning | Неподдерживаемый формат строки манифеста |
| `manifest_parse_error` | warning | Манифест зависимостей не разобран |
| `manifest_skipped` | warning | Манифест исключён из обработки |
| `manifest_record_limit_exceeded` | warning | Превышен лимит записей манифеста, обработана часть |
| `dependency_limit_exceeded` | warning | Превышен лимит зависимостей, обработана часть |
| `package_json_read_error` | warning | Файл `package.json` не прочитан |
| `package_json_parse_error` | warning | Файл `package.json` не разобран |
| `package_json_schema_error` | warning | Некорректная структура `package.json` |
| `requirements_read_error` | warning | Файл `requirements.txt` не прочитан |
| `setup_py_read_error` | warning | Файл `setup.py` не прочитан |

### 8.6. LLM-анализатор

Формируются только при заданных параметрах `--llm-url`, `--llm-model`, `--llm-key`.

| Код | Уровень | Описание |
|---|---|---|
| `llm_api_failed` | warning | Запрос к API не выполнен, номер пакета в `details.batch` |
| `llm_request_timeout` | warning | Превышен `--llm-timeout` |
| `llm_total_timeout` | warning | Исчерпан бюджет `--llm-total-timeout` |
| `llm_request_retried` | info | Выполнен повторный запрос |
| `llm_response_invalid` | warning | Ответ модели не разобран |
| `llm_response_incomplete` | warning | Ответ модели прерван, требуется увеличение `--llm-max-tokens` |
| `llm_batch_limit_exceeded` | warning | Обработана часть репозитория вследствие `--llm-max-batches` |
| `llm_finding_limit_exceeded` | warning | Превышен лимит кандидатов |
| `llm_finding_rejected` | info | Кандидат отклонён как невалидный |
| `llm_evidence_mismatch` | info | Цитата модели не найдена в файле, кандидат отклонён |
| `llm_evidence_rebound` | info | Цитата найдена в другой позиции, координаты скорректированы |
| `llm_duplicate_candidates_removed` | info | Устранены дубликаты |
| `llm_file_read_failed` | warning | Файл не прочитан при формировании запроса |
| `llm_file_path_invalid` | warning | Модель вернула некорректный путь |
| `llm_input_path_too_long` | warning | Превышена допустимая длина пути |
| `llm_content_redacted` | info | Часть содержимого исключена перед отправкой |
| `llm_structured_output_disabled` | info | Structured output отключён |
| `llm_provenance`, `llm_batch_provenance` | info | Сведения о модели, запросах и их хеш-суммах |
| `llm_verification_summary` | info | Итог состязательной верификации кандидатов |
| `llm_verification_api_failed` | warning | Сбой API на этапе верификации |
| `llm_verification_timeout` | warning | Превышен лимит времени верификации |
| `llm_verification_total_timeout` | warning | Исчерпан общий бюджет верификации |
| `llm_verification_response_invalid` | warning | Ответ верификации не разобран |
| `llm_verification_response_incomplete` | warning | Ответ верификации прерван |

### 8.7. Служебные

| Код | Уровень | Описание |
|---|---|---|
| `analyzer_failed` | error | Анализатор завершён аварийно, тип исключения в `analyzer_runs[].reason` |
| `analyzer_availability_failed` | error | Не выполнена проверка доступности анализатора |
| `diagnostics_suppressed` | warning | Однотипные диагностики агрегированы. Формируется анализаторами `cve` и `llm` |
| `finding_location_unknown` | warning | У находки отсутствует корректный путь |
| `finding_location_rejected` | warning | Путь находки не прошёл валидацию |
| `finding_line_invalid` | warning | Некорректный номер строки |
| `finding_end_line_invalid` | warning | Некорректный номер конечной строки |

## 9. Ограничения интерпретации

**Агрегация диагностик.** Механизм реализован в анализаторах `cve` (порог 25
записей на код) и `llm` (порог 100). При превышении порога остальные записи
заменяются одной агрегирующей (значения приведены для иллюстрации):

```json
{
  "code": "diagnostics_suppressed",
  "level": "warning",
  "analyzer": "cve",
  "path": "requirements.txt",
  "message": "Additional unpinned_dependency diagnostics were suppressed",
  "details": { "diagnostic_code": "unpinned_dependency", "suppressed_count": 47 }
}
```

Фактическое количество равно числу видимых записей и значения
`details.suppressed_count`. Подсчёт по длине массива `diagnostics` некорректен.

**Поле `message`.** Текст произвольной формы, изменяется между версиями и может
содержать пути внутренней изолированной копии репозитория. Автоматическая
обработка выполняется по полям `code`, `path` и `details`.

**Дублирование диагностик.** Один файл может быть указан в нескольких записях —
по одной от каждого анализатора. Для получения перечня проблемных файлов
требуется дедупликация по паре `path` и `code`.

## 10. Контроль полноты в CI

```bash
STATUS=$(jq -r '.scan.status' report.json)
SKIPPED=$(jq -r '.scope.files_skipped' report.json)
ERRORS=$(jq '[.diagnostics[] | select(.level == "error")] | length' report.json)

if [ "$STATUS" != "complete" ] || [ "$SKIPPED" != "0" ] || [ "$ERRORS" != "0" ]; then
  echo "Сканирование неполное: status=$STATUS skipped=$SKIPPED errors=$ERRORS" >&2
  exit 1
fi
```
