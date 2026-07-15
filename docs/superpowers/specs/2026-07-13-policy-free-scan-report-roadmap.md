# Skills Verified — Policy-Free Scan Report Roadmap

**Date:** 2026-07-13
**Status:** Core implemented in `0.2.0`; remaining items stay prioritized below

## Фактический статус реализации

P0 завершён: policy/scoring удалены, CLI всегда сериализует единый versioned
`ScanReport`, каждый анализатор имеет явный status, а ошибки и ограничения видны в
`diagnostics`. Ввод проходит через безопасный clone, ограниченный inventory и
изолированную staging-копию; зависимости разбираются статически и проверяются через
OSV без запуска package manager.

Из P1 реализованы platform profiles, рекурсивный Agent Skills discovery, стабильные
rule IDs/fingerprints, deduplication, evidence/remediation/references, версии
анализаторов и OSV batch/cache. Закреплён opt-in smoke corpus из Anthropic Skills,
NVIDIA SkillSpector и SkillTrustBench. SARIF остаётся следующим самостоятельным
форматом. P2/P3 (version diff, YARA, API/MCP endpoint, sandbox execution, SBOM,
provenance и attestation) намеренно не входят в текущую CLI-поставку.

## Решение

`skills-verified` становится анализатором, а не policy engine. Он собирает проверяемые факты о skill, описывает найденные проблемы и качество самого сканирования, после чего отдаёт стабильный JSON внешним сервисам. Решение о публикации, блокировке, исключениях и допустимом риске принимает потребитель отчёта.

Целевой поток:

```text
source -> safe input -> ScanContext -> analyzers -> deduplication -> JSON report
                                                               -> external policy service
```

Scanner не должен возвращать `trust_score`, `grade`, `publish`, `allow`, `deny` или аналогичный verdict. `severity` и `confidence` остаются техническими свойствами finding, но потребитель вправе интерпретировать их по-своему.

## Граница ответственности

Scanner отвечает за:

- полноту и воспроизводимость анализа;
- стабильные идентификаторы правил и findings;
- evidence, location, confidence и remediation;
- явное описание пропущенных, частичных и упавших проверок;
- безопасную обработку недоверенного репозитория.

Внешний сервис отвечает за:

- публикацию или блокировку skill;
- thresholds, severity policy и обязательные анализаторы;
- baselines, waivers, allowlists и срок их действия;
- объединение scan report с репутацией автора, ручной проверкой и бизнес-правилами.

Отсутствие findings означает только: завершившиеся анализаторы ничего не нашли в указанном scope. Оно не означает, что skill безопасен.

## Целевой JSON-контракт

```json
{
  "schema_version": "1.0",
  "scan": {
    "status": "complete",
    "started_at": "2026-07-13T12:00:00Z",
    "duration_ms": 842,
    "scanner": {
      "name": "skills-verified",
      "version": "0.2.0",
      "ruleset_version": "2026.07.13"
    }
  },
  "source": {
    "input": "https://github.com/example/skill",
    "commit_sha": "abc123",
    "artifact_sha256": "..."
  },
  "scope": {
    "skill_roots": ["skills/example"],
    "files_scanned": 18,
    "files_skipped": 2,
    "bytes_scanned": 18432
  },
  "platforms": [
    {"name": "agent_skills", "confidence": 1.0, "evidence": ["skills/example/SKILL.md"]}
  ],
  "analyzer_runs": [
    {
      "name": "guardrails",
      "status": "completed",
      "duration_ms": 34,
      "findings_count": 1,
      "reason": null,
      "version": "0.2.0"
    },
    {
      "name": "semgrep",
      "status": "skipped",
      "duration_ms": 0,
      "findings_count": 0,
      "reason": "not_available",
      "version": null
    }
  ],
  "findings": [
    {
      "rule_id": "SV-GUARD-001",
      "fingerprint": "sha256:...",
      "title": "Instruction override detected",
      "description": "...",
      "category": "guardrails",
      "severity": "critical",
      "confidence": 0.98,
      "analyzer": "guardrails",
      "location": {
        "path": "skills/example/SKILL.md",
        "start_line": 24,
        "end_line": 24
      },
      "evidence": {"kind": "source", "snippet": "..."},
      "remediation": "Remove instructions that override the host agent policy.",
      "references": []
    }
  ],
  "summary": {
    "findings_total": 1,
    "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
  },
  "diagnostics": []
}
```

`scan.status` описывает только выполнение: `complete`, `partial` или `failed`. Статусы analyzer run: `completed`, `partial`, `skipped`, `failed`. Parse errors, заблокированные symlinks, превышенные лимиты и ошибки внешних инструментов попадают в `diagnostics`, а не маскируются отсутствием findings.

## Что удаляем и меняем

| Область | Изменение |
|---|---|
| Scoring | Удалить `Scorer`, `Grade`, `CategoryScore`, общий и категорийные баллы |
| CLI policy | Удалить `--threshold`, `--threshold-grade` и `check_threshold()` |
| Badge | Удалить trust badge; технический scan-status badge пока не нужен |
| Report | Заменить `analyzers_used` и `llm_used` на структурированные `analyzer_runs` |
| Console/Markdown | Показывать findings, scope и полноту без «доверия», оценки и сертификации |
| README | Заменить формулировки Trust Scanner/сертификация на Security Analyzer |
| Suppression | Не добавлять baseline/waiver в core: scanner всегда отдаёт исходные findings |

Это намеренно breaking change. Новый контракт получает `schema_version`; параллельный legacy-формат добавляется только при наличии подтверждённого потребителя.

## Приоритеты

### P0 — корректный и безопасный контракт

1. Ввести новые `ScanReport`, `AnalyzerRun`, `Diagnostic`, `Location` и расширенный `Finding`.
2. Удалить scoring, grades, thresholds и badge из кода, тестов, CI-примеров и документации.
3. Переделать Pipeline: каждое выполнение анализатора обязано закончиться явным статусом и причиной.
4. Валидировать имена в `--only/--skip`; опечатка должна быть CLI-ошибкой, а не пустым clean scan.
5. Создать один `ScanContext` с platforms, skill roots, metadata, configs, tools и parse errors. Через него починить production flow `PrivilegeAnalyzer` и known-author checks.
6. Добавить `report.schema.json`, contract tests и golden JSON fixture. Неизвестные будущие поля должны игнорироваться потребителями.
7. Закрыть trust-boundary риски: symlink containment, file/count/time limits, безопасный clone с timeout/cleanup и sanitization output.
8. Отключить `pip-audit -r` для недоверенных manifests; использовать статический разбор pinned dependencies и OSV lookup. LLM оставить explicit opt-in с redaction и полным статусом выполнения.
9. Упаковать YAML rules как package resources и падать диагностикой при невозможности их загрузить.

**Критерий готовности:** сервис-потребитель может отличить «проверено и findings нет» от «проверка не запускалась/упала», а scanner нигде не принимает policy-решение.

### P1 — platform coverage и качество evidence

1. Добавить независимый `AgentSkillsProfile`, рекурсивный discovery и отдельный report scope для каждого `SKILL.md`.
2. Обновить Claude Code, Cursor и OpenClaw adapters; добавить Codex, Gemini и Copilot только через реальные fixtures и end-to-end tests.
3. Ввести стабильные `rule_id`, fingerprint и deduplication по rule/evidence/location до формирования JSON.
4. Добавить evidence snippets, end line, remediation, references и версии ruleset/analyzer.
5. Встроить OSV batch client с cache и явным offline/error status.
6. Добавить benchmark corpus: benign, malicious и borderline skills; измерять precision, recall и false-positive rate по платформам и категориям.
7. Добавить SARIF как производное представление того же report, не отдельную модель данных.

**Критерий готовности:** findings воспроизводимы, имеют доказательства и одинаково идентифицируются между повторными запусками.

### P2 — глубокие agent-specific проверки

1. Усилить Python AST/taint analysis и затем добавлять другие языки по данным benchmark, а не заранее.
2. Добавить опциональные YARA rules с versioned ruleset.
3. Расширить MCP-анализ: `allowed-tools`, malicious defaults/descriptions, Unicode deception, schema drift и повторный `tools/list` в изолированном режиме.
4. Реализовать version-diff findings для permissions, entrypoints, triggers, dependencies и MCP manifests. Хранение предыдущей версии остаётся обязанностью внешнего сервиса.
5. Разделить LLM на semantic discovery и evidence enrichment; использовать structured output и никогда не скрывать deterministic findings.
6. Добавить простой API/MCP endpoint `scan_skill`, возвращающий тот же JSON без собственного verdict.

**Критерий готовности:** analyzer покрывает угрозы, специфичные для skills и MCP, не меняя границу между detection и policy.

### P3 — дорогостоящие механизмы после P0–P2

1. Опциональный dynamic analyzer в disposable rootless sandbox: read-only input, fake credentials, default-deny egress и process/filesystem/network telemetry.
2. Формирование SBOM и проверка provenance/signatures; scanner сообщает факты подписи, но не решает, достаточно ли их для публикации.
3. Подписанная scan attestation, привязанная к `artifact_sha256`, scanner version и ruleset version.

Dynamic execution, dashboard, marketplace orchestration и policy packs не входят в ближайший core scope. Их следует добавлять только при появлении конкретного потребителя.

## План миграции

1. Зафиксировать JSON Schema и новые dataclasses тестами.
2. Перевести Pipeline и один встроенный analyzer на новый контракт как vertical slice.
3. Перевести остальные analyzers без изменения их detection logic.
4. Обновить все outputs как serializers единого `ScanReport`.
5. Удалить scorer и policy CLI после перевода тестов.
6. Затем выполнять hardening и platform work в порядке P0 → P1 → P2.

Не требуется переносить LangGraph или строить plugin framework заново. Текущего последовательного Pipeline и существующего `Analyzer` ABC достаточно; параллельность можно добавить позже стандартной библиотекой, если profiling покажет необходимость.
