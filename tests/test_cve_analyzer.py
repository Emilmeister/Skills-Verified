import json
from types import SimpleNamespace
from urllib.error import URLError

import pytest

import skills_verified.analyzers.cve_analyzer as cve_module
from skills_verified.analyzers.cve_analyzer import CveAnalyzer, CveLookupError
from skills_verified.core.models import Category, Severity


def test_name_and_availability():
    analyzer = CveAnalyzer()

    assert analyzer.name == "cve"
    assert analyzer.is_available() is True


def test_analyze_queries_osv_for_pinned_python_dependency(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask==2.0.0\nrequests>=2\n")
    analyzer = CveAnalyzer()
    queries = []

    def query_osv(dependencies):
        queries.extend(dependencies)
        return [
            {
                "vulns": [
                    {
                        "id": "PYSEC-2023-62",
                        "aliases": ["CVE-2023-30861"],
                        "summary": "Session cookie vulnerability",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [{"ranges": [{"events": [{"fixed": "2.3.2"}]}]}],
                        "references": [{"url": "https://osv.dev/PYSEC-2023-62"}],
                    }
                ]
            }
        ]

    monkeypatch.setattr(analyzer, "_query_osv", query_osv)

    findings = analyzer.analyze(tmp_path)

    assert [(dep.ecosystem, dep.name, dep.version) for dep in queries] == [
        ("PyPI", "flask", "2.0.0")
    ]
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2023-30861"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].category == Category.CVE
    assert findings[0].file_path == "requirements.txt"
    assert findings[0].rule_id == "SV-CVE-PYSEC-2023-62"
    assert findings[0].remediation == "Upgrade flask to 2.3.2 or later."
    assert findings[0].references == ["https://osv.dev/PYSEC-2023-62"]
    assert len(analyzer.diagnostics) == 1
    assert analyzer.diagnostics[0].code == "unpinned_dependency"
    assert analyzer.diagnostics[0].message == "Skipped unpinned dependency: requests>=2"
    assert analyzer.diagnostics[0].path == "requirements.txt"


def test_analyze_parses_pyproject_and_pipfile_pins(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["Django==4.2.1", "click>=8"]\n'
    )
    (tmp_path / "Pipfile").write_text('[packages]\nflask = "==2.0.0"\nrequests = "*"\n')
    analyzer = CveAnalyzer()
    seen = []
    monkeypatch.setattr(
        analyzer,
        "_query_osv",
        lambda dependencies: seen.extend(dependencies) or [{} for _ in dependencies],
    )

    assert analyzer.analyze(tmp_path) == []
    assert {(dep.name, dep.version) for dep in seen} == {
        ("django", "4.2.1"),
        ("flask", "2.0.0"),
    }


def test_analyze_reuses_central_inventory(tmp_path, monkeypatch):
    requirement = tmp_path / "requirements.txt"
    requirement.write_text("demo==1.0\n")
    analyzer = CveAnalyzer()
    monkeypatch.setattr(
        cve_module,
        "collect_safe_files",
        lambda _path: pytest.fail("must not rebuild inventory"),
    )
    monkeypatch.setattr(analyzer, "_query_osv", lambda _dependencies: [{}])

    assert (
        analyzer.analyze(tmp_path, context=SimpleNamespace(files=[requirement])) == []
    )


def test_requirement_include_is_explicitly_unsupported(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r dependencies.txt\n")
    (tmp_path / "dependencies.txt").write_text("flask==2.0.0\n")
    analyzer = CveAnalyzer()

    assert analyzer.analyze(tmp_path) == []
    assert analyzer.diagnostics[0].code == "unsupported_requirement"


def test_analyze_queries_osv_for_package_lock_dependencies(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "version": "1.0.0"},
                    "node_modules/lodash": {"version": "4.17.20"},
                    "node_modules/@scope/pkg": {"version": "1.2.3"},
                },
            }
        )
    )
    analyzer = CveAnalyzer()
    seen = []
    monkeypatch.setattr(
        analyzer,
        "_query_osv",
        lambda dependencies: seen.extend(dependencies) or [{} for _ in dependencies],
    )

    assert analyzer.analyze(tmp_path) == []
    assert {(dep.name, dep.version) for dep in seen} == {
        ("lodash", "4.17.20"),
        ("@scope/pkg", "1.2.3"),
    }


def test_analyze_queries_osv_for_bun_lock_dependencies(tmp_path, monkeypatch):
    (tmp_path / "bun.lock").write_text(
        "{\n"
        '  "lockfileVersion": 1,\n'
        '  "packages": {\n'
        '    "lodash": ["lodash@4.17.20", "", {}, "sha512-demo"],\n'
        '    "nested": ["@scope/pkg@1.2.3", "", {}],\n'
        '    "workspace": ["@demo/local@workspace:packages/local", ""],\n'
        "  },\n"
        "}\n"
    )
    analyzer = CveAnalyzer()
    seen = []
    monkeypatch.setattr(
        analyzer,
        "_query_osv",
        lambda dependencies: seen.extend(dependencies) or [{} for _ in dependencies],
    )

    assert analyzer.analyze(tmp_path) == []
    assert {(dep.name, dep.version) for dep in seen} == {
        ("lodash", "4.17.20"),
        ("@scope/pkg", "1.2.3"),
    }
    assert {dep.ecosystem for dep in seen} == {"npm"}


def test_osv_request_uses_static_package_coordinates(monkeypatch):
    captured = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _size):
            return b'{"results":[{}]}'

    def open_request(request, timeout, context):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data)
        captured["timeout"] = timeout
        assert context.verify_mode.name == "CERT_REQUIRED"
        return Response()

    monkeypatch.setattr("skills_verified.analyzers.cve_analyzer.urlopen", open_request)
    analyzer = CveAnalyzer(timeout=4)
    dependencies = analyzer._parse_requirement_lines(
        ["flask==2.0.0"], "requirements.txt"
    )

    assert analyzer._query_osv(dependencies) == [{}]
    assert captured == {
        "url": "https://api.osv.dev/v1/querybatch",
        "body": {
            "queries": [
                {
                    "package": {"ecosystem": "PyPI", "name": "flask"},
                    "version": "2.0.0",
                }
            ]
        },
        "timeout": 4,
    }


def test_osv_results_are_cached_by_package_coordinate(monkeypatch):
    calls = 0

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _size):
            return b'{"results":[{}]}'

    def open_request(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return Response()

    monkeypatch.setattr("skills_verified.analyzers.cve_analyzer.urlopen", open_request)
    analyzer = CveAnalyzer()
    dependencies = analyzer._parse_requirement_lines(
        ["flask==2.0.0"], "requirements.txt"
    )

    assert analyzer._query_osv(dependencies) == [{}]
    assert analyzer._query_osv(dependencies) == [{}]
    assert calls == 1


def test_batch_ids_are_enriched(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("demo==1.0\n")
    analyzer = CveAnalyzer()
    monkeypatch.setattr(
        analyzer,
        "_query_osv",
        lambda _dependencies: [
            {"vulns": [{"id": "GHSA-demo", "modified": "2026-01-01T00:00:00Z"}]}
        ],
    )
    calls = 0

    def get_vulnerability(vulnerability_id):
        nonlocal calls
        calls += 1
        assert vulnerability_id == "GHSA-demo"
        return {
            "id": vulnerability_id,
            "aliases": ["CVE-2026-1234"],
            "summary": "Enriched advisory",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"ranges": [{"events": [{"fixed": "1.1"}]}]}],
            "references": [{"url": "https://osv.dev/vulnerability/GHSA-demo"}],
        }

    monkeypatch.setattr(analyzer, "_get_vulnerability", get_vulnerability)

    findings = analyzer.analyze(tmp_path)

    assert findings[0].cve_id == "CVE-2026-1234"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].remediation == "Upgrade demo to 1.1 or later."
    assert findings[0].description == "Enriched advisory"
    assert calls == 1


def test_osv_vulnerability_details_are_cached(monkeypatch):
    calls = 0

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _size):
            return b'{"id":"GHSA-demo","summary":"details"}'

    def open_request(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return Response()

    monkeypatch.setattr("skills_verified.analyzers.cve_analyzer.urlopen", open_request)
    analyzer = CveAnalyzer()

    assert analyzer._get_vulnerability("GHSA-demo")["summary"] == "details"
    assert analyzer._get_vulnerability("GHSA-demo")["summary"] == "details"
    assert calls == 1


def test_dependency_collection_has_a_hard_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(cve_module, "_MAX_DEPENDENCIES", 2)
    (tmp_path / "requirements.txt").write_text(
        "one==1\ntwo==2\nthree==3\n",
        encoding="utf-8",
    )
    analyzer = CveAnalyzer()

    dependencies = analyzer._collect_dependencies(tmp_path)

    assert [(item.name, item.version) for item in dependencies] == [
        ("one", "1"),
        ("two", "2"),
    ]
    assert analyzer.diagnostics[-1].code == "dependency_limit_exceeded"


def test_manifest_records_and_repetitive_diagnostics_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(cve_module, "_MAX_MANIFEST_RECORDS", 10)
    monkeypatch.setattr(cve_module, "_MAX_DIAGNOSTICS_PER_CODE", 2)
    (tmp_path / "requirements.txt").write_text(
        "".join(f"unpinned-{index}\n" for index in range(100_000)),
        encoding="utf-8",
    )
    analyzer = CveAnalyzer()

    assert analyzer._collect_dependencies(tmp_path) == []

    codes = [item.code for item in analyzer.diagnostics]
    assert codes == [
        "unpinned_dependency",
        "unpinned_dependency",
        "diagnostics_suppressed",
        "manifest_record_limit_exceeded",
    ]
    assert analyzer.diagnostics[2].details == {
        "diagnostic_code": "unpinned_dependency",
        "suppressed_count": 8,
    }


def test_requirement_parser_stops_consuming_at_manifest_record_limit(monkeypatch):
    monkeypatch.setattr(cve_module, "_MAX_MANIFEST_RECORDS", 3)
    consumed = []

    def lines():
        for index in range(100):
            consumed.append(index)
            yield f"package-{index}==1\n"

    analyzer = CveAnalyzer()
    dependencies = analyzer._parse_requirement_lines(lines(), "requirements.txt")

    assert len(dependencies) == 3
    assert consumed == [0, 1, 2, 3]
    assert analyzer.diagnostics[-1].code == "manifest_record_limit_exceeded"


def test_diagnostic_message_is_bounded(monkeypatch):
    monkeypatch.setattr(cve_module, "_MAX_DIAGNOSTIC_MESSAGE_CHARS", 50)
    analyzer = CveAnalyzer()

    analyzer._parse_requirement_lines(["x" * 10_000], "requirements.txt")

    assert len(analyzer.diagnostics[0].message) == 50
    assert analyzer.diagnostics[0].message.endswith("…")


def test_osv_detail_enrichment_covers_every_summary(monkeypatch):
    analyzer = CveAnalyzer()
    seen = []

    def get_vulnerability(vulnerability_id):
        seen.append(vulnerability_id)
        return {"id": vulnerability_id, "summary": "enriched"}

    monkeypatch.setattr(analyzer, "_get_vulnerability", get_vulnerability)

    results = analyzer._enrich_results(
        [
            {
                "vulns": [
                    {"id": "GHSA-one", "modified": "2026-01-01T00:00:00Z"},
                    {"id": "GHSA-two", "modified": "2026-01-01T00:00:00Z"},
                ]
            }
        ]
    )

    assert sorted(seen) == ["GHSA-one", "GHSA-two"]
    assert results[0]["vulns"][0]["summary"] == "enriched"
    assert results[0]["vulns"][1]["summary"] == "enriched"
    assert not any(
        diagnostic.code == "osv_detail_limit_exceeded"
        for diagnostic in analyzer.diagnostics
    )


def test_osv_caches_are_reset_between_scans(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("demo==1.0\n")
    calls = 0

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _size):
            nonlocal calls
            calls += 1
            if calls == 1:
                return b'{"results":[{}]}'
            return (
                b'{"results":[{"vulns":[{"id":"CVE-2026-0001",'
                b'"summary":"new advisory"}]}]}'
            )

    monkeypatch.setattr(cve_module, "urlopen", lambda *_args, **_kwargs: Response())
    analyzer = CveAnalyzer()

    assert analyzer.analyze(tmp_path) == []
    assert [item.cve_id for item in analyzer.analyze(tmp_path)] == ["CVE-2026-0001"]
    assert calls == 2


def test_osv_network_error_is_not_silently_clean(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
    monkeypatch.setattr(
        "skills_verified.analyzers.cve_analyzer.urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(URLError("offline")),
    )
    analyzer = CveAnalyzer()

    with pytest.raises(CveLookupError, match="OSV query failed"):
        analyzer.analyze(tmp_path)

    assert analyzer.diagnostics[-1].code == "osv_lookup_failed"


def test_invalid_manifest_is_reported_as_diagnostic(tmp_path):
    (tmp_path / "package-lock.json").write_text("not json")
    analyzer = CveAnalyzer()

    assert analyzer.analyze(tmp_path) == []
    assert analyzer.diagnostics[0].code == "manifest_parse_error"


def test_vulnerability_without_severity_does_not_invent_high_risk(
    tmp_path, monkeypatch
):
    (tmp_path / "requirements.txt").write_text("demo==1.0\n")
    analyzer = CveAnalyzer()
    monkeypatch.setattr(
        analyzer,
        "_query_osv",
        lambda _dependencies: [
            {"vulns": [{"id": "GHSA-test", "summary": "Known vulnerability"}]}
        ],
    )

    findings = analyzer.analyze(tmp_path)

    assert findings[0].severity == Severity.UNKNOWN
    assert "Severity: not provided by OSV" in findings[0].description


def test_deduplicates_osv_alias_records_for_the_same_cve(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("demo==1.0\n")
    analyzer = CveAnalyzer()
    monkeypatch.setattr(
        analyzer,
        "_query_osv",
        lambda _dependencies: [
            {
                "vulns": [
                    {
                        "id": "GHSA-demo",
                        "aliases": ["CVE-2026-1234"],
                        "summary": "Detailed advisory",
                        "database_specific": {"severity": "HIGH"},
                        "references": [{"url": "https://osv.dev/GHSA-demo"}],
                    },
                    {
                        "id": "PYSEC-demo",
                        "aliases": ["CVE-2026-1234"],
                        "summary": "Alias advisory",
                        "references": [{"url": "https://osv.dev/PYSEC-demo"}],
                    },
                ]
            }
        ],
    )

    findings = analyzer.analyze(tmp_path)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].cve_id == "CVE-2026-1234"
    assert findings[0].references == [
        "https://osv.dev/GHSA-demo",
        "https://osv.dev/PYSEC-demo",
    ]


def test_osv_response_length_mismatch_is_an_error(monkeypatch):
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _size):
            return b'{"results":[]}'

    monkeypatch.setattr(
        "skills_verified.analyzers.cve_analyzer.urlopen",
        lambda *_args, **_kwargs: Response(),
    )
    analyzer = CveAnalyzer()
    dependencies = analyzer._parse_requirement_lines(["demo==1.0"], "requirements.txt")

    with pytest.raises(CveLookupError, match="result count"):
        analyzer._query_osv(dependencies)
