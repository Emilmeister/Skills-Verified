from skills_verified.analyzers.supply_chain_analyzer import (
    SupplyChainAnalyzer,
    _bounded_edit_distance,
)
from skills_verified.core.models import (
    AnalyzerRunStatus,
    Category,
    ScanStatus,
    Severity,
)
from skills_verified.core.pipeline import Pipeline


def test_is_available():
    analyzer = SupplyChainAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "supply_chain"


def test_finds_suspicious_postinstall(fake_repo_path):
    analyzer = SupplyChainAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    install_findings = [
        f
        for f in findings
        if "postinstall" in f.title.lower() or "install script" in f.title.lower()
    ]
    assert len(install_findings) >= 1
    assert install_findings[0].severity in (Severity.CRITICAL, Severity.HIGH)


def test_finds_typosquatting(fake_repo_path):
    analyzer = SupplyChainAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    typo_findings = [f for f in findings if "typosquat" in f.title.lower()]
    assert len(typo_findings) >= 1


def test_finds_setup_py_os_system(fake_repo_path):
    analyzer = SupplyChainAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    setup_findings = [f for f in findings if "setup.py" in (f.file_path or "")]
    assert len(setup_findings) >= 1


def test_no_findings_on_clean_package(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "clean", "dependencies": {"lodash": "4.17.21"}}')
    analyzer = SupplyChainAnalyzer()
    findings = analyzer.analyze(tmp_path)
    assert findings == []


def test_all_findings_are_supply_chain(fake_repo_path):
    analyzer = SupplyChainAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    for f in findings:
        assert f.category == Category.SUPPLY_CHAIN


def test_invalid_package_json_reports_diagnostic_and_resets(tmp_path):
    package = tmp_path / "package.json"
    package.write_text('{"scripts": ')
    analyzer = SupplyChainAnalyzer()

    assert analyzer.analyze(tmp_path) == []
    assert len(analyzer.diagnostics) == 1
    assert analyzer.diagnostics[0].code == "package_json_parse_error"
    assert analyzer.diagnostics[0].analyzer == "supply_chain"
    assert analyzer.diagnostics[0].path == "package.json"

    package.write_text('{"name": "valid"}')
    assert analyzer.analyze(tmp_path) == []
    assert analyzer.diagnostics == []


def test_invalid_package_json_marks_pipeline_partial(tmp_path):
    (tmp_path / "package.json").write_text("not-json")

    report = Pipeline([SupplyChainAnalyzer()]).run(tmp_path, repo_url="test")

    assert report.scan.status == ScanStatus.PARTIAL
    assert report.analyzer_runs[0].status == AnalyzerRunStatus.PARTIAL
    assert report.analyzer_runs[0].reason == "analyzer_reported_diagnostics"
    assert report.diagnostics[0].code == "package_json_parse_error"


def test_bounded_edit_distance_matches_typosquat_cutoff():
    assert _bounded_edit_distance("requests", "requests") == 0
    assert _bounded_edit_distance("requsets", "requests") == 2
    assert _bounded_edit_distance("requestzz", "requests") == 2
    assert _bounded_edit_distance("unrelated", "requests") == 3


def test_short_established_package_names_are_not_typosquats(tmp_path):
    package = tmp_path / "package.json"
    package.write_text('{"dependencies": {"vite": "1", "acorn": "1", "recast": "1"}}')

    assert SupplyChainAnalyzer().analyze(tmp_path) == []
