
from skills_verified.analyzers.supply_chain_analyzer import SupplyChainAnalyzer
from skills_verified.core.models import Category, Severity


def test_is_available():
    analyzer = SupplyChainAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "supply_chain"


def test_finds_suspicious_postinstall(fake_repo_path):
    analyzer = SupplyChainAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    install_findings = [f for f in findings if "postinstall" in f.title.lower() or "install script" in f.title.lower()]
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
