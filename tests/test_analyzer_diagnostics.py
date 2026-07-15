from pathlib import Path

import pytest

from skills_verified.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skills_verified.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from skills_verified.analyzers.guardrails_analyzer import GuardrailsAnalyzer
from skills_verified.analyzers.known_threats_analyzer import KnownThreatsAnalyzer
from skills_verified.analyzers.metadata_analyzer import MetadataAnalyzer
from skills_verified.analyzers.obfuscation_analyzer import ObfuscationAnalyzer
from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.analyzers.permissions_analyzer import PermissionsAnalyzer
from skills_verified.analyzers.reverse_shell_analyzer import ReverseShellAnalyzer
from skills_verified.analyzers.supply_chain_analyzer import SupplyChainAnalyzer


@pytest.mark.parametrize(
    ("analyzer_type", "filename"),
    [
        (BehavioralAnalyzer, "probe.py"),
        (ExfiltrationAnalyzer, "probe.py"),
        (GuardrailsAnalyzer, "probe.py"),
        (KnownThreatsAnalyzer, "probe.py"),
        (ObfuscationAnalyzer, "probe.py"),
        (PatternAnalyzer, "probe.py"),
        (PermissionsAnalyzer, "probe.py"),
        (ReverseShellAnalyzer, "probe.py"),
        (SupplyChainAnalyzer, "package.json"),
    ],
)
def test_target_read_failure_is_diagnostic_and_resets(
    analyzer_type, filename, monkeypatch, tmp_path
):
    target = tmp_path / filename
    target.write_text("pass\n")
    analyzer = analyzer_type()
    original_read_text = Path.read_text

    def failing_read_text(path, *args, **kwargs):
        if path == target:
            raise OSError("denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", failing_read_text)

    assert analyzer.analyze(tmp_path) == []
    assert len(analyzer.diagnostics) == 1
    assert analyzer.diagnostics[0].code.endswith("read_error")
    assert analyzer.diagnostics[0].analyzer == analyzer.name
    assert analyzer.diagnostics[0].path == filename

    target.unlink()
    assert analyzer.analyze(tmp_path) == []
    assert analyzer.diagnostics == []


def test_non_target_read_failure_does_not_emit_diagnostic(monkeypatch, tmp_path):
    target = tmp_path / "asset.png"
    target.write_bytes(b"not source")
    analyzer = PatternAnalyzer()

    def failing_read_text(path, *args, **kwargs):
        if path == target:
            raise AssertionError("non-target file should not be read")
        return ""

    monkeypatch.setattr(Path, "read_text", failing_read_text)

    assert analyzer.analyze(tmp_path) == []
    assert analyzer.diagnostics == []


def test_metadata_documentation_read_failure_is_diagnostic(monkeypatch, tmp_path):
    target = tmp_path / "README.md"
    target.write_text("# README\n")
    analyzer = MetadataAnalyzer()
    original_read_text = Path.read_text

    class EmptyProfile:
        @staticmethod
        def get_skill_metadata(repo_path):
            return None

    def failing_read_text(path, *args, **kwargs):
        if path == target:
            raise OSError("denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", failing_read_text)

    assert analyzer.analyze(tmp_path, platforms=[EmptyProfile()]) == []
    assert analyzer.diagnostics[0].code == "documentation_read_error"
    assert analyzer.diagnostics[0].path == "README.md"
