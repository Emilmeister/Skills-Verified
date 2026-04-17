from skills_verified.analyzers.aibom_analyzer import AibomAnalyzer
from skills_verified.analyzers.model_risk import ModelRiskRegistry
from skills_verified.core.models import Category, Finding, Severity


def test_registry_loads_with_minimum_entries():
    registry = ModelRiskRegistry()
    assert len(registry) >= 15


def test_registry_exact_lookup():
    registry = ModelRiskRegistry()
    entry = registry.lookup("gpt-4o")
    assert entry is not None
    assert entry["provider"] == "openai"


def test_registry_prefix_match():
    registry = ModelRiskRegistry()
    entry = registry.lookup("gpt-4-0125-preview")
    assert entry is not None
    assert entry["id"] == "gpt-4"


def test_registry_unknown_model_returns_none():
    registry = ModelRiskRegistry()
    assert registry.lookup("nobody/made-this-up") is None


def _mk_ai_finding(model_id: str) -> Finding:
    return Finding(
        title=f"AI model reference: {model_id}",
        description="Initial.",
        severity=Severity.INFO,
        category=Category.AI_BOM,
        file_path="x.py",
        line_number=1,
        analyzer="aibom",
    )


def test_enrich_raises_severity_for_critical_risk():
    registry = ModelRiskRegistry()
    finding = _mk_ai_finding("mistralai/Mistral-7B-Instruct-v0.2")
    registry.enrich_findings([finding])
    assert finding.severity == Severity.CRITICAL
    assert "critical" in finding.description.lower()


def test_enrich_raises_severity_for_high_risk():
    registry = ModelRiskRegistry()
    finding = _mk_ai_finding("meta-llama/Llama-3.1-70B")
    registry.enrich_findings([finding])
    assert finding.severity == Severity.HIGH


def test_enrich_low_risk_keeps_severity():
    registry = ModelRiskRegistry()
    finding = _mk_ai_finding("claude-3-5-sonnet")
    registry.enrich_findings([finding])
    assert finding.severity == Severity.INFO  # not raised for low risk


def test_enrich_unknown_model_no_change():
    registry = ModelRiskRegistry()
    finding = _mk_ai_finding("totally-unknown-model-xyz")
    registry.enrich_findings([finding])
    assert finding.severity == Severity.INFO
    assert finding.description == "Initial."


def test_aibom_with_registry_enriches(tmp_path):
    (tmp_path / "app.py").write_text("model = 'gpt-4'\n")
    analyzer = AibomAnalyzer(risk_registry=ModelRiskRegistry())
    findings = analyzer.analyze(tmp_path)
    model_finding = next(
        (f for f in findings if f.title == "AI model reference: gpt-4"),
        None,
    )
    assert model_finding is not None
    assert "Risk:" in model_finding.description
