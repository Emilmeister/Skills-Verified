from skills_verified.analyzers.aibom_analyzer import AibomAnalyzer
from skills_verified.core.models import Category, Severity


def test_detects_model_mcp_prompt_on_fake_repo(fake_repo_path):
    analyzer = AibomAnalyzer()
    findings = analyzer.analyze(fake_repo_path)
    inv = analyzer.last_inventory

    assert inv is not None
    assert len(inv.models) >= 1
    assert len(inv.mcp_servers) >= 1
    assert len(inv.system_prompts) >= 1

    titles = {f.title for f in findings}
    assert any(t.startswith("AI model reference:") for t in titles)
    assert any(t.startswith("MCP server:") for t in titles)
    assert any(t == "System prompt detected" for t in titles)
    for f in findings:
        assert f.category == Category.AI_BOM


def test_strict_mode_raises_shadow_findings_to_low(fake_repo_path):
    default = AibomAnalyzer(strict=False).analyze(fake_repo_path)
    strict = AibomAnalyzer(strict=True).analyze(fake_repo_path)

    default_low = sum(1 for f in default if f.severity == Severity.LOW)
    strict_low = sum(1 for f in strict if f.severity == Severity.LOW)
    assert strict_low >= default_low


def test_mcp_auth_detection(fake_repo_path):
    analyzer = AibomAnalyzer()
    analyzer.analyze(fake_repo_path)
    inv = analyzer.last_inventory
    by_name = {s.name: s for s in inv.mcp_servers}
    assert "github" in by_name
    assert by_name["github"].has_auth is True
    assert "filesystem" in by_name
    assert by_name["filesystem"].has_auth is False


def test_external_endpoint_detected(fake_repo_path):
    analyzer = AibomAnalyzer()
    analyzer.analyze(fake_repo_path)
    inv = analyzer.last_inventory
    endpoints = {e.endpoint for e in inv.endpoints}
    assert "api.openai.com" in endpoints


def test_embedding_model_detected(fake_repo_path):
    analyzer = AibomAnalyzer()
    analyzer.analyze(fake_repo_path)
    inv = analyzer.last_inventory
    emb_ids = {e.model_id for e in inv.embeddings}
    assert "text-embedding-3-small" in emb_ids


def test_empty_repo_returns_empty(tmp_path):
    analyzer = AibomAnalyzer()
    findings = analyzer.analyze(tmp_path)
    assert findings == []
    assert analyzer.last_inventory.models == []


def test_is_available():
    assert AibomAnalyzer().is_available() is True
