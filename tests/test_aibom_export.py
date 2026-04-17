import json
from pathlib import Path

from skills_verified.analyzers.aibom_analyzer import AibomAnalyzer
from skills_verified.output.aibom_export import (
    inventory_to_cyclonedx,
    save_aibom,
)


def test_cyclonedx_core_fields(fake_repo_path):
    analyzer = AibomAnalyzer()
    analyzer.analyze(fake_repo_path)
    bom = inventory_to_cyclonedx(analyzer.last_inventory, repo_name="fake_repo")

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["version"] == 1
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert isinstance(bom["components"], list)
    assert isinstance(bom["services"], list)
    assert bom["metadata"]["component"]["name"] == "fake_repo"


def test_cyclonedx_contains_models_and_mcp(fake_repo_path):
    analyzer = AibomAnalyzer()
    analyzer.analyze(fake_repo_path)
    bom = inventory_to_cyclonedx(analyzer.last_inventory)

    # At least one ML model component
    ml_components = [c for c in bom["components"] if c["type"] == "machine-learning-model"]
    assert len(ml_components) >= 1
    assert ml_components[0]["bom-ref"].startswith("ai-model/")

    # MCP servers exported as services
    mcp_services = [s for s in bom["services"] if s["bom-ref"].startswith("mcp-server/")]
    assert len(mcp_services) >= 1
    github = next((s for s in mcp_services if s["name"] == "github"), None)
    assert github is not None
    assert github["authenticated"] is True


def test_save_aibom_writes_valid_json(fake_repo_path, tmp_path: Path):
    analyzer = AibomAnalyzer()
    analyzer.analyze(fake_repo_path)
    out = tmp_path / "bom.json"
    save_aibom(analyzer.last_inventory, out, repo_name="fake_repo")
    assert out.is_file()
    data = json.loads(out.read_text())
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.6"


def test_cyclonedx_on_empty_inventory():
    from skills_verified.analyzers.aibom_analyzer import AibomInventory
    bom = inventory_to_cyclonedx(AibomInventory(), repo_name="r")
    assert bom["components"] == []
    assert bom["services"] == []
