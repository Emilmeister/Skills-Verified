import json
import uuid
from pathlib import Path

from skills_verified.analyzers.aibom_analyzer import AibomInventory

CYCLONEDX_SPEC_VERSION = "1.6"


def inventory_to_cyclonedx(inventory: AibomInventory, repo_name: str = "repo") -> dict:
    """Serialize an AibomInventory to a CycloneDX 1.6 BOM dict."""
    components: list[dict] = []
    services: list[dict] = []

    for model in inventory.models + inventory.embeddings:
        bom_ref = f"ai-model/{model.provider}/{model.model_id}"
        components.append({
            "type": "machine-learning-model",
            "bom-ref": bom_ref,
            "name": model.model_id,
            "supplier": {"name": model.provider},
            "properties": [
                {"name": "sv:provider", "value": model.provider},
                {"name": "sv:pinned_version", "value": str(model.pinned_version)},
            ],
            "evidence": {
                "occurrences": [
                    {"location": f"{f}:{ln}"} for f, ln in model.occurrences
                ],
            },
        })

    for server in inventory.mcp_servers:
        services.append({
            "bom-ref": f"mcp-server/{server.name}",
            "name": server.name,
            "provider": {"name": "mcp"},
            "endpoints": [server.command] if server.command else [],
            "authenticated": server.has_auth,
            "properties": [
                {"name": "sv:source_file", "value": server.source_file},
                {"name": "sv:args", "value": " ".join(server.args)},
                {"name": "sv:env_keys", "value": ",".join(server.env_keys)},
            ],
        })

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": repo_name,
                "bom-ref": f"application/{repo_name}",
            },
            "properties": [
                {"name": "sv:system_prompts", "value": str(len(inventory.system_prompts))},
                {"name": "sv:external_endpoints", "value": str(len(inventory.endpoints))},
            ],
        },
        "components": components,
        "services": services,
    }
    return bom


def save_aibom(inventory: AibomInventory, path: Path, repo_name: str = "repo") -> None:
    bom = inventory_to_cyclonedx(inventory, repo_name=repo_name)
    path.write_text(json.dumps(bom, indent=2))
