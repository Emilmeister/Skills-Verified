"""Local GenAI model risk registry — loads a curated YAML file and enriches
AI-BOM findings with behavioral risk metadata."""
import logging
from pathlib import Path

import yaml

from skills_verified.core.models import Finding, Severity

logger = logging.getLogger(__name__)

DEFAULT_REGISTRY = Path(__file__).resolve().parent.parent / "data" / "model_risk_registry.yaml"

_RISK_TO_SEVERITY = {
    "low": None,
    "medium": None,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": None,
}


class ModelRiskRegistry:
    def __init__(self, yaml_path: Path | None = None):
        path = yaml_path or DEFAULT_REGISTRY
        try:
            raw = yaml.safe_load(path.read_text())
        except (OSError, yaml.YAMLError) as e:
            logger.warning("could not load model risk registry: %s", e)
            raw = {"models": []}
        self._entries: list[dict] = raw.get("models", []) if isinstance(raw, dict) else []
        self._by_id: dict[str, dict] = {m["id"]: m for m in self._entries if "id" in m}

    def __len__(self) -> int:
        return len(self._entries)

    def lookup(self, model_id: str) -> dict | None:
        if model_id in self._by_id:
            return self._by_id[model_id]
        # Prefix-match: "gpt-4-0125-preview" → "gpt-4"
        for known_id in sorted(self._by_id, key=len, reverse=True):
            if model_id.startswith(known_id):
                return self._by_id[known_id]
        return None

    def enrich_findings(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            if f.title.startswith("AI model reference:"):
                model_id = f.title.split(":", 1)[1].strip()
            elif f.title.startswith("Embedding model reference:"):
                model_id = f.title.split(":", 1)[1].strip()
            else:
                continue
            entry = self.lookup(model_id)
            if entry is None:
                continue
            risk = entry.get("risk", {}) or {}
            overall = risk.get("overall", "unknown")
            boosted = _RISK_TO_SEVERITY.get(overall)
            if boosted is not None and _severity_rank(boosted) < _severity_rank(f.severity):
                f.severity = boosted
            owasp_lines = entry.get("owasp_llm_top10") or []
            if owasp_lines:
                f.description += f"\nRisk: {overall}; " + "; ".join(owasp_lines)
            else:
                f.description += f"\nRisk: {overall}"
        return findings


def _severity_rank(s: Severity) -> int:
    return {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}[s]
