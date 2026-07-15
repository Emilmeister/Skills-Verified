from importlib import resources
from pathlib import Path

import yaml


_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_SOURCE_RULES = _PROJECT_ROOT / "data"


class SignatureLoadError(RuntimeError):
    """A required signature database could not be loaded."""


class SignatureLoader:
    def __init__(self, data_dir: Path | None = None):
        if data_dir is not None:
            self.data_dir = Path(data_dir)
            return
        packaged_rules = resources.files("skills_verified.data").joinpath("rules")
        self.data_dir = packaged_rules if packaged_rules.is_dir() else _SOURCE_RULES

    def load(self, filename: str) -> dict:
        if not filename or filename != Path(filename).name or "\\" in filename:
            raise SignatureLoadError("Signature resource must be a plain filename")
        path = self.data_dir.joinpath(filename)
        if not path.is_file():
            raise SignatureLoadError(f"Signature file not found: {filename}")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise SignatureLoadError(
                f"Failed to parse signature file: {filename}"
            ) from exc
        if not isinstance(data, dict):
            raise SignatureLoadError(
                f"Signature file must contain a mapping: {filename}"
            )
        return data

    def _load_list(self, filename: str, key: str) -> list[dict]:
        data = self.load(filename)
        if key not in data:
            raise SignatureLoadError(
                f"Signature file is missing required key '{key}': {filename}"
            )
        value = data[key]
        if not isinstance(value, list) or not all(
            isinstance(item, dict) for item in value
        ):
            raise SignatureLoadError(
                f"Signature key '{key}' must contain a list of mappings: {filename}"
            )
        return value

    def load_signatures(self, filename: str) -> list[dict]:
        return self._load_list(filename, "signatures")

    def load_authors(self, filename: str) -> list[dict]:
        return self._load_list(filename, "authors")

    def load_hashes(self, filename: str) -> list[dict]:
        return self._load_list(filename, "hashes")

    def load_campaigns(self, filename: str) -> list[dict]:
        return self._load_list(filename, "campaigns")
