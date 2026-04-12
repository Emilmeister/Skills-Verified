import json
from pathlib import Path


def read_config(path: str) -> dict:
    config_path = Path(path)
    with config_path.open() as f:
        return json.load(f)


def process_items(items: list[str]) -> list[str]:
    return [item.strip().lower() for item in items if item]


def calculate_score(values: list[int]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)
