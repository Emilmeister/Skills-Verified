from pathlib import Path

import pytest


@pytest.fixture
def fake_repo_path() -> Path:
    return Path(__file__).parent / "fixtures" / "fake_repo"
