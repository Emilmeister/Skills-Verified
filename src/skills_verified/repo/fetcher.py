import re
import tempfile
from pathlib import Path

import git


def is_git_url(source: str) -> bool:
    return bool(re.match(r"(https?://|git@)", source))


def fetch_repo(source: str, clone_dir: str | None = None, branch: str | None = None) -> Path:
    if is_git_url(source):
        target = Path(clone_dir) if clone_dir else Path(tempfile.mkdtemp(prefix="sv-"))
        kwargs: dict = {"depth": 1}
        if branch:
            kwargs["branch"] = branch
        git.Repo.clone_from(source, str(target), **kwargs)
        return target

    path = Path(source)
    if not path.exists():
        raise ValueError(f"Local path does not exist: {source}")
    return path
