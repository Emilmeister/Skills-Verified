
from skills_verified.repo.fetcher import fetch_repo


def test_fetch_local_path(tmp_path):
    test_file = tmp_path / "hello.py"
    test_file.write_text("print('hi')")
    result = fetch_repo(str(tmp_path))
    assert result == tmp_path
    assert (result / "hello.py").exists()


def test_fetch_local_path_nonexistent():
    import pytest
    with pytest.raises(ValueError, match="does not exist"):
        fetch_repo("/nonexistent/path/abc123")


def test_fetch_detects_url():
    from skills_verified.repo.fetcher import is_git_url
    assert is_git_url("https://github.com/user/repo") is True
    assert is_git_url("git@github.com:user/repo.git") is True
    assert is_git_url("/home/user/repo") is False
    assert is_git_url("./relative/path") is False
