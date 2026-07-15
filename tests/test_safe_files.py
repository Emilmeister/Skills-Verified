import os

import pytest

from skills_verified.repo.files import (
    RepositoryLimitError,
    UnsafeRepositoryPath,
    collect_safe_files,
    safe_read_bytes,
    safe_read_text,
)


def test_collect_safe_files_excludes_generated_directories_and_symlinks(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "SKILL.md").write_text("safe")
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("secret")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "dependency.js").write_text("ignored")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    (root / "escape.txt").symlink_to(outside)

    inventory = collect_safe_files(root)

    assert inventory.files == ((root / "SKILL.md").resolve(),)
    reasons = {item.path: item.reason for item in inventory.skipped}
    assert reasons[".git"] == "excluded_directory"
    assert reasons["node_modules"] == "excluded_directory"
    assert reasons["escape.txt"] == "symlink_outside_repository"


def test_collect_safe_files_records_internal_symlink_alias_without_duplicate_content(
    tmp_path,
):
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "shared.txt"
    target.write_text("shared")
    (root / "alias.txt").symlink_to("shared.txt")

    inventory = collect_safe_files(root)

    assert inventory.files == (target.resolve(),)
    alias = next(item for item in inventory.skipped if item.path == "alias.txt")
    assert alias.reason == "internal_symlink_alias"
    assert alias.target == "shared.txt"


def test_collect_safe_files_skips_oversized_file(tmp_path):
    (tmp_path / "small.txt").write_text("small")
    (tmp_path / "large.txt").write_text("x" * 20)

    inventory = collect_safe_files(tmp_path, max_file_bytes=10)

    assert inventory.files == ((tmp_path / "small.txt").resolve(),)
    assert inventory.skipped[-1].reason == "file_too_large"


def test_collect_safe_files_enforces_file_and_total_limits(tmp_path):
    (tmp_path / "a.txt").write_text("1234")
    (tmp_path / "b.txt").write_text("5678")

    with pytest.raises(RepositoryLimitError, match="file count"):
        collect_safe_files(tmp_path, max_files=1)
    with pytest.raises(RepositoryLimitError, match="total size"):
        collect_safe_files(tmp_path, max_total_bytes=7)


def test_collect_safe_files_does_not_silently_ignore_traversal_errors(
    tmp_path, monkeypatch
):
    def failed_walk(root, *, followlinks, onerror):
        assert followlinks is False
        onerror(PermissionError(13, "denied", str(root / "private")))
        return iter(())

    monkeypatch.setattr(os, "walk", failed_walk)

    with pytest.raises(RepositoryLimitError, match="traversal failed at private"):
        collect_safe_files(tmp_path)


def test_safe_read_text_rejects_symlink(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    link = root / "link.txt"
    link.symlink_to(outside)

    with pytest.raises(UnsafeRepositoryPath, match="symlink"):
        safe_read_text(link, root)


def test_safe_read_text_reads_regular_file(tmp_path):
    path = tmp_path / "file.txt"
    path.write_text("hello")

    assert safe_read_text(path, tmp_path) == "hello"


def test_safe_read_bytes_reads_binary_file(tmp_path):
    path = tmp_path / "file.bin"
    path.write_bytes(b"\x00\xff")

    assert safe_read_bytes(path, tmp_path) == b"\x00\xff"


def test_safe_read_bytes_enforces_read_limit(tmp_path):
    path = tmp_path / "file.bin"
    path.write_bytes(b"1234")

    with pytest.raises(RepositoryLimitError, match="exceeds 3 bytes"):
        safe_read_bytes(path, tmp_path, max_bytes=3)


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="platform lacks O_NOFOLLOW")
def test_safe_read_text_does_not_follow_replaced_final_component(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    link = root / "link.txt"
    link.symlink_to(outside)

    with pytest.raises(UnsafeRepositoryPath):
        safe_read_text(link, root)
