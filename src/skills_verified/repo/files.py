import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path


DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "node_modules",
        "venv",
    }
)
DEFAULT_MAX_TOTAL_BYTES = 50 * 1024 * 1024


class UnsafeRepositoryPath(ValueError):
    """A repository path is not safe to read."""


class RepositoryLimitError(ValueError):
    """Repository inventory exceeded a configured resource limit."""


@dataclass(frozen=True)
class SkippedPath:
    path: str
    reason: str
    size_bytes: int | None = None
    target: str | None = None


@dataclass(frozen=True)
class FileInventory:
    root: Path
    files: tuple[Path, ...]
    skipped: tuple[SkippedPath, ...]
    total_bytes: int


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _classify_symlink(
    path: Path,
    root: Path,
    excluded_dirs: frozenset[str],
) -> SkippedPath:
    relative = _relative(path, root)
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return SkippedPath(relative, "symlink_unresolvable")
    try:
        target = resolved.relative_to(root)
    except ValueError:
        return SkippedPath(relative, "symlink_outside_repository")
    if any(part in excluded_dirs for part in target.parts):
        return SkippedPath(
            relative, "symlink_target_excluded", target=target.as_posix()
        )
    return SkippedPath(relative, "internal_symlink_alias", target=target.as_posix())


def collect_safe_files(
    root: Path,
    *,
    max_files: int = 10_000,
    max_file_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_duration_seconds: float = 10,
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS,
) -> FileInventory:
    """Build a deterministic inventory without following links or special files."""
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise UnsafeRepositoryPath(f"Repository root is not a directory: {root}")
    if min(max_files, max_file_bytes, max_total_bytes) < 1 or max_duration_seconds <= 0:
        raise ValueError("Repository limits must be positive")

    started = time.monotonic()
    files: list[Path] = []
    skipped: list[SkippedPath] = []
    total_bytes = 0

    def traversal_error(error: OSError) -> None:
        failed_path = Path(error.filename) if error.filename else root
        try:
            display_path = failed_path.relative_to(root).as_posix()
        except ValueError:
            display_path = failed_path.name or "."
        raise RepositoryLimitError(
            f"Repository traversal failed at {display_path}: {type(error).__name__}"
        ) from error

    for current, directory_names, file_names in os.walk(
        root,
        followlinks=False,
        onerror=traversal_error,
    ):
        if time.monotonic() - started > max_duration_seconds:
            raise RepositoryLimitError("Repository inventory exceeded its time limit")
        current_path = Path(current)
        kept_directories = []
        for name in sorted(directory_names):
            path = current_path / name
            relative = _relative(path, root)
            if name in excluded_dirs:
                skipped.append(SkippedPath(relative, "excluded_directory"))
            elif path.is_symlink():
                skipped.append(_classify_symlink(path, root, excluded_dirs))
            else:
                kept_directories.append(name)
        directory_names[:] = kept_directories

        for name in sorted(file_names):
            path = current_path / name
            relative = _relative(path, root)
            try:
                metadata = path.lstat()
            except OSError as exc:
                skipped.append(SkippedPath(relative, f"stat_error:{exc.errno}"))
                continue
            if stat.S_ISLNK(metadata.st_mode):
                skipped.append(_classify_symlink(path, root, excluded_dirs))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                skipped.append(SkippedPath(relative, "special_file"))
                continue
            try:
                resolved = path.resolve(strict=True)
            except OSError as exc:
                skipped.append(SkippedPath(relative, f"resolve_error:{exc.errno}"))
                continue
            try:
                resolved.relative_to(root)
            except ValueError:
                skipped.append(SkippedPath(relative, "outside_repository"))
                continue
            if metadata.st_size > max_file_bytes:
                skipped.append(
                    SkippedPath(relative, "file_too_large", metadata.st_size)
                )
                continue
            if len(files) >= max_files:
                raise RepositoryLimitError(f"Repository file count exceeds {max_files}")
            if total_bytes + metadata.st_size > max_total_bytes:
                raise RepositoryLimitError(
                    f"Repository total size exceeds {max_total_bytes} bytes"
                )
            files.append(resolved)
            total_bytes += metadata.st_size

    return FileInventory(root, tuple(files), tuple(skipped), total_bytes)


def safe_read_bytes(
    path: Path,
    root: Path,
    *,
    max_bytes: int = 2 * 1024 * 1024,
) -> bytes:
    """Read a contained regular file without following its final symlink."""
    root = Path(root).resolve(strict=True)
    path = Path(path)
    if not path.is_absolute():
        path = root / path
    try:
        path.parent.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise UnsafeRepositoryPath(f"Path is outside repository: {path}") from exc
    if path.is_symlink():
        raise UnsafeRepositoryPath(f"Refusing to read symlink: {path}")
    if not hasattr(os, "O_NOFOLLOW"):
        try:
            path.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as exc:
            raise UnsafeRepositoryPath(f"Path is outside repository: {path}") from exc

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise UnsafeRepositoryPath(
            f"Could not safely open repository file: {path}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsafeRepositoryPath(f"Repository path is not a regular file: {path}")
        if metadata.st_size > max_bytes:
            raise RepositoryLimitError(
                f"Repository file exceeds {max_bytes} bytes: {path}"
            )
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            content = stream.read(max_bytes + 1)
            if len(content) > max_bytes:
                raise RepositoryLimitError(
                    f"Repository file exceeds {max_bytes} bytes while reading: {path}"
                )
            return content
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def safe_read_text(
    path: Path,
    root: Path,
    *,
    max_bytes: int = 2 * 1024 * 1024,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> str:
    """Read and decode a contained regular file."""
    return safe_read_bytes(path, root, max_bytes=max_bytes).decode(
        encoding, errors=errors
    )
