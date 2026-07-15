import atexit
import ipaddress
import json
import math
import os
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Collection, Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit


_SCP_GIT_URL = re.compile(r"^(?P<user>[A-Za-z0-9_.-]+)@(?P<host>[^:/]+):(?P<path>.+)$")
_DNS_NAME = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)
_SSH_REPOSITORY_PATH = re.compile(r"/?[A-Za-z0-9._~/-]+\Z")
DEFAULT_MAX_CLONE_BYTES = 128 * 1024 * 1024
DEFAULT_CLONE_TIMEOUT_SECONDS = 120.0
_CLONE_POLL_INTERVAL_SECONDS = 0.25
_MIN_ENTRY_DISK_BYTES = 4096
_FALLBACK_ENTRY_DISK_BYTES = 64 * 1024


class RepoFetchError(RuntimeError):
    """A remote repository could not be acquired safely."""


def is_git_url(source: str) -> bool:
    return source.lower().startswith(("http://", "https://", "ssh://")) or bool(
        _SCP_GIT_URL.fullmatch(source)
    )


def _remote_host(source: str) -> tuple[str, int | None]:
    scp_match = _SCP_GIT_URL.fullmatch(source)
    if scp_match:
        if not _SSH_REPOSITORY_PATH.fullmatch(scp_match.group("path")):
            raise ValueError("SSH repository path contains unsafe characters")
        host = scp_match.group("host")
        if not _valid_host_syntax(host):
            raise ValueError("Repository URL contains an invalid hostname")
        return host, 22

    parsed = urlsplit(source)
    if parsed.scheme not in {"https", "ssh"}:
        raise ValueError("Remote repositories must use HTTPS or SSH")
    if not parsed.hostname or not parsed.path:
        raise ValueError("Remote repository URL must include a host and path")
    if parsed.password or (parsed.username and parsed.scheme == "https"):
        raise ValueError("Credentials must not be embedded in repository URLs")
    if parsed.query or parsed.fragment:
        raise ValueError("Repository URLs must not contain query strings or fragments")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Repository URL contains an invalid port") from exc
    if port is not None and port == 0:
        raise ValueError("Repository URL contains an invalid port")
    if not _valid_host_syntax(parsed.hostname):
        raise ValueError("Repository URL contains an invalid hostname")
    if parsed.scheme == "ssh" and not _SSH_REPOSITORY_PATH.fullmatch(parsed.path):
        raise ValueError("SSH repository path contains unsafe characters")
    return parsed.hostname, port or (443 if parsed.scheme == "https" else 22)


def _valid_host_syntax(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        try:
            ascii_host = host.rstrip(".").encode("idna").decode("ascii")
        except UnicodeError:
            return False
        return bool(_DNS_NAME.fullmatch(ascii_host))


def _validate_remote(
    source: str,
    *,
    allow_ssh: bool,
    allow_private_hosts: bool,
    allowed_hosts: Collection[str] | None,
    resolve_timeout: float,
) -> tuple[str, int, tuple[str, ...]]:
    if not allow_ssh and (
        _SCP_GIT_URL.fullmatch(source) or urlsplit(source).scheme == "ssh"
    ):
        raise ValueError("SSH repository URLs require explicit allow_ssh=True")
    host, port = _remote_host(source)
    canonical_host = host.rstrip(".").lower()
    if allowed_hosts is not None and canonical_host not in {
        item.rstrip(".").lower() for item in allowed_hosts
    }:
        raise ValueError(f"Repository host is not allowed: {host}")
    addresses = set(_resolve_remote_addresses(host, port, resolve_timeout))
    if not addresses:
        raise RepoFetchError(f"Could not resolve repository host: {host}")
    for address in addresses:
        try:
            is_public = ipaddress.ip_address(address).is_global
        except ValueError as exc:
            raise RepoFetchError(
                f"Repository host resolved to an invalid address: {host}"
            ) from exc
        if not allow_private_hosts and not is_public:
            raise ValueError(
                f"Repository host resolves to a non-public address: {host}"
            )
    return host, port or 443, tuple(sorted(addresses))


def _resolve_remote_addresses(host: str, port: int, timeout: float) -> tuple[str, ...]:
    """Resolve in a disposable process so libc DNS cannot escape the deadline."""
    worker_path = Path(__file__).with_name("dns_worker.py").resolve()
    environment = {
        key: os.environ[key]
        for key in ("SYSTEMROOT", "WINDIR", "LANG", "LC_ALL")
        if key in os.environ
    }
    environment["PYTHONNOUSERSITE"] = "1"
    try:
        result = subprocess.run(
            [sys.executable, "-I", str(worker_path)],
            input=json.dumps({"host": host, "port": port}).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
            cwd=str(Path(sys.executable).resolve().parent),
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise RepoFetchError(
            f"DNS resolution timed out after {timeout:g} seconds"
        ) from exc
    except OSError as exc:
        raise RepoFetchError("DNS resolver worker could not be started") from exc
    if result.returncode != 0:
        reason = {
            2: "invalid resolver input",
            3: "host resolution failed",
            4: "too many resolved addresses",
        }.get(result.returncode, f"resolver exit code {result.returncode}")
        raise RepoFetchError(f"Could not resolve repository host {host}: {reason}")
    try:
        addresses = json.loads(result.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RepoFetchError("DNS resolver returned invalid output") from exc
    if not isinstance(addresses, list) or not all(
        isinstance(address, str) for address in addresses
    ):
        raise RepoFetchError("DNS resolver returned invalid output")
    return tuple(addresses)


def _entry_disk_usage(metadata: os.stat_result) -> int:
    blocks = getattr(metadata, "st_blocks", None)
    if isinstance(blocks, int):
        return max(metadata.st_size, blocks * 512, _MIN_ENTRY_DISK_BYTES)
    return max(metadata.st_size, _FALLBACK_ENTRY_DISK_BYTES)


def _directory_size_exceeds(root: Path, limit: int) -> bool:
    """Estimate disk usage conservatively, including tiny files and directories."""
    if not root.exists():
        return False

    try:
        total = _entry_disk_usage(root.lstat())
    except OSError:
        return True
    if total > limit:
        return True

    directories = [root]
    while directories:
        current = directories.pop()
        try:
            entries = os.scandir(current)
        except OSError:
            return True
        try:
            with entries:
                for entry in entries:
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                        total += _entry_disk_usage(metadata)
                        is_directory = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        return True
                    if total > limit:
                        return True
                    if is_directory:
                        directories.append(Path(entry.path))
        except OSError:
            return True
    return False


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            # The group can outlive its leader, so signal the known PGID even
            # when Git itself has already exited.
            os.killpg(process.pid, signal.SIGKILL)
        else:
            system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
            taskkill = system_root / "System32" / "taskkill.exe"
            result = subprocess.run(
                [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                timeout=5,
            )
            if result.returncode != 0 and process.poll() is None:
                process.kill()
    except (OSError, subprocess.SubprocessError):
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _run_clone(
    command: list[str],
    environment: dict[str, str],
    target: Path,
    *,
    timeout: float,
    max_clone_bytes: int,
) -> None:
    try:
        process = subprocess.Popen(
            command,
            env=environment,
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            start_new_session=os.name == "posix",
            creationflags=(
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                if os.name == "nt"
                else 0
            ),
        )
    except FileNotFoundError as exc:
        raise RepoFetchError("Git executable was not found") from exc
    except OSError as exc:
        raise RepoFetchError(
            f"Git clone could not be started: {type(exc).__name__}"
        ) from exc

    completed = False
    try:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RepoFetchError(f"Git clone timed out after {timeout:g} seconds")
            try:
                return_code = process.wait(
                    timeout=min(_CLONE_POLL_INTERVAL_SECONDS, remaining)
                )
            except subprocess.TimeoutExpired:
                if _directory_size_exceeds(target, max_clone_bytes):
                    raise RepoFetchError(
                        "Git clone exceeded the "
                        f"{max_clone_bytes}-byte estimated disk limit"
                    )
                continue

            if return_code != 0:
                raise RepoFetchError(f"Git clone failed with exit code {return_code}")
            if _directory_size_exceeds(target, max_clone_bytes):
                raise RepoFetchError(
                    "Git clone exceeded the "
                    f"{max_clone_bytes}-byte estimated disk limit"
                )
            completed = True
            return
    finally:
        if not completed:
            _terminate_process(process)


def fetch_repo(
    source: str,
    clone_dir: str | None = None,
    *,
    timeout: float = DEFAULT_CLONE_TIMEOUT_SECONDS,
    allow_ssh: bool = False,
    allow_private_hosts: bool = False,
    allowed_hosts: Collection[str] | None = None,
    max_clone_bytes: int = DEFAULT_MAX_CLONE_BYTES,
) -> Path:
    """Return a local repository directory, cloning a safe remote URL when needed.

    Automatically-created clone directories are removed on failure and at process
    exit. Long-running callers should prefer :func:`fetched_repo` for prompt cleanup.
    """
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Clone timeout must be positive")
    if type(max_clone_bytes) is not int or max_clone_bytes <= 0:
        raise ValueError("Clone size limit must be positive")
    if not is_git_url(source):
        path = Path(source).expanduser()
        if not path.exists():
            raise ValueError(f"Local path does not exist: {source}")
        if not path.is_dir():
            raise ValueError(f"Local path is not a directory: {source}")
        return path.resolve()

    deadline = time.monotonic() + timeout
    remote_host, remote_port, remote_addresses = _validate_remote(
        source,
        allow_ssh=allow_ssh,
        allow_private_hosts=allow_private_hosts,
        allowed_hosts=allowed_hosts,
        resolve_timeout=timeout,
    )
    clone_timeout = deadline - time.monotonic()
    if clone_timeout <= 0:
        raise RepoFetchError(
            f"Repository acquisition timed out after {timeout:g} seconds"
        )
    owns_target = clone_dir is None
    target = Path(clone_dir) if clone_dir else Path(tempfile.mkdtemp(prefix="sv-"))
    environment = {
        key: os.environ[key]
        for key in ("PATH", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "SYSTEMROOT")
        if key in os.environ
    }
    environment.update(
        {
            "GIT_ALLOW_PROTOCOL": "https:ssh" if allow_ssh else "https",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": shutil.which("false") or os.devnull,
            "GCM_INTERACTIVE": "never",
        }
    )
    if allow_ssh:
        for key in ("HOME", "SSH_AUTH_SOCK"):
            if key in os.environ:
                environment[key] = os.environ[key]
        pinned_address = remote_addresses[0]
        environment["GIT_SSH_COMMAND"] = (
            "ssh -F /dev/null -oBatchMode=yes -oStrictHostKeyChecking=yes "
            "-oClearAllForwardings=yes -oPermitLocalCommand=no -oProxyCommand=none "
            f"-oHostName={pinned_address} -oHostKeyAlias={remote_host}"
        )
    command = [
        "git",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "http.followRedirects=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "clone",
        "--depth=1",
        "--single-branch",
        "--no-tags",
        "--",
        source,
        str(target),
    ]
    if urlsplit(source).scheme == "https":
        pinned_addresses = ",".join(
            f"[{address}]" if ":" in address else address
            for address in remote_addresses
        )
        command[command.index("clone") : command.index("clone")] = [
            "-c",
            f"http.curloptResolve={remote_host}:{remote_port}:{pinned_addresses}",
        ]
    if allow_ssh:
        command[command.index("clone") : command.index("clone")] = [
            "-c",
            "protocol.ssh.allow=always",
        ]
    try:
        _run_clone(
            command,
            environment,
            target,
            timeout=clone_timeout,
            max_clone_bytes=max_clone_bytes,
        )
    except BaseException:
        if owns_target:
            shutil.rmtree(target, ignore_errors=True)
        raise

    if owns_target:
        atexit.register(shutil.rmtree, target, ignore_errors=True)
    return target.resolve()


@contextmanager
def fetched_repo(
    source: str,
    clone_dir: str | None = None,
    **kwargs,
) -> Iterator[Path]:
    """Acquire a repository and clean up an automatic clone after use."""
    if not is_git_url(source) or clone_dir is not None:
        yield fetch_repo(source, clone_dir, **kwargs)
        return

    with tempfile.TemporaryDirectory(prefix="sv-") as temporary_dir:
        yield fetch_repo(source, temporary_dir, **kwargs)
