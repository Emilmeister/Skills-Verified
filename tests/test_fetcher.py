import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import skills_verified.repo.fetcher as fetcher_module
from skills_verified.repo.fetcher import (
    DEFAULT_MAX_CLONE_BYTES,
    _MIN_ENTRY_DISK_BYTES,
    RepoFetchError,
    _directory_size_exceeds,
    _entry_disk_usage,
    _resolve_remote_addresses,
    _run_clone,
    _terminate_process,
    fetch_repo,
    fetched_repo,
    is_git_url,
)


def _stub_dns(monkeypatch, address="93.184.216.34"):
    monkeypatch.setattr(
        fetcher_module,
        "_resolve_remote_addresses",
        lambda _host, _port, _timeout: (address,),
    )


def test_fetch_local_path(tmp_path):
    test_file = tmp_path / "hello.py"
    test_file.write_text("print('hi')")
    result = fetch_repo(str(tmp_path))
    assert result == tmp_path
    assert (result / "hello.py").exists()


def test_fetch_local_path_nonexistent():
    with pytest.raises(ValueError, match="does not exist"):
        fetch_repo("/nonexistent/path/abc123")


def test_fetch_rejects_local_file(tmp_path):
    source = tmp_path / "SKILL.md"
    source.write_text("test")

    with pytest.raises(ValueError, match="not a directory"):
        fetch_repo(str(source))


def test_fetch_detects_url():
    assert is_git_url("https://github.com/user/repo") is True
    assert is_git_url("git@github.com:user/repo.git") is True
    assert is_git_url("/home/user/repo") is False
    assert is_git_url("./relative/path") is False


@pytest.mark.parametrize(
    "source",
    [
        "http://github.com/user/repo.git",
        "https://user:secret@github.com/user/repo.git",
        "https://github.com:0/user/repo.git",
        "https://127.0.0.1/repo.git",
        "https://10.0.0.1/repo.git",
        "git@github.com:repo;touch-pwned",
        "ssh://git@github.com/repo%20name.git",
        "file:///tmp/repo",
    ],
)
def test_fetch_rejects_unsafe_remote_sources(source):
    with pytest.raises(ValueError):
        fetch_repo(source)


def test_fetch_rejects_hostname_resolving_to_private_ip(monkeypatch):
    _stub_dns(monkeypatch, "192.168.1.2")

    with pytest.raises(ValueError, match="non-public"):
        fetch_repo("https://git.example.test/repo.git")


def test_fetch_remote_uses_noninteractive_timed_clone(monkeypatch, tmp_path):
    _stub_dns(monkeypatch)
    run_clone = Mock()
    monkeypatch.setattr(fetcher_module, "_run_clone", run_clone)
    target = tmp_path / "clone"

    assert (
        fetch_repo("https://git.example.test/repo.git", str(target), timeout=7)
        == target
    )

    args, kwargs = run_clone.call_args
    assert args[0][-2:] == ["https://git.example.test/repo.git", str(target)]
    assert "--depth=1" in args[0]
    assert "http.followRedirects=false" in args[0]
    assert "http.curloptResolve=git.example.test:443:93.184.216.34" in args[0]
    assert "protocol.allow=never" in args[0]
    assert args[1]["GIT_TERMINAL_PROMPT"] == "0"
    assert args[1]["GIT_ALLOW_PROTOCOL"] == "https"
    assert "GIT_SSH_COMMAND" not in args[1]
    assert "GIT_CONFIG_COUNT" not in args[1]
    assert args[2] == target
    assert 0 < kwargs["timeout"] <= 7
    assert kwargs["max_clone_bytes"] == DEFAULT_MAX_CLONE_BYTES


def test_fetch_rejects_ssh_without_explicit_opt_in():
    with pytest.raises(ValueError, match="explicit allow_ssh"):
        fetch_repo("git@github.com:user/repo.git")


def test_fetch_timeout_cleans_automatic_clone_directory(monkeypatch):
    _stub_dns(monkeypatch)
    clone_target = None

    def timeout(command, _environment, _target, **_kwargs):
        nonlocal clone_target
        clone_target = Path(command[-1])
        (clone_target / "partial").write_text("partial clone")
        raise RepoFetchError("Git clone timed out after 1 seconds")

    monkeypatch.setattr(fetcher_module, "_run_clone", timeout)

    with pytest.raises(RepoFetchError, match="timed out"):
        fetch_repo("https://git.example.test/repo.git", timeout=1)

    assert clone_target is not None
    assert not clone_target.exists()


def test_fetched_repo_context_cleans_automatic_clone(monkeypatch):
    _stub_dns(monkeypatch)

    def clone(command, _environment, _target, **_kwargs):
        (Path(command[-1]) / "SKILL.md").write_text("test")

    monkeypatch.setattr(fetcher_module, "_run_clone", clone)

    with fetched_repo("https://git.example.test/repo.git") as path:
        assert (path / "SKILL.md").exists()
        clone_path = path

    assert not clone_path.exists()


def test_fetch_rejects_nonpositive_clone_size_limit(tmp_path):
    with pytest.raises(ValueError, match="size limit must be positive"):
        fetch_repo(str(tmp_path), max_clone_bytes=0)


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), float("-inf"), True])
def test_fetch_rejects_nonfinite_or_boolean_timeout(tmp_path, timeout):
    with pytest.raises(ValueError, match="timeout must be positive"):
        fetch_repo(str(tmp_path), timeout=timeout)


@pytest.mark.parametrize(
    "limit", [float("nan"), float("inf"), float("-inf"), 1.0, True]
)
def test_fetch_rejects_noninteger_clone_size_limit(tmp_path, limit):
    with pytest.raises(ValueError, match="size limit must be positive"):
        fetch_repo(str(tmp_path), max_clone_bytes=limit)


def test_directory_size_limit_stops_counting_early(tmp_path):
    (tmp_path / "one").write_bytes(b"1234")
    (tmp_path / "two").write_bytes(b"5678")

    estimated_usage = 3 * _MIN_ENTRY_DISK_BYTES
    assert _directory_size_exceeds(tmp_path, estimated_usage - 1) is True
    assert _directory_size_exceeds(tmp_path, estimated_usage) is False


def test_directory_size_limit_counts_tiny_file_allocation(tmp_path):
    for index in range(100):
        (tmp_path / f"empty-{index}").touch()

    assert _directory_size_exceeds(tmp_path, 100 * _MIN_ENTRY_DISK_BYTES) is True


def test_disk_usage_uses_conservative_fallback_without_block_metadata():
    metadata = SimpleNamespace(st_size=1)

    assert _entry_disk_usage(metadata) == fetcher_module._FALLBACK_ENTRY_DISK_BYTES


def test_dns_resolution_timeout_is_reported(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(side_effect=subprocess.TimeoutExpired(["python"], 0.01)),
    )

    with pytest.raises(RepoFetchError, match="DNS resolution timed out"):
        _resolve_remote_addresses("example.test", 443, 0.01)


def test_fetch_timeout_covers_dns_and_clone(monkeypatch, tmp_path):
    captured = {}

    def resolve(_host, _port, timeout):
        captured["dns_timeout"] = timeout
        return ("93.184.216.34",)

    def clone(_command, _environment, _target, *, timeout, max_clone_bytes):
        captured["clone_timeout"] = timeout
        captured["max_clone_bytes"] = max_clone_bytes

    monkeypatch.setattr(fetcher_module, "_resolve_remote_addresses", resolve)
    monkeypatch.setattr(fetcher_module, "_run_clone", clone)
    monotonic = iter((100.0, 102.0))
    monkeypatch.setattr(fetcher_module.time, "monotonic", lambda: next(monotonic))

    fetch_repo(
        "https://git.example.test/repo.git",
        str(tmp_path / "clone"),
        timeout=7,
    )

    assert captured == {
        "dns_timeout": 7,
        "clone_timeout": 5,
        "max_clone_bytes": DEFAULT_MAX_CLONE_BYTES,
    }


def test_directory_size_check_fails_closed_on_traversal_error(monkeypatch, tmp_path):
    monkeypatch.setattr(
        fetcher_module.os,
        "scandir",
        lambda _path: (_ for _ in ()).throw(PermissionError("denied")),
    )

    assert _directory_size_exceeds(tmp_path, 1024 * 1024) is True


def test_run_clone_stops_process_when_disk_limit_is_exceeded(monkeypatch, tmp_path):
    target = tmp_path / "clone"
    target.mkdir()
    (target / "pack").write_bytes(b"12345")
    terminated = []

    class Process:
        def wait(self, timeout):
            raise subprocess.TimeoutExpired(["git"], timeout)

    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: Process())
    monkeypatch.setattr(
        fetcher_module,
        "_terminate_process",
        lambda process: terminated.append(process),
    )

    with pytest.raises(RepoFetchError, match="4-byte estimated disk limit"):
        _run_clone(
            ["git", "clone"],
            {},
            target,
            timeout=1,
            max_clone_bytes=4,
        )

    assert len(terminated) == 1


def test_run_clone_passes_isolated_process_options(monkeypatch, tmp_path):
    process = Mock()
    process.wait.return_value = 0
    popen = Mock(return_value=process)
    monkeypatch.setattr(subprocess, "Popen", popen)

    _run_clone(
        ["git", "clone"],
        {"PATH": "/bin"},
        tmp_path / "clone",
        timeout=1,
        max_clone_bytes=1024,
    )

    popen.assert_called_once_with(
        ["git", "clone"],
        env={"PATH": "/bin"},
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        start_new_session=fetcher_module.os.name == "posix",
        creationflags=0,
    )


def test_run_clone_terminates_process_on_unexpected_base_exception(
    monkeypatch, tmp_path
):
    terminated = []

    class Process:
        def wait(self, timeout):
            raise KeyboardInterrupt

    process = Process()
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        fetcher_module,
        "_terminate_process",
        lambda item: terminated.append(item),
    )

    with pytest.raises(KeyboardInterrupt):
        _run_clone(
            ["git", "clone"],
            {},
            tmp_path / "clone",
            timeout=1,
            max_clone_bytes=1024,
        )

    assert terminated == [process]


def test_terminate_process_signals_group_even_if_leader_exited(monkeypatch):
    process = Mock(pid=4321)
    process.poll.return_value = 1
    process.wait.return_value = 1
    kill_group = Mock()
    monkeypatch.setattr(fetcher_module.os, "killpg", kill_group)

    _terminate_process(process)

    kill_group.assert_called_once_with(4321, fetcher_module.signal.SIGKILL)


def test_fetch_ssh_pins_validated_address(monkeypatch, tmp_path):
    _stub_dns(monkeypatch)
    run_clone = Mock()
    monkeypatch.setattr(fetcher_module, "_run_clone", run_clone)

    fetch_repo(
        "git@git.example.test:owner/repo.git",
        str(tmp_path / "clone"),
        allow_ssh=True,
    )

    environment = run_clone.call_args.args[1]
    assert "-oHostName=93.184.216.34" in environment["GIT_SSH_COMMAND"]
    assert "-oHostKeyAlias=git.example.test" in environment["GIT_SSH_COMMAND"]
    assert "protocol.ssh.allow=always" in run_clone.call_args.args[0]


def test_fetch_cleans_automatic_clone_on_keyboard_interrupt(monkeypatch):
    _stub_dns(monkeypatch)
    clone_target = None

    def interrupted(command, _environment, _target, **_kwargs):
        nonlocal clone_target
        clone_target = Path(command[-1])
        (clone_target / "partial").write_text("partial clone")
        raise KeyboardInterrupt

    monkeypatch.setattr(fetcher_module, "_run_clone", interrupted)

    with pytest.raises(KeyboardInterrupt):
        fetch_repo("https://git.example.test/repo.git")

    assert clone_target is not None
    assert not clone_target.exists()
