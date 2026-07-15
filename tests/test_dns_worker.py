import io
import ipaddress
import json
import socket
from types import SimpleNamespace

from skills_verified.repo import dns_worker
from skills_verified.repo.fetcher import _resolve_remote_addresses


def _invoke(monkeypatch, payload):
    stdin = SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))
    stdout = io.StringIO()
    monkeypatch.setattr(dns_worker.sys, "stdin", stdin)
    monkeypatch.setattr(dns_worker.sys, "stdout", stdout)
    return dns_worker.main(), stdout.getvalue()


def test_dns_worker_returns_unique_sorted_addresses(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, 0, 0, "", ("203.0.113.2", 443)),
            (socket.AF_INET, 0, 0, "", ("203.0.113.1", 443)),
            (socket.AF_INET, 0, 0, "", ("203.0.113.2", 443)),
        ],
    )

    exit_code, output = _invoke(monkeypatch, {"host": "example.test", "port": 443})

    assert exit_code == 0
    assert json.loads(output) == ["203.0.113.1", "203.0.113.2"]


def test_dns_worker_rejects_invalid_input_without_resolving(monkeypatch):
    called = False

    def resolve(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(socket, "getaddrinfo", resolve)

    exit_code, output = _invoke(monkeypatch, {"host": "example.test", "port": True})

    assert exit_code == 2
    assert output == ""
    assert called is False


def test_dns_worker_reports_resolution_failure(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(socket.gaierror("missing")),
    )

    exit_code, output = _invoke(monkeypatch, {"host": "missing.example", "port": 443})

    assert exit_code == 3
    assert output == ""


def test_dns_worker_rejects_oversized_input_before_resolution(monkeypatch):
    stdin = SimpleNamespace(buffer=io.BytesIO(b"x" * (dns_worker.MAX_INPUT_BYTES + 1)))
    stdout = io.StringIO()
    called = False

    def resolve(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(dns_worker.sys, "stdin", stdin)
    monkeypatch.setattr(dns_worker.sys, "stdout", stdout)

    assert dns_worker.main() == 2
    assert called is False
    assert stdout.getvalue() == ""


def test_dns_worker_rejects_excessive_address_set(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, 0, 0, "", (f"203.0.113.{index}", 443))
            for index in range(dns_worker.MAX_ADDRESSES + 1)
        ],
    )

    exit_code, output = _invoke(monkeypatch, {"host": "example.test", "port": 443})

    assert exit_code == 4
    assert output == ""


def test_parent_runs_isolated_dns_worker_from_source_checkout():
    addresses = _resolve_remote_addresses("localhost", 80, 3)

    assert addresses
    assert all(ipaddress.ip_address(address) for address in addresses)
