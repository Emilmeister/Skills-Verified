import io
import json
import math
import subprocess
import time
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request

import pytest

from skills_verified.repo import cloudru_auth as auth


KEY_ID = "synthetic-key-id"
KEY_SECRET = "synthetic-key-secret"
TOKEN = "synthetic.bearer-token_123"


def test_credentials_are_immutable_and_hide_both_keys():
    from skills_verified.repo.cloudru_auth import CloudRuCredentials

    credentials = CloudRuCredentials("synthetic-key-id", "synthetic-key-secret")

    assert credentials.key_id == "synthetic-key-id"
    assert credentials.key_secret == "synthetic-key-secret"
    assert "synthetic-key" not in repr(credentials)
    with pytest.raises(FrozenInstanceError):
        credentials.key_id = "replacement"


@pytest.mark.parametrize("invalid", ["", "  ", None, 42, True])
@pytest.mark.parametrize("field", ["key_id", "key_secret"])
def test_credentials_reject_empty_or_non_string_keys(field, invalid):
    from skills_verified.repo.cloudru_auth import CloudRuCredentials

    values = {"key_id": "synthetic-key-id", "key_secret": "synthetic-key-secret"}
    values[field] = invalid

    with pytest.raises(ValueError, match="nonempty strings"):
        CloudRuCredentials(**values)


def test_token_exchange_sends_keys_only_through_isolated_worker_stdin(monkeypatch):
    monkeypatch.setenv("CLOUDRU_KEY_SECRET", KEY_SECRET)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("PYTHONPATH", "/untrusted")
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.example.test")
    process = Mock(return_value=SimpleNamespace(returncode=0, stdout=TOKEN.encode()))
    monkeypatch.setattr(subprocess, "run", process)

    assert (
        auth.get_access_token(auth.CloudRuCredentials(KEY_ID, KEY_SECRET), timeout=3)
        == TOKEN
    )

    args, options = process.call_args
    assert args[0][1] == "-I"
    assert args[0][2].endswith("/cloudru_auth_worker.py")
    assert KEY_ID not in repr(args)
    assert KEY_SECRET not in repr(args)
    assert json.loads(options["input"]) == {
        "keyId": KEY_ID,
        "secret": KEY_SECRET,
        "timeout_seconds": 3,
    }
    assert options["timeout"] == 3
    assert options["stdout"] == subprocess.PIPE
    assert options["stderr"] == subprocess.DEVNULL
    assert options["check"] is False
    assert options["env"].keys() <= {
        "SYSTEMROOT",
        "SystemRoot",
        "WINDIR",
        "PATH",
        "TMP",
        "TEMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    }
    assert KEY_SECRET not in repr(options["env"])


@pytest.mark.parametrize("timeout", [0, -1, math.nan, math.inf, True, "3"])
def test_invalid_timeout_never_starts_worker(monkeypatch, timeout):
    process = Mock()
    monkeypatch.setattr(subprocess, "run", process)

    with pytest.raises(ValueError, match="positive finite"):
        auth.get_access_token(
            auth.CloudRuCredentials(KEY_ID, KEY_SECRET), timeout=timeout
        )

    process.assert_not_called()


@pytest.mark.parametrize(
    ("code", "message"),
    [
        (3, "request failed"),
        (4, "invalid response"),
        (5, "Key ID or Key Secret"),
        (6, "access denied"),
        (7, "timed out"),
        (99, "request failed"),
    ],
)
def test_worker_failures_have_fixed_messages_without_output(monkeypatch, code, message):
    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(
            return_value=SimpleNamespace(
                returncode=code, stdout=f"{KEY_ID} {KEY_SECRET} {TOKEN}".encode()
            )
        ),
    )

    with pytest.raises(auth.CloudRuAuthError, match=message) as caught:
        auth.get_access_token(auth.CloudRuCredentials(KEY_ID, KEY_SECRET), timeout=3)

    for value in (KEY_ID, KEY_SECRET, TOKEN):
        assert value not in str(caught.value)
        assert value not in repr(caught.value)


@pytest.mark.parametrize(
    "failure",
    [
        subprocess.TimeoutExpired(
            ["python"], 3, output=TOKEN.encode(), stderr=KEY_SECRET.encode()
        ),
        OSError(f"{KEY_SECRET}: startup failed"),
    ],
)
def test_subprocess_exceptions_cannot_leak_through_exception_chaining(
    monkeypatch, failure
):
    monkeypatch.setattr(subprocess, "run", Mock(side_effect=failure))

    with pytest.raises(auth.CloudRuAuthError) as caught:
        auth.get_access_token(auth.CloudRuCredentials(KEY_ID, KEY_SECRET), timeout=3)

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert TOKEN not in repr(caught.value)
    assert KEY_SECRET not in repr(caught.value)


@pytest.mark.parametrize(
    "output",
    [
        b"",
        b"token\r\nInjected: secret",
        b"token with spaces",
        b"\xff",
        pytest.param(b"x" * 65_537, id="oversized"),
    ],
)
def test_parent_rejects_unsafe_worker_token(monkeypatch, output):
    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(return_value=SimpleNamespace(returncode=0, stdout=output)),
    )

    with pytest.raises(auth.CloudRuAuthError, match="invalid response") as caught:
        auth.get_access_token(auth.CloudRuCredentials(KEY_ID, KEY_SECRET), timeout=3)

    assert caught.value.__context__ is None


def test_wall_clock_timeout_kills_worker_even_after_partial_output(
    monkeypatch, tmp_path
):
    worker = tmp_path / "cloudru_auth_worker.py"
    worker.write_text(
        "import sys, time\nsys.stdout.write('partial-secret-token')\nsys.stdout.flush()\ntime.sleep(10)\n"
    )
    monkeypatch.setattr(auth, "__file__", str(tmp_path / "cloudru_auth.py"))
    start = time.monotonic()

    with pytest.raises(auth.CloudRuAuthError, match="timed out") as caught:
        auth.get_access_token(auth.CloudRuCredentials(KEY_ID, KEY_SECRET), timeout=0.15)

    assert time.monotonic() - start < 3
    assert caught.value.__context__ is None
    assert "partial-secret-token" not in repr(caught.value)


def _run_worker(
    monkeypatch,
    response=b'{"access_token":"synthetic.bearer-token_123"}',
    error=None,
    payload=None,
):
    from skills_verified.repo import cloudru_auth_worker as worker

    payload = payload or {"keyId": KEY_ID, "secret": KEY_SECRET, "timeout_seconds": 3}
    stdin = SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))
    stdout = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(worker.sys, "stdin", stdin)
    monkeypatch.setattr(worker.sys, "stdout", stdout)
    reads, captured = [], {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, limit):
            reads.append(limit)
            return response

    def open_request(request, *, timeout, context):
        captured.update(
            url=request.full_url,
            body=json.loads(request.data),
            headers=dict(request.header_items()),
            timeout=timeout,
            context=context,
        )
        if error is not None:
            raise error
        return Response()

    monkeypatch.setattr(worker, "_open_request", open_request)
    code = worker.main()
    return code, stdout.buffer.getvalue(), reads, captured


def test_worker_posts_exact_iam_request_with_verified_tls_and_bounded_read(monkeypatch):
    code, output, reads, captured = _run_worker(monkeypatch)

    assert code == 0
    assert output == TOKEN.encode()
    assert reads == [65_537]
    assert captured["url"] == "https://iam.api.cloud.ru/api/v1/auth/token"
    assert captured["body"] == {"keyId": KEY_ID, "secret": KEY_SECRET}
    assert captured["headers"]["Content-type"] == "application/json"
    assert captured["timeout"] == 3
    assert captured["context"].verify_mode.name == "CERT_REQUIRED"
    assert captured["context"].check_hostname is True


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(b"x" * 65_537, id="oversized"),
        b"not-json",
        b"[]",
        b"{}",
        b'{"access_token":null}',
        b'{"access_token":""}',
        b'{"access_token":"token\\r\\nInjected: secret"}',
        b'{"access_token":"non-ascii-\xc3\xa9"}',
    ],
)
def test_worker_rejects_invalid_response_without_output(monkeypatch, response):
    code, output, reads, _ = _run_worker(monkeypatch, response=response)

    assert code == 4
    assert output == b""
    assert reads == [65_537]


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (
            HTTPError(
                "https://iam.api.cloud.ru",
                401,
                KEY_SECRET,
                {},
                io.BytesIO(TOKEN.encode()),
            ),
            5,
        ),
        (
            HTTPError(
                "https://iam.api.cloud.ru",
                403,
                KEY_SECRET,
                {},
                io.BytesIO(TOKEN.encode()),
            ),
            6,
        ),
        (
            HTTPError(
                "https://iam.api.cloud.ru",
                302,
                KEY_SECRET,
                {},
                io.BytesIO(TOKEN.encode()),
            ),
            3,
        ),
        (URLError(KEY_SECRET), 3),
        (URLError(TimeoutError(KEY_SECRET)), 7),
        (TimeoutError(KEY_SECRET), 7),
    ],
)
def test_worker_sanitizes_iam_and_transport_failures(monkeypatch, error, expected):
    code, output, reads, _ = _run_worker(monkeypatch, error=error)

    assert code == expected
    assert output == b""
    assert reads == []


def test_worker_opener_disables_redirects_and_proxies(monkeypatch):
    from skills_verified.repo import cloudru_auth_worker as worker

    opener = Mock()
    builder = Mock(return_value=opener)
    monkeypatch.setattr(worker, "build_opener", builder)
    request = Request("https://iam.api.cloud.ru/api/v1/auth/token", data=b"{}")
    context = Mock()

    worker._open_request(request, timeout=3, context=context)

    handlers = builder.call_args.args
    assert any(
        isinstance(handler, ProxyHandler) and handler.proxies == {}
        for handler in handlers
    )
    assert any(
        isinstance(handler, HTTPSHandler) and handler._context is context
        for handler in handlers
    )
    redirect = next(
        handler
        for handler in handlers
        if isinstance(handler, worker._NoRedirectHandler)
    )
    for code in (301, 302, 303, 307, 308):
        assert (
            redirect.redirect_request(
                request, None, code, "redirect", {}, "https://untrusted.example.test"
            )
            is None
        )
    opener.open.assert_called_once_with(request, timeout=3)
