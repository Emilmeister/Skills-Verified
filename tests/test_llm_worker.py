import io
import json
import math
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from skills_verified.analyzers import llm_worker
from skills_verified.analyzers import llm_analyzer as llm_module


def _run_worker(monkeypatch, payload, response_bytes):
    stdin = SimpleNamespace(
        buffer=io.BytesIO(json.dumps(payload, separators=(",", ":")).encode())
    )
    stdout = SimpleNamespace(buffer=io.BytesIO())
    reads = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, size):
            reads.append(size)
            return response_bytes

    captured = {}

    def open_request(request, timeout, context):
        captured["url"] = request.full_url
        captured["headers"] = dict(request.header_items())
        captured["body"] = json.loads(request.data)
        captured["timeout"] = timeout
        assert context.verify_mode.name == "CERT_REQUIRED"
        return Response()

    monkeypatch.setattr(llm_worker.sys, "stdin", stdin)
    monkeypatch.setattr(llm_worker.sys, "stdout", stdout)
    monkeypatch.setattr(llm_worker, "_open_request", open_request)

    exit_code = llm_worker.main()
    return exit_code, stdout.buffer.getvalue(), reads, captured


def _payload():
    return {
        "url": "https://llm.example.test/v1",
        "key": "secret-key",
        "timeout_seconds": 3,
        "request": {"model": "test", "messages": []},
    }


def test_worker_posts_to_openai_compatible_endpoint(monkeypatch):
    response = b'{"choices":[{"message":{"content":"{\\"findings\\":[]}"}}]}'

    exit_code, output, reads, captured = _run_worker(monkeypatch, _payload(), response)

    assert exit_code == 0
    assert output == response
    assert reads == [llm_worker.MAX_LLM_HTTP_RESPONSE_BYTES + 1]
    assert captured["url"] == "https://llm.example.test/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer secret-key"
    assert captured["body"] == {"model": "test", "messages": []}
    assert captured["timeout"] == 3


def test_worker_rejects_response_before_unbounded_materialization(monkeypatch):
    oversized = b"x" * (llm_worker.MAX_LLM_HTTP_RESPONSE_BYTES + 1)

    exit_code, output, reads, _captured = _run_worker(
        monkeypatch, _payload(), oversized
    )

    assert exit_code == 4
    assert output == b""
    assert reads == [llm_worker.MAX_LLM_HTTP_RESPONSE_BYTES + 1]


def test_worker_rejects_oversized_input_without_network(monkeypatch):
    stdin = SimpleNamespace(
        buffer=io.BytesIO(b"x" * (llm_worker.MAX_LLM_WORKER_INPUT_BYTES + 1))
    )
    stdout = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(llm_worker.sys, "stdin", stdin)
    monkeypatch.setattr(llm_worker.sys, "stdout", stdout)
    monkeypatch.setattr(
        llm_worker,
        "_open_request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("network must not be called")
        ),
    )

    assert llm_worker.main() == 2
    assert stdout.buffer.getvalue() == b""


def test_worker_limits_match_parent_process_contract():
    assert (
        llm_worker.MAX_LLM_HTTP_RESPONSE_BYTES == llm_module.MAX_LLM_HTTP_RESPONSE_BYTES
    )
    assert (
        llm_worker.MAX_LLM_WORKER_INPUT_BYTES == llm_module.MAX_LLM_WORKER_INPUT_BYTES
    )


def test_worker_honors_operator_ca_bundle(monkeypatch, tmp_path):
    ca_bundle = tmp_path / "enterprise-ca.pem"
    ca_bundle.write_text("test certificate placeholder")
    create_context = Mock(return_value=Mock())
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_bundle))
    monkeypatch.setattr(llm_worker.ssl, "create_default_context", create_context)
    monkeypatch.setattr(
        llm_worker,
        "_open_request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("stop after TLS setup")
        ),
    )
    stdin = SimpleNamespace(
        buffer=io.BytesIO(json.dumps(_payload(), separators=(",", ":")).encode())
    )
    stdout = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(llm_worker.sys, "stdin", stdin)
    monkeypatch.setattr(llm_worker.sys, "stdout", stdout)

    assert llm_worker.main() == 3
    create_context.assert_called_once_with(cafile=str(ca_bundle))


@pytest.mark.parametrize("timeout", [0, -1, math.nan, math.inf, -math.inf, True])
def test_worker_rejects_invalid_timeout_without_network(monkeypatch, timeout):
    payload = _payload()
    payload["timeout_seconds"] = timeout
    called = False

    def open_request(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(llm_worker, "_open_request", open_request)
    stdin = SimpleNamespace(
        buffer=io.BytesIO(json.dumps(payload, separators=(",", ":")).encode())
    )
    stdout = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(llm_worker.sys, "stdin", stdin)
    monkeypatch.setattr(llm_worker.sys, "stdout", stdout)

    assert llm_worker.main() == 2
    assert called is False


def test_worker_rejects_redirect_without_forwarding_authorization(monkeypatch):
    redirected_requests = []
    source_authorization = []

    class RedirectTarget(BaseHTTPRequestHandler):
        def do_POST(self):
            redirected_requests.append(dict(self.headers))
            self.send_response(200)
            self.end_headers()

        def do_GET(self):
            redirected_requests.append(dict(self.headers))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args):
            return

    target = ThreadingHTTPServer(("127.0.0.1", 0), RedirectTarget)

    class RedirectSource(BaseHTTPRequestHandler):
        def do_POST(self):
            source_authorization.append(self.headers.get("Authorization"))
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{target.server_port}/captured",
            )
            self.end_headers()

        def log_message(self, *_args):
            return

    source = ThreadingHTTPServer(("127.0.0.1", 0), RedirectSource)
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (target, source)
    ]
    for thread in threads:
        thread.start()

    payload = _payload()
    payload["url"] = f"http://127.0.0.1:{source.server_port}/v1"
    stdin = SimpleNamespace(
        buffer=io.BytesIO(json.dumps(payload, separators=(",", ":")).encode())
    )
    stdout = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(llm_worker.sys, "stdin", stdin)
    monkeypatch.setattr(llm_worker.sys, "stdout", stdout)
    try:
        assert llm_worker.main() == 3
    finally:
        for server in (source, target):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)

    assert source_authorization == ["Bearer secret-key"]
    assert redirected_requests == []
