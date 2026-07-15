"""Isolated, size-bounded HTTP worker for OpenAI-compatible chat endpoints."""

from __future__ import annotations

import json
import math
import os
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

import certifi

# Keep these constants synchronized with llm_analyzer.py. They are intentionally
# local so this file can run under `python -I` from an uninstalled source tree.
MAX_LLM_HTTP_RESPONSE_BYTES = 512_000
MAX_LLM_WORKER_INPUT_BYTES = 1_000_000


class _NoRedirectHandler(HTTPRedirectHandler):
    """Fail closed instead of forwarding the provider key to another origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_request(request: Request, *, timeout: float, context: ssl.SSLContext):
    opener = build_opener(_NoRedirectHandler(), HTTPSHandler(context=context))
    return opener.open(request, timeout=timeout)


def _endpoint(base_url: str) -> str:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid endpoint URL")
    return base_url.rstrip("/") + "/chat/completions"


def main() -> int:
    raw_input = sys.stdin.buffer.read(MAX_LLM_WORKER_INPUT_BYTES + 1)
    if len(raw_input) > MAX_LLM_WORKER_INPUT_BYTES:
        return 2
    try:
        payload = json.loads(raw_input)
        base_url = payload["url"]
        key = payload["key"]
        timeout_seconds = payload["timeout_seconds"]
        request_data = payload["request"]
        if (
            not isinstance(base_url, str)
            or not isinstance(key, str)
            or not key
            or type(timeout_seconds) not in (int, float)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or not isinstance(request_data, dict)
        ):
            return 2
        endpoint = _endpoint(base_url)
        body = json.dumps(request_data, ensure_ascii=False).encode()
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return 2

    request = Request(
        endpoint,
        data=body,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        context = ssl.create_default_context(
            cafile=os.environ.get("SSL_CERT_FILE") or certifi.where()
        )
        with _open_request(
            request, timeout=float(timeout_seconds), context=context
        ) as response:
            raw_response = response.read(MAX_LLM_HTTP_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        return 3
    if len(raw_response) > MAX_LLM_HTTP_RESPONSE_BYTES:
        return 4
    sys.stdout.buffer.write(raw_response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
