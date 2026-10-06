"""Isolated Cloud.ru IAM exchange; keys arrive on stdin and token leaves on stdout."""

from __future__ import annotations

import json
import math
import re
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

import certifi

# Local constants allow this worker to run under python -I from a source tree.
MAX_IAM_RESPONSE_BYTES = 64 * 1024
MAX_IAM_WORKER_INPUT_BYTES = 64 * 1024
_BEARER_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+=*")
_IAM_URL = "https://iam.api.cloud.ru/api/v1/auth/token"


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_request(request: Request, *, timeout: float, context: ssl.SSLContext):
    opener = build_opener(
        ProxyHandler({}), _NoRedirectHandler(), HTTPSHandler(context=context)
    )
    return opener.open(request, timeout=timeout)


def main() -> int:
    raw_input = sys.stdin.buffer.read(MAX_IAM_WORKER_INPUT_BYTES + 1)
    if len(raw_input) > MAX_IAM_WORKER_INPUT_BYTES:
        return 2
    try:
        payload = json.loads(raw_input)
        key_id = payload["keyId"]
        key_secret = payload["secret"]
        timeout = payload["timeout_seconds"]
        if (
            not isinstance(key_id, str)
            or not key_id.strip()
            or not isinstance(key_secret, str)
            or not key_secret.strip()
            or type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            return 2
        body = json.dumps({"keyId": key_id, "secret": key_secret}).encode()
    except (KeyError, TypeError, ValueError, RecursionError):
        return 2

    request = Request(
        _IAM_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with _open_request(
            request, timeout=float(timeout), context=context
        ) as response:
            raw_response = response.read(MAX_IAM_RESPONSE_BYTES + 1)
    except HTTPError as error:
        return {401: 5, 403: 6}.get(error.code, 3)
    except TimeoutError:
        return 7
    except URLError as error:
        return 7 if isinstance(error.reason, TimeoutError) else 3
    except (OSError, ValueError):
        return 3
    if len(raw_response) > MAX_IAM_RESPONSE_BYTES:
        return 4
    try:
        response_data = json.loads(raw_response)
    except (ValueError, RecursionError):
        return 4
    token = (
        response_data.get("access_token") if isinstance(response_data, dict) else None
    )
    if not isinstance(token, str) or not _BEARER_TOKEN.fullmatch(token):
        return 4
    sys.stdout.buffer.write(token.encode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
