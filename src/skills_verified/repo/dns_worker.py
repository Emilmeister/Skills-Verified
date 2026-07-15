"""Small isolated DNS resolver used to enforce repository acquisition deadlines."""

from __future__ import annotations

import json
import socket
import sys

MAX_INPUT_BYTES = 1_024
MAX_ADDRESSES = 256


def main() -> int:
    raw_input = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw_input) > MAX_INPUT_BYTES:
        return 2
    try:
        payload = json.loads(raw_input)
        host = payload["host"]
        port = payload["port"]
        if (
            not isinstance(host, str)
            or not host
            or len(host) > 253
            or type(port) is not int
            or not 1 <= port <= 65_535
        ):
            return 2
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return 2

    try:
        addresses = sorted(
            {
                item[4][0]
                for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            }
        )
    except (socket.gaierror, OSError):
        return 3
    if len(addresses) > MAX_ADDRESSES:
        return 4
    sys.stdout.write(json.dumps(addresses, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
