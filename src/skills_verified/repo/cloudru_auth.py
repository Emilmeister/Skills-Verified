"""Obtain Cloud.ru IAM bearer tokens without exposing access keys."""

import json
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


MAX_IAM_RESPONSE_BYTES = 64 * 1024
MAX_IAM_WORKER_INPUT_BYTES = 64 * 1024
_BEARER_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+=*")


class CloudRuAuthError(RuntimeError):
    """Cloud.ru IAM authentication failed without disclosing credentials."""


@dataclass(frozen=True)
class CloudRuCredentials:
    key_id: str = field(repr=False)
    key_secret: str = field(repr=False)

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, str) or not value.strip()
            for value in (self.key_id, self.key_secret)
        ):
            raise ValueError("Cloud.ru Key ID and Key Secret must be nonempty strings")


def get_access_token(credentials: CloudRuCredentials, *, timeout: float) -> str:
    """Exchange access keys under a wall-clock deadline, including DNS and reads."""
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Cloud.ru IAM timeout must be a positive finite number")
    worker_input = json.dumps(
        {
            "keyId": credentials.key_id,
            "secret": credentials.key_secret,
            "timeout_seconds": timeout,
        },
        separators=(",", ":"),
    ).encode()
    if len(worker_input) > MAX_IAM_WORKER_INPUT_BYTES:
        raise CloudRuAuthError("Cloud.ru IAM credentials exceed the input size limit")
    environment = {
        key: os.environ[key]
        for key in (
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
        )
        if key in os.environ
    }
    failure = None
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(Path(__file__).with_name("cloudru_auth_worker.py").resolve()),
            ],
            input=worker_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
            cwd=str(Path(sys.executable).resolve().parent),
            env=environment,
        )
    except subprocess.TimeoutExpired:
        failure = "Cloud.ru IAM authentication timed out"
    except OSError:
        failure = "Cloud.ru IAM authentication worker could not be started"
    # Raise outside the handler: even __context__ must not retain captured secrets.
    if failure:
        raise CloudRuAuthError(failure)
    if result.returncode != 0:
        message = {
            2: "Cloud.ru IAM authentication received invalid input",
            4: "Cloud.ru IAM returned an invalid response",
            5: "Cloud.ru IAM rejected the Key ID or Key Secret (401)",
            6: "Cloud.ru IAM access denied (403); check access key permissions",
            7: "Cloud.ru IAM authentication timed out",
        }.get(result.returncode, "Cloud.ru IAM authentication request failed")
        raise CloudRuAuthError(message)
    token = ""
    if len(result.stdout) <= MAX_IAM_RESPONSE_BYTES:
        try:
            token = result.stdout.decode("ascii")
        except UnicodeDecodeError:
            pass
    if not _BEARER_TOKEN.fullmatch(token):
        raise CloudRuAuthError("Cloud.ru IAM returned an invalid response")
    return token
