import json
import os
from contextlib import contextmanager
from pathlib import Path

import pytest
from click.testing import CliRunner

import skills_verified.cli as cli_module
from skills_verified.analyzers.llm_analyzer import LlmAnalyzer
from skills_verified.cli import _all_analyzers, main


def test_cli_help_describes_json_analyzer():
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "policy-free JSON" in result.output
    assert "report" in result.output
    assert "--threshold" not in result.output
    assert "--format" not in result.output


def test_default_registry_contains_shellcheck_in_stable_position():
    names = [analyzer.name for analyzer in _all_analyzers(None)]

    assert names[names.index("bandit") + 1] == "shellcheck"
    assert len(names) == 18


def test_cli_nonexistent_path_is_input_error():
    result = CliRunner().invoke(main, ["/nonexistent/path/xyz123"])

    assert result.exit_code == 2
    report = json.loads(result.output)
    assert report["scan"]["status"] == "failed"
    assert report["source"]["input"] == "/nonexistent/path/xyz123"
    assert report["source"]["commit_sha"] is None
    assert report["findings"] == []
    assert report["diagnostics"][0]["code"] == "source_fetch_failed"
    assert report["diagnostics"][0]["level"] == "error"
    assert report["analyzer_runs"]
    assert all(
        run["status"] == "skipped" and run["reason"] == "source_fetch_failed"
        for run in report["analyzer_runs"]
    )
    rendered = json.dumps(report)
    assert "trust_score" not in rendered
    assert "overall_score" not in rendered
    assert "overall_grade" not in rendered


def test_cli_emits_typed_corroborated_llm_finding(tmp_path: Path, monkeypatch):
    (tmp_path / "code.py").write_text("dangerous_call()\n", encoding="utf-8")
    candidate_response = json.dumps(
        {
            "findings": [
                {
                    "title": "Dangerous call",
                    "description": "The cited call directly executes unsafe input.",
                    "severity": "high",
                    "file_path": "code.py",
                    "start_line": 1,
                    "end_line": 1,
                    "evidence": "dangerous_call()",
                    "confidence": 0.9,
                }
            ]
        }
    )
    monkeypatch.setattr(
        LlmAnalyzer,
        "_request_with_deadline",
        lambda *_args: candidate_response,
    )

    def verify(_self, candidates, _batch, _timeout, _run_number):
        return json.dumps(
            {
                "verifications": [
                    {
                        "candidate_id": candidates[0].verification.candidate_id,
                        "status": "supported",
                    }
                ]
            }
        )

    monkeypatch.setattr(LlmAnalyzer, "_verification_request_with_deadline", verify)
    result = CliRunner().invoke(
        main,
        [
            str(tmp_path),
            "--only",
            "llm",
            "--llm-url",
            "http://localhost:11434/v1",
            "--llm-model",
            "test",
            "--llm-key",
            "secret",
            "--llm-verification-runs",
            "1",
            "--compact",
        ],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    finding = report["findings"][0]
    assert finding["verification"]["status"] == "corroborated"
    assert finding["verification"]["attempts"] == 1
    assert finding["verification"]["candidate_id"].startswith("sha256:")


@pytest.mark.parametrize("scheme", ["https", "HTTPS"])
def test_cli_redacts_credentials_from_malformed_source_url(scheme):
    source = f"{scheme}://user:secret@[bad/repo?token=also-secret"

    result = CliRunner().invoke(main, [source, "--only", "guardrails", "--compact"])

    assert result.exit_code == 2
    report = json.loads(result.output)
    rendered = json.dumps(report)
    assert report["source"]["input"] == f"{scheme}://[bad/repo"
    assert "secret" not in rendered
    assert "token" not in rendered


@pytest.mark.parametrize("missing", ["SV_CLOUDRU_KEY_ID", "SV_CLOUDRU_KEY_SECRET"])
def test_cli_requires_cloudru_credentials_together(tmp_path, missing):
    environment = {
        "SV_CLOUDRU_KEY_ID": "test-id",
        "SV_CLOUDRU_KEY_SECRET": "test-secret",
    }
    environment[missing] = None

    result = CliRunner().invoke(
        main, [str(tmp_path), "--only", "guardrails"], env=environment
    )

    assert result.exit_code == 2
    assert "must be provided together" in result.output
    assert "test-id" not in result.output
    assert "test-secret" not in result.output


@pytest.mark.parametrize("invalid", ["", "   "])
def test_cli_rejects_empty_cloudru_key_without_echoing_secret(tmp_path, invalid):
    result = CliRunner().invoke(
        main,
        [str(tmp_path), "--only", "guardrails"],
        env={"SV_CLOUDRU_KEY_ID": invalid, "SV_CLOUDRU_KEY_SECRET": "test-secret"},
    )

    assert result.exit_code == 2
    assert "test-secret" not in result.output


def test_cli_cloudru_credentials_preserve_local_scans(tmp_path):
    result = CliRunner().invoke(
        main,
        [str(tmp_path), "--only", "guardrails", "--compact"],
        env={"SV_CLOUDRU_KEY_ID": "test-id", "SV_CLOUDRU_KEY_SECRET": "test-secret"},
    )

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["source"]["input"] == str(tmp_path)
    assert "test-id" not in result.output
    assert "test-secret" not in result.output


def test_cli_cloudru_credentials_are_consumed_before_scanning(monkeypatch, tmp_path):
    captured = {}

    @contextmanager
    def fetch(source, **kwargs):
        captured.update(kwargs)
        assert os.getenv("SV_CLOUDRU_KEY_ID") is None
        assert os.getenv("SV_CLOUDRU_KEY_SECRET") is None
        yield tmp_path

    monkeypatch.setattr(cli_module, "fetched_repo", fetch)
    result = CliRunner().invoke(
        main,
        [
            "https://repo.cloud.ru/project/skills.git",
            "--only",
            "guardrails",
            "--compact",
        ],
        env={"SV_CLOUDRU_KEY_ID": "test-id", "SV_CLOUDRU_KEY_SECRET": "test-secret"},
    )

    assert result.exit_code == 0, result.output
    credentials = captured["cloudru_credentials"]
    assert credentials.key_id == "test-id"
    assert credentials.key_secret == "test-secret"
    assert "test-id" not in repr(credentials)
    assert "test-secret" not in repr(credentials)
    assert "test-id" not in result.output
    assert "test-secret" not in result.output


def test_cli_cloudru_auth_error_is_a_secret_free_json_report(monkeypatch):
    @contextmanager
    def fetch(source, **kwargs):
        raise RuntimeError("Cloud.ru IAM authentication failed (HTTP 401)")
        yield

    monkeypatch.setattr(cli_module, "fetched_repo", fetch)
    result = CliRunner().invoke(
        main,
        [
            "https://repo.cloud.ru/project/skills.git",
            "--only",
            "guardrails",
            "--compact",
        ],
        env={"SV_CLOUDRU_KEY_ID": "test-id", "SV_CLOUDRU_KEY_SECRET": "test-secret"},
    )

    assert result.exit_code == 2
    report = json.loads(result.output)
    assert report["scan"]["status"] == "failed"
    assert report["diagnostics"][0]["code"] == "source_fetch_failed"
    assert "HTTP 401" in report["diagnostics"][0]["message"]
    assert "test-id" not in result.output
    assert "test-secret" not in result.output
