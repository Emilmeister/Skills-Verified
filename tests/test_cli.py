import json
from contextlib import contextmanager
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from skills_verified.analyzers.llm_analyzer import LlmAnalyzer
from skills_verified.cli import _all_analyzers, main
from skills_verified.core.pipeline import Pipeline


def _invoke_json(path: Path, *args: str):
    result = CliRunner().invoke(main, [str(path), "--compact", *args])
    assert result.exit_code == 0, result.output
    return result, json.loads(result.output)


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


def test_cli_with_local_path_emits_json(fake_repo_path: Path):
    result, report = _invoke_json(fake_repo_path, "--only", "guardrails")

    assert report["schema_version"] == "1.0"
    assert report["source"]["input"] == str(fake_repo_path)
    assert report["analyzer_runs"][0]["name"] == "guardrails"
    assert "overall_score" not in report
    assert "overall_grade" not in report


def test_cli_progress_uses_stderr_and_keeps_stdout_as_json(
    fake_repo_path: Path, monkeypatch
):
    emitted: list[tuple[str, bool]] = []
    original_echo = click.echo

    def observe_echo(message=None, **kwargs):
        emitted.append((str(message), bool(kwargs.get("err"))))
        return original_echo(message, **kwargs)

    monkeypatch.setattr("skills_verified.cli.click.echo", observe_echo)
    result = CliRunner().invoke(
        main,
        [
            str(fake_repo_path),
            "--only",
            "guardrails",
            "--progress",
            "--compact",
        ],
    )

    assert result.exit_code == 0, result.output
    stdout_messages = [message for message, is_stderr in emitted if not is_stderr]
    stderr_messages = [message for message, is_stderr in emitted if is_stderr]
    assert json.loads(stdout_messages[-1])["scan"]["status"] == "complete"
    assert any("[1/1] guardrails: started" in message for message in stderr_messages)
    assert any("[1/1] guardrails: completed" in message for message in stderr_messages)
    assert all("guardrails: started" not in message for message in stdout_messages)


def test_cli_output_file_matches_stdout(fake_repo_path: Path, tmp_path: Path):
    out_file = tmp_path / "nested" / "report.json"
    result = CliRunner().invoke(
        main,
        [
            str(fake_repo_path),
            "--only",
            "guardrails",
            "--compact",
            "--output",
            str(out_file),
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(out_file.read_text(encoding="utf-8")) == json.loads(result.output)


def test_cli_forwards_remote_clone_limit(fake_repo_path: Path, monkeypatch):
    observed = []

    @contextmanager
    def fake_fetch(source, **kwargs):
        observed.append((source, kwargs))
        yield fake_repo_path

    monkeypatch.setattr("skills_verified.cli.fetched_repo", fake_fetch)
    result = CliRunner().invoke(
        main,
        [
            "https://example.test/repo.git",
            "--only",
            "guardrails",
            "--max-clone-mib",
            "512",
            "--clone-timeout",
            "240",
            "--compact",
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed == [
        (
            "https://example.test/repo.git",
            {"timeout": 240.0, "max_clone_bytes": 512 * 1024 * 1024},
        )
    ]


def test_cli_forwards_scan_inventory_limit(fake_repo_path: Path, monkeypatch):
    observed = []
    original_run = Pipeline.run

    def observe(self, repo_path, repo_url, **kwargs):
        observed.append(kwargs["max_total_bytes"])
        return original_run(self, repo_path, repo_url, **kwargs)

    monkeypatch.setattr("skills_verified.cli.Pipeline.run", observe)
    result = CliRunner().invoke(
        main,
        [
            str(fake_repo_path),
            "--only",
            "guardrails",
            "--max-scan-mib",
            "256",
            "--compact",
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed == [256 * 1024 * 1024]


def test_cli_output_write_failure_still_emits_json(
    fake_repo_path: Path, tmp_path: Path
):
    parent_file = tmp_path / "not-a-directory"
    parent_file.write_text("blocker", encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            str(fake_repo_path),
            "--only",
            "guardrails",
            "--compact",
            "--output",
            str(parent_file / "report.json"),
        ],
    )

    assert result.exit_code == 3
    report = json.loads(result.output)
    assert report["diagnostics"][-1]["code"] == "output_write_failed"


def test_cli_skip_and_only_select_expected_analyzers(fake_repo_path: Path):
    _, report = _invoke_json(
        fake_repo_path,
        "--only",
        "guardrails,pattern",
        "--skip",
        "permissions",
    )

    assert [run["name"] for run in report["analyzer_runs"]] == ["pattern", "guardrails"]


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


def test_cli_rejects_unknown_analyzer(fake_repo_path: Path):
    result = CliRunner().invoke(main, [str(fake_repo_path), "--only", "guardrailz"])

    assert result.exit_code == 2
    assert "unknown analyzer name(s): guardrailz" in result.output


def test_cli_rejects_conflicting_selection(fake_repo_path: Path):
    result = CliRunner().invoke(
        main,
        [str(fake_repo_path), "--only", "guardrails", "--skip", "guardrails"],
    )

    assert result.exit_code == 2
    assert "present in both --only and --skip" in result.output


def test_cli_rejects_partial_llm_configuration(fake_repo_path: Path):
    result = CliRunner().invoke(
        main,
        [str(fake_repo_path), "--llm-url", "http://localhost:11434/v1"],
    )

    assert result.exit_code == 2
    assert "must be provided together" in result.output


def test_cli_rejects_invalid_llm_url_as_usage_error(fake_repo_path: Path):
    result = CliRunner().invoke(
        main,
        [
            str(fake_repo_path),
            "--llm-url",
            "file:///tmp/provider",
            "--llm-model",
            "test",
            "--llm-key",
            "secret",
        ],
    )

    assert result.exit_code == 2
    assert "LLM URL must be an HTTP(S) base URL" in result.output
    assert "secret" not in result.output


def test_cli_can_disable_llm_structured_output(fake_repo_path: Path, monkeypatch):
    observed = []

    def request(analyzer, _batch, _timeout_seconds):
        observed.append(analyzer.config.structured_output)
        return json.dumps({"findings": []})

    monkeypatch.setattr(LlmAnalyzer, "_request_with_deadline", request)
    result = CliRunner().invoke(
        main,
        [
            str(fake_repo_path),
            "--only",
            "llm",
            "--llm-url",
            "http://localhost:11434/v1",
            "--llm-model",
            "test",
            "--llm-key",
            "secret",
            "--no-llm-structured-output",
            "--compact",
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed and set(observed) == {False}
    report = json.loads(result.output)
    assert report["scan"]["status"] == "complete"
    assert any(
        diagnostic["code"] == "llm_structured_output_disabled"
        for diagnostic in report["diagnostics"]
    )


def test_cli_forwards_llm_runtime_limits(fake_repo_path: Path, monkeypatch):
    observed = []

    def request(analyzer, _batch, timeout_seconds):
        observed.append(
            (
                analyzer.config.timeout_seconds,
                analyzer.config.total_timeout_seconds,
                analyzer.config.max_completion_tokens,
                analyzer.config.token_parameter,
                analyzer.config.reasoning_effort,
                analyzer.config.concurrency,
                analyzer.config.max_batches,
                analyzer.config.verification_runs,
                timeout_seconds,
            )
        )
        return json.dumps({"findings": []})

    monkeypatch.setattr(LlmAnalyzer, "_request_with_deadline", request)
    result = CliRunner().invoke(
        main,
        [
            str(fake_repo_path),
            "--only",
            "llm",
            "--llm-url",
            "http://localhost:11434/v1",
            "--llm-model",
            "test",
            "--llm-key",
            "secret",
            "--llm-timeout",
            "45",
            "--llm-total-timeout",
            "600",
            "--llm-max-tokens",
            "8192",
            "--llm-token-parameter",
            "max_completion_tokens",
            "--llm-reasoning-effort",
            "minimal",
            "--llm-concurrency",
            "2",
            "--llm-max-batches",
            "10",
            "--llm-verification-runs",
            "2",
            "--compact",
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed
    (
        request_timeout,
        total_timeout,
        max_tokens,
        token_parameter,
        reasoning_effort,
        concurrency,
        max_batches,
        verification_runs,
        effective_timeout,
    ) = observed[0]
    assert request_timeout == 45
    assert total_timeout == 600
    assert max_tokens == 8192
    assert token_parameter == "max_completion_tokens"
    assert reasoning_effort == "minimal"
    assert concurrency == 2
    assert max_batches == 10
    assert verification_runs == 2
    assert 0 < effective_timeout <= 45


def test_cli_rejects_removed_llm_json_schema_flag(fake_repo_path: Path):
    result = CliRunner().invoke(main, [str(fake_repo_path), "--llm-json-schema"])

    assert result.exit_code == 2
    assert "No such option: --llm-json-schema" in result.output


def test_cli_leaves_llm_batch_and_total_time_budgets_unlimited_by_default(
    fake_repo_path: Path, monkeypatch
):
    observed = []

    def request(analyzer, _batch, timeout_seconds):
        observed.append(
            (
                analyzer.config.max_batches,
                analyzer.config.total_timeout_seconds,
                timeout_seconds,
            )
        )
        return json.dumps({"findings": []})

    monkeypatch.setattr(LlmAnalyzer, "_request_with_deadline", request)
    result = CliRunner().invoke(
        main,
        [
            str(fake_repo_path),
            "--only",
            "llm",
            "--llm-url",
            "http://localhost:11434/v1",
            "--llm-model",
            "test",
            "--llm-key",
            "secret",
            "--compact",
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed
    assert observed[0] == (None, None, 30)


def test_cli_reads_llm_concurrency_from_environment(fake_repo_path: Path, monkeypatch):
    observed = []

    def request(analyzer, _batch, _timeout_seconds):
        observed.append(analyzer.config.concurrency)
        return json.dumps({"findings": []})

    monkeypatch.setattr(LlmAnalyzer, "_request_with_deadline", request)
    result = CliRunner().invoke(
        main,
        [
            str(fake_repo_path),
            "--only",
            "llm",
            "--llm-url",
            "http://localhost:11434/v1",
            "--llm-model",
            "test",
            "--llm-key",
            "secret",
            "--compact",
        ],
        env={"SV_LLM_CONCURRENCY": "2"},
    )

    assert result.exit_code == 0, result.output
    assert observed and set(observed) == {2}


def test_cli_reads_analyzer_concurrency_from_environment(
    fake_repo_path: Path, monkeypatch
):
    observed = []
    original_run = Pipeline.run

    def observe(self, repo_path, repo_url, **kwargs):
        observed.append(self.concurrency)
        return original_run(self, repo_path, repo_url, **kwargs)

    monkeypatch.setattr("skills_verified.cli.Pipeline.run", observe)
    result = CliRunner().invoke(
        main,
        [str(fake_repo_path), "--only", "guardrails", "--compact"],
        env={"SV_ANALYZER_CONCURRENCY": "2"},
    )

    assert result.exit_code == 0, result.output
    assert observed == [2]


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


def test_removed_policy_flags_are_rejected(fake_repo_path: Path):
    result = CliRunner().invoke(main, [str(fake_repo_path), "--threshold", "50"])

    assert result.exit_code == 2
    assert "No such option" in result.output
    assert "--threshold" in result.output


def test_failed_scan_still_emits_machine_readable_json(fake_repo_path: Path):
    result = CliRunner().invoke(
        main,
        [str(fake_repo_path), "--only", "llm", "--compact"],
    )

    assert result.exit_code == 3
    report = json.loads(result.output)
    assert report["scan"]["status"] == "failed"
    assert report["analyzer_runs"][0]["version"]
    assert report["analyzer_runs"] == [
        {
            "duration_ms": report["analyzer_runs"][0]["duration_ms"],
            "findings_count": 0,
            "name": "llm",
            "reason": "not_available",
            "status": "skipped",
            "version": report["analyzer_runs"][0]["version"],
        }
    ]


def test_unexpected_pipeline_failure_is_json_and_exit_three(
    fake_repo_path: Path, monkeypatch
):
    def fail_scan(*args, **kwargs):
        raise RuntimeError("orchestration broke")

    monkeypatch.setattr("skills_verified.cli.Pipeline.run", fail_scan)

    result = CliRunner().invoke(
        main,
        [str(fake_repo_path), "--only", "guardrails", "--compact"],
    )

    assert result.exit_code == 3
    report = json.loads(result.output)
    assert report["scan"]["status"] == "failed"
    assert report["diagnostics"][0]["code"] == "scan_execution_failed"
    assert report["analyzer_runs"][0]["reason"] == "scan_execution_failed"
