from click.testing import CliRunner

from skills_verified.cli import main


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "skills-verified" in result.output.lower() or "usage" in result.output.lower()


def test_cli_with_local_path(fake_repo_path):
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path)])
    assert result.exit_code == 0
    assert "TRUST SCORE" in result.output


def test_cli_with_json_output(fake_repo_path, tmp_path):
    out_file = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path), "--output", str(out_file)])
    assert result.exit_code == 0
    assert out_file.exists()


def test_cli_with_skip(fake_repo_path):
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path), "--skip", "bandit,semgrep"])
    assert result.exit_code == 0


def test_cli_with_only(fake_repo_path):
    runner = CliRunner()
    result = runner.invoke(main, [str(fake_repo_path), "--only", "guardrails"])
    assert result.exit_code == 0


def test_cli_nonexistent_path():
    runner = CliRunner()
    result = runner.invoke(main, ["/nonexistent/path/xyz123"])
    assert result.exit_code != 0


def test_cli_fail_on_strict_blocks_non_A(fake_repo_path):
    """fake_repo has many findings so grade < A; strict should block."""
    runner = CliRunner()
    result = runner.invoke(main, [
        str(fake_repo_path), "--skip", "bandit,semgrep,cve,llm,container",
        "--fail-on", "strict",
    ])
    assert result.exit_code == 1
    assert "BLOCKED" in result.output


def test_cli_fail_on_relaxed_passes_non_F(fake_repo_path):
    """With only guardrails on a repo that isn't grade F, relaxed should pass."""
    runner = CliRunner()
    result = runner.invoke(main, [
        str(fake_repo_path), "--only", "permissions",
        "--fail-on", "relaxed",
    ])
    assert result.exit_code == 0


def test_cli_fail_on_standard_blocks_on_D(fake_repo_path):
    """fake_repo has enough findings to push some categories to D/F."""
    runner = CliRunner()
    result = runner.invoke(main, [
        str(fake_repo_path), "--skip", "bandit,semgrep,cve,llm,container",
        "--fail-on", "standard",
    ])
    # With all built-in analyzers the fake_repo should trigger at least CRITICAL
    assert result.exit_code == 1


def test_cli_no_fail_on_always_passes(fake_repo_path):
    """Without --fail-on, exit code is always 0 regardless of grade."""
    runner = CliRunner()
    result = runner.invoke(main, [
        str(fake_repo_path), "--skip", "bandit,semgrep,cve,llm,container",
    ])
    assert result.exit_code == 0
