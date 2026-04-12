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
