# Cloud.ru Repo authentication implementation plan

**Goal:** Scan private Cloud.ru Repo repositories using Key ID/Key Secret in CI.

**Architecture:** A focused IAM client exchanges the credentials for a fresh JWT.
The fetcher supplies a host-scoped Bearer header through Git environment config;
the CLI reads only environment variables for credentials. Reuse stdlib networking,
the installed certifi bundle and the existing isolated subprocess pattern to
retain a hard wall-clock acquisition budget.

**Tech stack:** Python 3.11+, urllib, subprocess, Click, pytest, Ruff.

- [x] Add failing tests and implement `repo/cloudru_auth.py` (and an isolated
  `repo/cloudru_auth_worker.py` if required for the deadline). Define a redacted
  `CloudRuCredentials` object, `CloudRuAuthError` and
  `get_access_token(credentials, *, timeout) -> str`. Verify with
  `pytest tests/test_cloudru_auth.py -v`.
- [x] Add failing tests in `tests/test_fetcher.py`, then extend `fetch_repo` with
  `cloudru_credentials=None`. Authenticate only the default-port Cloud.ru HTTPS
  origin after DNS validation, deduct IAM time before clone, and supply
  `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=http.https://repo.cloud.ru/.extraHeader`,
  `GIT_CONFIG_VALUE_0=Authorization: Bearer <token>` in the isolated environment.
  Verify host isolation, elapsed deadline and lack of secrets in argv/config.
- [x] Add failing CLI tests, then read `SV_CLOUDRU_KEY_ID` and
  `SV_CLOUDRU_KEY_SECRET`, validate the pair and forward the redacted credentials
  to `fetched_repo`. Preserve the existing JSON failure report path.
- [x] Add usage instructions beside remote-repository usage in README.md,
  preserving its existing user edits. Review spec coverage and security.
- [x] Run `pytest tests/ -v`, `ruff check src/ tests/`,
  `ruff format --check src/ tests/` and `skills-verified --help`.

Verification: 616 tests passed, 9 skipped; Ruff lint, format check and CLI help
exited successfully. Focused authentication/integration tests passed after the
expected failures. Independent security review found no blockers. Live private
Repo access was not tested because no Cloud.ru credentials/repository were supplied.
