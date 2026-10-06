# Cloud.ru Repo authentication

The user approved direct IAM authentication with Key ID/Key Secret. The CLI reads
`SV_CLOUDRU_KEY_ID` and `SV_CLOUDRU_KEY_SECRET`; there are no secret command-line
options. Both values are required together. Local paths and other Git hosts keep
their existing behavior even when the complete credential pair is configured.

For HTTPS URLs on `repo.cloud.ru` with the default HTTPS port, validate the remote
first, then exchange the keys at the fixed IAM token endpoint. Use the returned
`access_token` as a Bearer header scoped to that HTTPS origin. Pass it through
Git's process environment, never its arguments, repository URL or on-disk config.
Do not pass the original keys to Git or analyzer subprocesses. Reject redirects
when sending keys to IAM and retain Git's existing redirect and network guards.

Each clone gets a fresh token. No persistent token storage or refresh loop is
needed: the default clone budget is 120 seconds and IAM tokens last one hour.
Authentication consumes the same acquisition deadline as DNS and cloning.
Bound and validate IAM responses and emit fixed errors without server bodies or
secret exception text. Credential objects must not reveal keys through repr.

Tests cover the IAM request/response, invalid and failed responses, hard timeout,
host/protocol isolation, Git environment scoping, unchanged public/local scans,
CLI credential validation, and absence of secrets from reports and Git config.
Live cloning needs the user's credentials and a private repository; fixtures
must use synthetic credentials only.

Sources:
- https://cloud.ru/docs/console_api/ug/topics/guides__auth_api
- https://cloud.ru/docs/repo-evolution/ug/topics/guides__auth
- https://git-scm.com/docs/git-config
