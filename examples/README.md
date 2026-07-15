# CI examples

Every example runs Skills Verified and stores its policy-free JSON report. The examples inspect `scan.status`, `findings`, and `analyzer_runs`, but do not decide whether a skill may be published.

## GitHub Actions

| Example | Purpose |
| --- | --- |
| [`github-actions/basic.yml`](github-actions/basic.yml) | Scan one repository and print technical execution data |
| [`github-actions/full.yml`](github-actions/full.yml) | Configure analyzers and upload the JSON artifact |
| [`github-actions/monorepo.yml`](github-actions/monorepo.yml) | Produce one independent report per skill directory |

Replace `@main` with a release tag or commit SHA before production use.

The action outputs are `report-path`, `scan-status`, and `findings-count`. The complete, versioned contract remains in the JSON file.

## GitLab CI

| Example | Purpose |
| --- | --- |
| [`gitlab-ci/basic.yml`](gitlab-ci/basic.yml) | Include and run the shared scanner job |
| [`gitlab-ci/full.yml`](gitlab-ci/full.yml) | Configure source/analyzer selection and artifact retention |
| [`gitlab-ci/monorepo.yml`](gitlab-ci/monorepo.yml) | Run the scanner as a parallel matrix |

The template installs from `SV_INSTALL_SPEC`; pin this variable to a release or commit in production. Its job fails only when the scanner cannot produce a technically usable scan. Findings never alter the process exit code.

## Consuming the report

Send the untouched artifact to the service that owns publication policy. Consumers should check at least:

```python
status = report["scan"]["status"]
findings = report["findings"]
analyzer_runs = report["analyzer_runs"]
```

`partial` and `failed` describe analysis completeness, not repository safety. Absence of findings is meaningful only together with scope, analyzer runs, diagnostics, scanner version, and ruleset version.
