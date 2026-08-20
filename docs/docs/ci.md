---
sidebar_position: 5
---

# Use in CI

PySentry is built for CI: it exits non-zero when findings reach the `--fail-on` threshold, so any CI system can gate on it without extra flags. This page covers the GitHub Action and the generic recipe for other CI systems.

## GitHub Action

The first-party action ([Marketplace listing](https://github.com/marketplace/actions/pysentry-security-audit)) downloads a prebuilt binary (verified against the release checksums), runs the audit, and — on push to the default branch — uploads a SARIF report to GitHub Code Scanning so findings appear in the repository Security tab. On pull requests the SARIF upload is skipped by default (fork PRs get a read-only token, so the upload would fail); instead PySentry writes a compact report to the run's **job summary**, which it does whenever it runs in GitHub Actions.

```yaml
name: Dependency Audit

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write # required for the SARIF upload

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: nyudenkov/pysentry@v0.4.9
        with:
          fail-on: high
```

### Inputs

All inputs are optional and map to CLI flags.

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Project to audit |
| `version` | action tag | PySentry version to download |
| `fail-on` | PySentry default | Minimum severity causing a non-zero exit (`low`, `medium`, `high`, `critical`) |
| `sources` | PySentry default | Space-separated vulnerability sources (`pypa`, `pypi`, `osv`) |
| `format` | `sarif` | Report format |
| `output` | `pysentry-results.sarif` | Report file path |
| `ignore` | — | Space-separated vulnerability IDs to suppress |
| `upload-sarif` | `true` | Upload the report to Code Scanning |
| `upload-sarif-on-pr` | `false` | Also upload on `pull_request` events (off by default; fork PRs can't get the write token) |
| `category` | `pysentry` | Code Scanning category |
| `args` | — | Extra raw CLI arguments |

### Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | PySentry exit code |
| `output-file` | Path to the generated report |

On push, the SARIF report is uploaded even when the audit fails, so findings always reach the Security tab; the job then fails with the audit's exit code. On pull requests, the job summary shows the compact report and the job still fails on findings at or above `fail-on`.

## Other CI systems

No installation step is needed on runners with `uv`:

```bash
uvx pysentry-rs --fail-on high
```

The exit code is the contract: `0` when no findings reach the threshold, non-zero otherwise. See the [exit codes table](/getting-started/quickstart#exit-codes) for details.

GitLab CI example:

```yaml
dependency-audit:
  image: python:3.12-slim
  script:
    - pip install pysentry-rs
    - pysentry-rs --fail-on high
```

## Related

- [Pre-commit hook](https://github.com/pysentry/pysentry-pre-commit) for local gating before CI
- [Configuration files](/configuration/config-files) to keep CI flags in `.pysentry.toml` instead of workflow YAML
