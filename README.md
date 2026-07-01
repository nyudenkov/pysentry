<div align="center">

<img src="assets/logo.svg" alt="PySentry logo" width="96" height="96">

# PySentry

**Fast, reliable vulnerability scanning for Python dependencies.**

[![CI](https://github.com/nyudenkov/pysentry/actions/workflows/ci.yml/badge.svg)](https://github.com/nyudenkov/pysentry/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pysentry-rs)](https://pypi.org/project/pysentry-rs/)
[![crates.io](https://img.shields.io/crates/v/pysentry)](https://crates.io/crates/pysentry)
[![Downloads](https://static.pepy.tech/badge/pysentry-rs/week)](https://pepy.tech/projects/pysentry-rs)

[**Documentation**](https://docs.pysentry.com) · [**Benchmarks**](benchmarks/results/) · [Help test & improve](https://github.com/nyudenkov/pysentry/issues/12) · [Usage survey](https://tally.so/r/mYNPNv)

</div>

PySentry audits Python projects for known security vulnerabilities. It reads your lock file or manifest, resolves the full dependency tree, and checks every package against three vulnerability databases — then reports what is affected, how severe it is, and the upgrade that fixes it.

![PySentry scanning a project and reporting vulnerabilities](assets/demo.gif)

## Features

- **Every dependency format** — `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pylock.toml`, `pyproject.toml`, `Pipfile`, `requirements.txt`, and PEP 723 inline script metadata. Lock files take precedence when both are present.
- **Three databases, one report** — PyPA Advisory Database, PyPI JSON API, and OSV.dev, queried concurrently with results merged and de-duplicated.
- **Tree-aware findings** — distinguishes direct from transitive dependencies and names the top-level package that pulls a vulnerable one in.
- **PEP 792 lifecycle checks** — flags archived, deprecated, and quarantined packages; `--forbid-quarantined` turns known malware into a failing build.
- **Built for CI** — human, JSON, SARIF, and Markdown output; `--fail-on` sets the exit threshold without hiding lower-severity findings.
- **Fast** — a Rust core with async fetching and local caching. See the [benchmarks](benchmarks/results/).

## Used by

PySentry runs in CI pipelines at [Genkit](https://github.com/genkit-ai/genkit) (Google), [OVD-Info](https://ovd.info/en), and [activist.org](https://activist.org), among others.

## Installation

```bash
# Run without installing (recommended)
uvx pysentry-rs

# Or install permanently
pip install pysentry-rs    # PyPI
cargo install pysentry     # crates.io
```

Pre-built binaries are attached to [GitHub Releases](https://github.com/nyudenkov/pysentry/releases). See the [installation guide](https://docs.pysentry.com/getting-started/installation) for all options.

> **Naming:** the Python package installs the binary as `pysentry-rs`; the Rust crate and release binaries are plain `pysentry`. Examples below use `pysentry-rs` — substitute accordingly.

## Quick start

```bash
# Scan the current directory
pysentry-rs

# Scan another project
pysentry-rs /path/to/project

# Report only high and critical findings
pysentry-rs --severity high

# Exit non-zero only for critical findings
pysentry-rs --fail-on critical

# Write a SARIF report for GitHub code scanning
pysentry-rs --format sarif --output results.sarif

# Refuse quarantined (malicious) packages
pysentry-rs --forbid-quarantined
```

More examples in the [quickstart guide](https://docs.pysentry.com/getting-started/quickstart).

## Pre-commit

```yaml
repos:
  - repo: https://github.com/pysentry/pysentry-pre-commit
    rev: v0.4.7
    hooks:
      - id: pysentry
        # args: ['--compact']  # terser output for hook runs
```

## Configuration

Project defaults live in `.pysentry.toml` or `pyproject.toml`; CLI flags always take precedence:

```toml
version = 1

[defaults]
severity = "medium"
fail_on = "high"

[sources]
enabled = ["pypa", "osv"]

[ignore]
ids = ["CVE-2023-12345"]
```

All options are covered in the [configuration guide](https://docs.pysentry.com/configuration/config-files).

## Documentation

Full documentation lives at [docs.pysentry.com](https://docs.pysentry.com):
[Installation](https://docs.pysentry.com/getting-started/installation) ·
[Quickstart](https://docs.pysentry.com/getting-started/quickstart) ·
[CLI options](https://docs.pysentry.com/configuration/cli-options) ·
[Configuration files](https://docs.pysentry.com/configuration/config-files) ·
[Environment variables](https://docs.pysentry.com/configuration/environment-variables) ·
[Troubleshooting](https://docs.pysentry.com/troubleshooting)

## Requirements

- **Python** 3.9–3.14 for the PyPI package
- **Rust** 1.79+ only for `cargo install` or building from source
- **`uv`** (recommended) or **`pip-tools`** for scanning manifests without a lock file (`requirements.txt`, `pyproject.toml`, `Pipfile`) — auditing lock files needs no external tools

## Feedback

Bug reports and feature requests are welcome on the [issue tracker](https://github.com/nyudenkov/pysentry/issues); a couple of minutes on the [usage survey](https://tally.so/r/mYNPNv) helps shape the roadmap. For anything else, reach out at nikita@pysentry.com.

If PySentry saves you time, consider [sponsoring on GitHub](https://github.com/sponsors/nyudenkov) or [buying me a coffee](https://buymeacoffee.com/nyudenkov).

## Acknowledgments

Inspired by [pip-audit](https://github.com/pypa/pip-audit) and [uv #9189](https://github.com/astral-sh/uv/issues/9189). Vulnerability data comes from [PyPA](https://github.com/pypa/advisory-database), [PyPI](https://pypi.org/), and [OSV.dev](https://osv.dev/).

## License

[MIT](LICENSE)
