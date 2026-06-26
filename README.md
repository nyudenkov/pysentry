<div align="center">

<img src="assets/logo.svg" alt="PySentry logo" width="96" height="96">

# PySentry

**A fast and reliable security vulnerability scanner for Python projects.**

[![PyPI Downloads](https://static.pepy.tech/badge/pysentry-rs/week)](https://pepy.tech/projects/pysentry-rs)

[Help to test and improve](https://github.com/nyudenkov/pysentry/issues/12) · [Participate in pysentry usage survey](https://tally.so/r/mYNPNv)

</div>

PySentry scans Python projects for known security vulnerabilities by reading your dependency files and cross-referencing them against multiple vulnerability databases.

**[Documentation](https://docs.pysentry.com)** · **[Benchmarks](benchmarks/results/)** · **[Buy Me a Coffee](https://buymeacoffee.com/nyudenkov)**

## Features

- **Multiple file formats** — reads `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pylock.toml`, `pyproject.toml`, `Pipfile`, and `requirements.txt`
- **Three vulnerability databases** — PyPA Advisory Database, PyPI JSON API, and OSV.dev, all queried by default
- **PEP 792 support** — detects archived, deprecated, and quarantined packages, and can block quarantined ones
- **Multiple output formats** — human-readable, JSON, SARIF, and Markdown
- **Fast** — a Rust core with async fetching and local caching

## Used by

PySentry runs in CI pipelines at projects like:

- [Genkit](https://github.com/genkit-ai/genkit) (Google)
- [OVD-Info](https://ovd.info/en)
- [activist.org](https://activist.org)

## Installation

```bash
# Using uvx (recommended)
uvx pysentry-rs /path/to/project

# Using pip
pip install pysentry-rs

# Using cargo
cargo install pysentry

# Pre-built binaries available at GitHub Releases
```

See [Installation Guide](https://docs.pysentry.com/getting-started/installation) for all options.

## Quick Start

> **Note:** Examples use `pysentry-rs`. If you installed via `cargo install pysentry` or a binary release, replace it with `pysentry` throughout.

```bash
# Scan current directory
pysentry-rs

# Scan specific project
pysentry-rs /path/to/project

# Filter by severity
pysentry-rs --severity high

# Output to JSON
pysentry-rs --format json --output report.json

# Fail on critical vulnerabilities only
pysentry-rs --fail-on critical

# Block quarantined packages (malware protection)
pysentry-rs --forbid-quarantined
```

See [Quickstart Guide](https://docs.pysentry.com/getting-started/quickstart) for more examples.

## Pre-commit

```yaml
repos:
  - repo: https://github.com/pysentry/pysentry-pre-commit
    rev: v0.4.7
    hooks:
      - id: pysentry
        # Use compact mode for minimal pre-commit output
        # args: ['--compact']
```

## Configuration

PySentry supports TOML configuration via `.pysentry.toml` or `pyproject.toml`:

```toml
# .pysentry.toml
version = 1

[defaults]
severity = "medium"
fail_on = "high"

[sources]
enabled = ["pypa", "osv"]

[ignore]
ids = ["CVE-2023-12345"]
```

See [Configuration Guide](https://docs.pysentry.com/configuration/config-files) for all options.

## Documentation

Full documentation is available at **[docs.pysentry.com](https://docs.pysentry.com)**:

- [Installation](https://docs.pysentry.com/getting-started/installation)
- [Quickstart](https://docs.pysentry.com/getting-started/quickstart)
- [CLI Options](https://docs.pysentry.com/configuration/cli-options)
- [Configuration Files](https://docs.pysentry.com/configuration/config-files)
- [Environment Variables](https://docs.pysentry.com/configuration/environment-variables)
- [Troubleshooting](https://docs.pysentry.com/troubleshooting)

## Requirements

- **For `requirements.txt` scanning**: Install `uv` (recommended) or `pip-tools` for dependency resolution
- **Python**: 3.9–3.14 (for pip/uvx installation)
- **Rust**: 1.79+ (for cargo installation or building from source)

## Feedback

Bug reports and feature requests are welcome on the [issue tracker](https://github.com/nyudenkov/pysentry/issues). For anything else, reach out at nikita@pysentry.com.

## Acknowledgments

- Inspired by [pip-audit](https://github.com/pypa/pip-audit) and [uv #9189](https://github.com/astral-sh/uv/issues/9189)
- Vulnerability data from [PyPA](https://github.com/pypa/advisory-database), [PyPI](https://pypi.org/), and [OSV.dev](https://osv.dev/)
