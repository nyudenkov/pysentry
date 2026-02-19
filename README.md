# PySentry

[![PyPI Downloads](https://static.pepy.tech/badge/pysentry-rs/week)](https://pepy.tech/projects/pysentry-rs)

[Help to test and improve](https://github.com/nyudenkov/pysentry/issues/12) · [Participate in pysentry usage survey](https://tally.so/r/mYNPNv)

Please, send feedback to nikita@pysentry.com

A fast, reliable security vulnerability scanner for Python projects, written in Rust.

PySentry audits Python projects for known security vulnerabilities by analyzing dependency files and cross-referencing them against multiple vulnerability databases.

**[Documentation](https://docs.pysentry.com)** · **[Benchmarks](benchmarks/results/)** · **[Buy Me a Coffee](https://buymeacoffee.com/nyudenkov)**

## Features

- **Multiple formats** — `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pylock.toml`, `pyproject.toml`, `Pipfile`, `requirements.txt`
- **Multiple sources** — PyPA Advisory Database, PyPI JSON API, OSV.dev (all enabled by default)
- **PEP 792 support** — Detects archived, deprecated, and quarantined packages
- **Flexible output** — Human-readable, JSON, SARIF, Markdown
- **Fast** — Written in Rust with async processing and caching

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

```bash
# Scan current directory
pysentry

# Scan specific project
pysentry /path/to/project

# Filter by severity
pysentry --severity high

# Output to JSON
pysentry --format json --output report.json

# Fail on critical vulnerabilities only
pysentry --fail-on critical

# Block quarantined packages (malware protection)
pysentry --forbid-quarantined
```

See [Quickstart Guide](https://docs.pysentry.com/getting-started/quickstart) for more examples.

## Pre-commit

```yaml
repos:
  - repo: https://github.com/pysentry/pysentry-pre-commit
    rev: v0.4.1
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

## Acknowledgments

- Inspired by [pip-audit](https://github.com/pypa/pip-audit) and [uv #9189](https://github.com/astral-sh/uv/issues/9189)
- Vulnerability data from [PyPA](https://github.com/pypa/advisory-database), [PyPI](https://pypi.org/), and [OSV.dev](https://osv.dev/)
