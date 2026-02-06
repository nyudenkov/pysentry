---
sidebar_position: 1
slug: /
---

# Introduction

**PySentry** is a fast, reliable security vulnerability scanner for Python projects, written in Rust.

## Overview

PySentry audits Python projects for known security vulnerabilities by analyzing dependency files and cross-referencing them against multiple vulnerability databases. It provides comprehensive reporting with support for various output formats and filtering options.

## Key Features

- **Multiple Project Formats**: Supports `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pylock.toml`, `pyproject.toml`, `Pipfile`, and `requirements.txt` files
- **External Resolver Integration**: Leverages `uv` and `pip-tools` for accurate requirements.txt constraint solving
- **Multiple Data Sources** (all sources used by default):
  - PyPA Advisory Database
  - PyPI JSON API
  - OSV.dev (Open Source Vulnerabilities)
- **PEP 792 Project Status Markers**: Detects archived, deprecated, and quarantined packages
- **Flexible Output for different workflows**: Human-readable, JSON, SARIF, and Markdown formats
- **Performance Focused**:
  - Written in Rust for speed
  - Async/concurrent processing
  - Multi-tier intelligent caching (vulnerability data + resolved dependencies)
- **Comprehensive Filtering**:
  - Severity levels (low, medium, high, critical, unknown)
  - Dependency scopes (main only vs all dependencies)
  - Direct vs. transitive dependencies
- **CI/CD Ready**: Exit codes, JSON output, and GitHub Actions annotations for pipeline integration

## Why PySentry?

PySentry combines the reliability of established tools with the performance benefits of Rust:

1. **Speed**: Concurrent processing and intelligent caching make PySentry significantly faster than Python-based alternatives
2. **Accuracy**: Uses multiple vulnerability sources for comprehensive coverage
3. **Flexibility**: Works with all major Python dependency management tools
4. **CI/CD Ready**: Multiple output formats and exit codes designed for automation

## Quick Example

```bash
# Scan current directory
pysentry

# Scan specific project
pysentry /path/to/project

# Generate JSON report
pysentry --format json --output report.json

# Only fail on critical vulnerabilities
pysentry --fail-on critical
```

## Getting Help

- [GitHub Issues](https://github.com/nyudenkov/pysentry/issues) - Bug reports and feature requests
- [GitHub Discussions](https://github.com/nyudenkov/pysentry/discussions) - Questions and discussions
- Email: nikita@pysentry.com
