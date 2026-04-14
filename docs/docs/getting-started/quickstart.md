---
sidebar_position: 2
---

# Quick Start

Get started with PySentry in minutes.

:::note
Examples use `pysentry-rs`. If you installed via `cargo install pysentry` or a binary release, replace it with `pysentry` throughout.
:::

## Basic Usage

```bash
# Run without installing (recommended for occasional use)
uvx pysentry-rs /path/to/python/project

# If installed via pip
pysentry-rs
pysentry-rs /path/to/python/project

# Automatically detects project type (uv.lock, poetry.lock, Pipfile.lock, pylock.toml, pyproject.toml, Pipfile, requirements.txt)
pysentry-rs /path/to/project

# Force specific resolver
pysentry-rs --resolver uv /path/to/project
pysentry-rs --resolver pip-tools /path/to/project

# Exclude extra dependencies (only check main dependencies)
pysentry-rs --exclude-extra

# Only fail on high and critical vulnerabilities
pysentry-rs --fail-on high

# Output to JSON file
pysentry-rs --format json --output audit-results.json
```

## Advanced Usage

```bash
# Use specific vulnerability sources (all sources used by default)
pysentry-rs --sources pypa /path/to/project
pysentry-rs --sources pypa --sources osv /path/to/project

# Generate markdown report
pysentry-rs --format markdown --output security-report.md

# Control CI exit codes - only fail on critical vulnerabilities
pysentry-rs --fail-on critical

# Extras included by default
pysentry-rs --sources pypa,osv --direct-only

# Ignore specific vulnerabilities
pysentry-rs --ignore CVE-2023-12345 --ignore GHSA-xxxx-yyyy-zzzz

# Ignore unfixable vulnerabilities (only while they have no fix available)
pysentry-rs --ignore-while-no-fix CVE-2025-8869

# Fail on unmaintained packages (archived, deprecated, or quarantined)
pysentry-rs --forbid-unmaintained

# Fail only on quarantined packages (malware/compromised)
pysentry-rs --forbid-quarantined

# Check maintenance status for direct dependencies only
pysentry-rs --forbid-unmaintained --maintenance-direct-only

# Don't fail on vulnerabilities with unknown severity
pysentry-rs --no-fail-on-unknown

# Disable caching for CI environments
pysentry-rs --no-cache

# Force colors for piped output or log capture
pysentry-rs --color always

# Disable colors (useful in plain-text environments or scripts)
pysentry-rs --color never

# Compact output with table layout (default)
pysentry-rs --compact

# Compact output with traditional text layout
pysentry-rs --compact --display text

# Verbose output for debugging (-v for warnings, -vv for info, -vvv for debug)
pysentry-rs -v
pysentry-rs -vv
```

## Requirements.txt Usage

```bash
# Scan multiple requirements files
pysentry-rs --requirements-files requirements.txt requirements-dev.txt

# Check only direct dependencies from requirements.txt
pysentry-rs --direct-only --resolver uv

# Ensure resolver is available in your environment
source venv/bin/activate  # Activate your virtual environment first
pysentry-rs /path/to/project

# Debug requirements.txt resolution
pysentry-rs --verbose --resolver uv /path/to/project

# Use longer resolution cache TTL (48 hours)
pysentry-rs --resolution-cache-ttl 48 /path/to/project

# Clear resolution cache before scanning
pysentry-rs --clear-resolution-cache /path/to/project
```

## Understanding Output

PySentry reports vulnerabilities with:

- **Package name and version**: The affected dependency
- **Dependency type**: `[direct]` or `[transitive]` tag on each vulnerability entry
- **Vulnerability ID**: CVE, GHSA, or PYSEC identifier
- **Severity**: Critical, High, Medium, Low, or Unknown
- **Description**: Brief explanation of the vulnerability
- **Fix version**: Recommended version to upgrade to (when available)
- **Source file**: Which dependency file contains the vulnerable package

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found at or above the `--fail-on` threshold |
| 1 | Vulnerabilities found at or above the `--fail-on` threshold, or error during execution |

Note: Both vulnerability detection and errors result in exit code 1. Use verbose output (`-v`) to distinguish between them.

## Next Steps

- [Configure PySentry](/configuration/config-files) with a configuration file
- Explore [CLI options](/configuration/cli-options) for output formats and more
- Read about [why scanning is essential](/why-scan)
