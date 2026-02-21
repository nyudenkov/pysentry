---
sidebar_position: 2
---

# Quick Start

Get started with PySentry in minutes.

## Basic Usage

```bash
# Using uvx (recommended for occasional use)
uvx pysentry-rs
uvx pysentry-rs /path/to/python/project

# Using installed binary
pysentry
pysentry /path/to/python/project

# Automatically detects project type (uv.lock, poetry.lock, Pipfile.lock, pylock.toml, pyproject.toml, Pipfile, requirements.txt)
pysentry /path/to/project

# Force specific resolver
pysentry --resolver uv /path/to/project
pysentry --resolver pip-tools /path/to/project

# Exclude extra dependencies (only check main dependencies)
pysentry --exclude-extra

# Only fail on high and critical vulnerabilities
pysentry --fail-on high

# Output to JSON file
pysentry --format json --output audit-results.json
```

## Advanced Usage

```bash
# Use specific vulnerability sources (all sources used by default)
uvx pysentry-rs --sources pypa /path/to/project
uvx pysentry-rs --sources pypa --sources osv /path/to/project

# Generate markdown report
uvx pysentry-rs --format markdown --output security-report.md

# Control CI exit codes - only fail on critical vulnerabilities
uvx pysentry-rs --fail-on critical

# Or with installed binary (extras included by default)
pysentry --sources pypa,osv --direct-only
pysentry --format markdown --output security-report.md

# Ignore specific vulnerabilities
pysentry --ignore CVE-2023-12345 --ignore GHSA-xxxx-yyyy-zzzz

# Ignore unfixable vulnerabilities (only while they have no fix available)
pysentry --ignore-while-no-fix CVE-2025-8869

# Fail on unmaintained packages (archived, deprecated, or quarantined)
pysentry --forbid-unmaintained

# Fail only on quarantined packages (malware/compromised)
pysentry --forbid-quarantined

# Check maintenance status for direct dependencies only
pysentry --forbid-unmaintained --maintenance-direct-only

# Don't fail on vulnerabilities with unknown severity
pysentry --no-fail-on-unknown

# Disable caching for CI environments
pysentry --no-cache

# Verbose output for debugging (-v for warnings, -vv for info, -vvv for debug)
pysentry -v
pysentry -vv
```

## Requirements.txt Usage

```bash
# Scan multiple requirements files
pysentry --requirements-files requirements.txt requirements-dev.txt

# Check only direct dependencies from requirements.txt
pysentry --direct-only --resolver uv

# Ensure resolver is available in your environment
source venv/bin/activate  # Activate your virtual environment first
pysentry /path/to/project

# Debug requirements.txt resolution
pysentry --verbose --resolver uv /path/to/project

# Use longer resolution cache TTL (48 hours)
pysentry --resolution-cache-ttl 48 /path/to/project

# Clear resolution cache before scanning
pysentry --clear-resolution-cache /path/to/project
```

## Understanding Output

PySentry reports vulnerabilities with:

- **Package name and version**: The affected dependency
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
