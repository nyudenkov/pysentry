---
sidebar_position: 3
---

# Command Line Options

Complete reference for all PySentry command line options.

## General Options

| Option | Description | Default |
|--------|-------------|---------|
| `[PATH]` | Path to project directory | Current directory |
| `--format` | Output format: `human`, `json`, `sarif`, `markdown` | `human` |
| `-o`, `--output` | Output file path | stdout |
| `-v`, `--verbose` | Increase verbosity: `-v` (warn), `-vv` (info), `-vvv` (debug), `-vvvv` (trace) | error level |
| `-q`, `--quiet` | Suppress all output | `false` |
| `--config` | Custom configuration file path | Auto-discovered |
| `--no-config` | Disable configuration file loading | `false` |
| `--include-withdrawn` | Include withdrawn vulnerabilities | `false` |
| `--help` | Display help information | - |
| `--version` | Display version information | - |

## Filtering Options

| Option | Description | Default |
|--------|-------------|---------|
| `--severity` | Minimum severity: `low`, `medium`, `high`, `critical` | `low` |
| `--fail-on` | Fail (exit non-zero) on vulnerabilities >= severity | `medium` |
| `--sources` | Vulnerability sources: `pypa`, `pypi`, `osv` (multiple) | `pypa,pypi,osv` |
| `--exclude-extra` | Exclude extra dependencies (dev, optional, etc) | `false` |
| `--direct-only` | Check only direct dependencies | `false` |
| `--detailed` | Show full vulnerability descriptions | `false` |
| `--no-fail-on-unknown` | Don't fail on vulnerabilities with unknown severity | `false` |

## Ignore Options

| Option | Description | Default |
|--------|-------------|---------|
| `--ignore` | Vulnerability IDs to ignore (repeatable) | `[]` |
| `--ignore-while-no-fix` | Ignore vulnerabilities only while no fix is available | `[]` |

## Cache Options

| Option | Description | Default |
|--------|-------------|---------|
| `--no-cache` | Disable all caching | `false` |
| `--cache-dir` | Custom cache directory | Platform-specific |
| `--resolution-cache-ttl` | Resolution cache TTL in hours | `24` |
| `--no-resolution-cache` | Disable resolution caching only | `false` |
| `--clear-resolution-cache` | Clear resolution cache on startup | `false` |

## Resolver Options

| Option | Description | Default |
|--------|-------------|---------|
| `--resolver` | Dependency resolver: `uv`, `pip-tools` | `uv` |
| `--requirements-files` | Specific requirements files to audit (disables auto-discovery, repeatable) | `[]` |

## Maintenance Options

| Option | Description | Default |
|--------|-------------|---------|
| `--no-maintenance-check` | Disable PEP 792 project status checks | `false` |
| `--forbid-archived` | Fail on archived packages | `false` |
| `--forbid-deprecated` | Fail on deprecated packages | `false` |
| `--forbid-quarantined` | Fail on quarantined packages (malware/compromised) | `false` |
| `--forbid-unmaintained` | Fail on any unmaintained packages | `false` |
| `--maintenance-direct-only` | Only check direct dependencies for maintenance status | `false` |

## CI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--no-ci-detect` | Disable automatic CI environment detection | `false` |

## Subcommands

### Config Subcommand

```bash
pysentry config <COMMAND>
```

| Command | Description |
|---------|-------------|
| `init` | Generate a configuration file |
| `show` | Display current configuration |
| `validate` | Validate configuration file |
| `path` | Show configuration file path |

#### Config Init Options

```bash
pysentry config init [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-o`, `--output` | Output file path (default: stdout) |
| `--force` | Overwrite existing configuration file |
| `--minimal` | Generate minimal configuration with only essential options |

### Resolvers Subcommand

Check available dependency resolvers:

```bash
pysentry resolvers
```

Shows which resolvers (`uv`, `pip-tools`) are installed and available for requirements resolution.

### Check-Version Subcommand

Check for newer PySentry versions:

```bash
pysentry check-version
```

Compares installed version with the latest available release.

## Usage Examples

### Basic Scanning

```bash
# Scan current directory
pysentry

# Scan specific project
pysentry /path/to/project

# Scan with JSON output
pysentry --format json --output results.json
```

### Filtering

```bash
# Only show high and critical vulnerabilities
pysentry --severity high

# Only fail on critical vulnerabilities
pysentry --fail-on critical

# Use specific vulnerability sources
pysentry --sources pypa --sources osv
```

### Ignoring Vulnerabilities

```bash
# Ignore specific vulnerabilities
pysentry --ignore CVE-2023-12345 --ignore GHSA-xxxx-yyyy-zzzz

# Ignore vulnerabilities without fixes
pysentry --ignore-while-no-fix CVE-2025-8869
```

### Cache Control

```bash
# Disable all caching
pysentry --no-cache

# Clear resolution cache before scanning
pysentry --clear-resolution-cache

# Use custom cache directory
pysentry --cache-dir /tmp/pysentry-cache
```

### Requirements.txt

```bash
# Specify requirements files explicitly (disables auto-discovery)
pysentry --requirements-files requirements-dev.txt requirements-test.txt

# Force specific resolver
pysentry --resolver uv
```

### Maintenance Checks

```bash
# Fail on quarantined packages only
pysentry --forbid-quarantined

# Fail on any unmaintained package
pysentry --forbid-unmaintained

# Check only direct dependencies
pysentry --forbid-unmaintained --maintenance-direct-only
```

### CI/CD

```bash
# PySentry auto-detects GitHub Actions and emits native annotations
# No extra flags needed — just run pysentry

# Disable CI detection (run as if locally)
pysentry --no-ci-detect

# Don't fail on unknown severity vulnerabilities
pysentry --no-fail-on-unknown
```

### Debugging

```bash
# Verbose output (warnings)
pysentry -v

# More verbose (info level)
pysentry -vv

# Debug output
pysentry -vvv

# Maximum verbosity (trace)
pysentry -vvvv
```
