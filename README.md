# 🐍 PySentry

[![OSV Integration](https://img.shields.io/badge/OSV-Integrated-blue)](https://google.github.io/osv.dev/)
[![PyPI Downloads](https://static.pepy.tech/badge/pysentry-rs/week)](https://pepy.tech/projects/pysentry-rs)

[Help to test and improve](https://github.com/nyudenkov/pysentry/issues/12) | [Latest PySentry - pip-audit benchmark](benchmarks/results/latest.md)

Please, send feedback to nikita@pysentry.com

A fast, reliable security vulnerability scanner for Python projects, written in Rust.

## Overview

PySentry audits Python projects for known security vulnerabilities by analyzing dependency files (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `pylock.toml`, `pyproject.toml`, `Pipfile`, `requirements.txt`) and cross-referencing them against multiple vulnerability databases. It provides comprehensive reporting with support for various output formats and filtering options.

## Key Features

- **Multiple Project Formats**: Supports `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pylock.toml`, `pyproject.toml`, `Pipfile`, and `requirements.txt` files
- **External Resolver Integration**: Leverages `uv` and `pip-tools` for accurate requirements.txt constraint solving
- **Multiple Data Sources**:
  - PyPA Advisory Database (default)
  - PyPI JSON API
  - OSV.dev (Open Source Vulnerabilities)
- **Flexible Output for different workflows**: Human-readable, JSON, SARIF, and Markdown formats
- **Performance Focused**:
  - Written in Rust for speed
  - Async/concurrent processing
  - Multi-tier intelligent caching (vulnerability data + resolved dependencies)
- **Comprehensive Filtering**:
  - Severity levels (low, medium, high, critical)
  - Dependency scopes (main only vs all [optional, dev, prod, etc] dependencies)
  - Direct vs. transitive dependencies
- **Enterprise Ready**: SARIF output for IDE/CI integration

## Installation

Choose the installation method that works best for you:

### ⚡ Via uvx (Recommended for occasional use)

Run directly without installing (requires [uv](https://docs.astral.sh/uv/)):

```bash
uvx pysentry-rs /path/to/project
```

This method:

- Runs the latest version without installation
- Automatically manages Python environment
- Perfect for CI/CD or occasional security audits
- No need to manage package versions or updates

### 📦 From PyPI (Python Package)

For Python 3.8+ on Linux and macOS:

```bash
pip install pysentry-rs
```

Then use it with Python:

```bash
python -m pysentry /path/to/project
# or directly if scripts are in PATH
pysentry-rs /path/to/project
```

### ⚡ From Crates.io (Rust Package)

If you have Rust installed:

```bash
cargo install pysentry
```

### 💾 From GitHub Releases (Pre-built Binaries)

Download the latest release for your platform:

- **Linux x64**: `pysentry-linux-x64.tar.gz`
- **Linux x64 (musl)**: `pysentry-linux-x64-musl.tar.gz`
- **Linux ARM64**: `pysentry-linux-arm64.tar.gz`
- **macOS x64**: `pysentry-macos-x64.tar.gz`
- **macOS ARM64**: `pysentry-macos-arm64.tar.gz`
- **Windows x64**: `pysentry-windows-x64.zip`

```bash
# Example for Linux x64
curl -L https://github.com/nyudenkov/pysentry/releases/latest/download/pysentry-linux-x64.tar.gz | tar -xz
./pysentry-linux-x64/pysentry --help
```

### 🔧 From Source

```bash
git clone https://github.com/nyudenkov/pysentry
cd pysentry
cargo build --release
```

The binary will be available at `target/release/pysentry`.

### Requirements

- **For uvx**: Python 3.8+ and [uv](https://docs.astral.sh/uv/) installed (Linux/macOS only)
- **For binaries**: No additional dependencies
- **For Python package**: Python 3.8+ (Linux/macOS only)
- **For Rust package and source**: Rust 1.79+

### Platform Support

| Installation Method | Linux | macOS | Windows |
| ------------------- | ----- | ----- | ------- |
| uvx                 | ✅    | ✅    | ❌      |
| PyPI (pip)          | ✅    | ✅    | ❌      |
| Crates.io (cargo)   | ✅    | ✅    | ✅      |
| GitHub Releases     | ✅    | ✅    | ✅      |
| From Source         | ✅    | ✅    | ✅      |

**Note**: Windows Python wheels are not available due to compilation complexity. Windows users should use the pre-built binary from GitHub releases, install via cargo and build from source.

### CLI Command Names

- **Rust binary**: `pysentry` (when installed via cargo or binary releases)
- **Python package**: `pysentry-rs` (when installed via pip or uvx)

Both variants support identical functionality. The resolver tools (`uv`, `pip-tools`) must be available in your current environment regardless of which PySentry variant you use.

### Requirements.txt Support Prerequisites

To scan `requirements.txt` files, PySentry requires an external dependency resolver to convert version constraints (e.g., `flask>=2.0,<3.0`) into exact versions for vulnerability scanning.

**Install a supported resolver:**

```bash
# uv (recommended - fastest, Rust-based)
pip install uv

# pip-tools (widely compatible, Python-based)
pip install pip-tools
```

**Environment Requirements:**

- Resolvers must be available in your current environment
- If using virtual environments, activate your venv before running PySentry:
  ```bash
  source venv/bin/activate  # Linux/macOS
  venv\Scripts\activate     # Windows
  pysentry /path/to/project
  ```
- Alternatively, install resolvers globally for system-wide availability

**Auto-detection:** PySentry automatically detects and prefers: `uv` > `pip-tools`. Without a resolver, only `uv.lock` and `poetry.lock` files can be scanned.

## Quick Start

### Basic Usage

```bash
# Using uvx (recommended for occasional use)
uvx pysentry-rs
uvx pysentry-rs /path/to/python/project

# Using installed binary
pysentry
pysentry /path/to/python/project

# Automatically detects project type (uv.lock, poetry.lock, Pipfile.lock, pyproject.toml, Pipfile, requirements.txt)
pysentry /path/to/project

# Force specific resolver
pysentry --resolver uv /path/to/project
pysentry --resolver pip-tools /path/to/project

# Include all dependencies (main + dev + optional)
pysentry --all-extras

# Filter by severity (only show high and critical)
pysentry --severity high

# Output to JSON file
pysentry --format json --output audit-results.json
```

### Advanced Usage

```bash
# Using uvx for comprehensive audit
uvx pysentry-rs --all-extras --format sarif --output security-report.sarif

# Check multiple vulnerability sources concurrently
uvx pysentry-rs --sources pypa,osv,pypi /path/to/project
uvx pysentry-rs --sources pypa --sources osv --sources pypi

# Generate markdown report
uvx pysentry-rs --format markdown --output security-report.md

# Control CI exit codes - only fail on critical vulnerabilities
uvx pysentry-rs --fail-on critical

# Or with installed binary
pysentry --all-extras --format sarif --output security-report.sarif
pysentry --sources pypa,osv --direct-only
pysentry --format markdown --output security-report.md

# Ignore specific vulnerabilities
pysentry --ignore CVE-2023-12345 --ignore GHSA-xxxx-yyyy-zzzz

# Disable caching for CI environments
pysentry --no-cache

# Verbose output for debugging
pysentry --verbose
```

### Advanced Requirements.txt Usage

```bash
# Scan multiple requirements files
pysentry --requirements requirements.txt --requirements requirements-dev.txt

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

### CI/CD Integration Examples

```bash
# Development environment - only fail on critical vulnerabilities
pysentry --fail-on critical --format json --output security-report.json

# Staging environment - fail on high+ vulnerabilities
pysentry --fail-on high --sources pypa,osv --format sarif --output security.sarif

# Production deployment - strict security (fail on medium+, default)
pysentry --sources pypa,pypi,osv --format json --output prod-security.json

# Generate markdown report for GitHub issues/PRs
pysentry --format markdown --output SECURITY-REPORT.md

# Comprehensive audit with all sources and full reporting
pysentry --sources pypa,pypi,osv --all-extras --format json --fail-on low

# CI environment with fresh resolution cache
pysentry --clear-resolution-cache --sources pypa,osv --format sarif

# CI with resolution cache disabled
pysentry --no-resolution-cache --format json --output security-report.json
```

## Pre-commit Integration

PySentry integrates seamlessly with [pre-commit](https://pre-commit.com/) to automatically scan for vulnerabilities before commits.

### Setup

Add PySentry to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/pysentry/pysentry-pre-commit
    rev: v0.3.6
    hooks:
      - id: pysentry # default pysentry settings
```

### Advanced Configuration

```yaml
repos:
  - repo: https://github.com/pysentry/pysentry-pre-commit
    rev: v0.3.6
    hooks:
      - id: pysentry
        args: ["--sources", "pypa,osv", "--fail-on", "high"]
```

### Installation Requirements

Pre-commit will automatically install PySentry, uv and pip-tools via PyPI.

## Configuration

PySentry supports TOML-based configuration files for persistent settings management. Configuration files follow a hierarchical discovery pattern:

1. **Project-level**: `.pysentry.toml` in current or parent directories
2. **User-level**: `~/.config/pysentry/config.toml` (Linux/macOS)
3. **System-level**: `/etc/pysentry/config.toml` (Unix systems)

### Configuration File Example

```toml
version = 1

[defaults]
format = "json"
severity = "medium"
fail_on = "high"
scope = "all"
direct_only = false

[sources]
enabled = ["pypa", "osv"]

[resolver]
type = "uv"
fallback = "pip-tools"

[cache]
enabled = true
resolution_ttl = 48
vulnerability_ttl = 72

[output]
quiet = false
verbose = false
color = "auto"

[ignore]
ids = ["CVE-2023-12345", "GHSA-xxxx-yyyy-zzzz"]
```

### Environment Variables

| Variable             | Description                     | Example                                |
| -------------------- | ------------------------------- | -------------------------------------- |
| `PYSENTRY_CONFIG`    | Override config file path       | `PYSENTRY_CONFIG=/path/to/config.toml` |
| `PYSENTRY_NO_CONFIG` | Disable all config file loading | `PYSENTRY_NO_CONFIG=1`                 |

### Command Line Options

| Option                     | Description                                               | Default           |
| -------------------------- | --------------------------------------------------------- | ----------------- |
| `--format`                 | Output format: `human`, `json`, `sarif`, `markdown`       | `human`           |
| `--severity`               | Minimum severity: `low`, `medium`, `high`, `critical`     | `low`             |
| `--fail-on`                | Fail (exit non-zero) on vulnerabilities ≥ severity        | `medium`          |
| `--sources`                | Vulnerability sources: `pypa`, `pypi`, `osv` (multiple)   | `pypa`            |
| `--all-extras`             | Include all dependencies (main + dev + optional)          | `false`           |
| `--direct-only`            | Check only direct dependencies                            | `false`           |
| `--detailed`               | Show full vulnerability descriptions instead of truncated | `false`           |
| `--ignore`                 | Vulnerability IDs to ignore (repeatable)                  | `[]`              |
| `--output`                 | Output file path                                          | `stdout`          |
| `--no-cache`               | Disable all caching                                       | `false`           |
| `--cache-dir`              | Custom cache directory                                    | Platform-specific |
| `--resolution-cache-ttl`   | Resolution cache TTL in hours                             | `24`              |
| `--no-resolution-cache`    | Disable resolution caching only                           | `false`           |
| `--clear-resolution-cache` | Clear resolution cache on startup                         | `false`           |
| `--verbose`                | Enable verbose output                                     | `false`           |
| `--quiet`                  | Suppress non-error output                                 | `false`           |
| `--resolver`               | Dependency resolver: `auto`, `uv`, `pip-tools`            | `auto`            |
| `--requirements`           | Additional requirements files (repeatable)                | `[]`              |

### Cache Management

PySentry uses an intelligent multi-tier caching system for optimal performance:

#### Vulnerability Data Cache

- **Location**: `{CACHE_DIR}/pysentry/vulnerability-db/`
- **Purpose**: Caches vulnerability databases from PyPA, PyPI, OSV
- **TTL**: 24 hours (configurable per source)
- **Benefits**: Avoids redundant API calls and downloads

#### Resolution Cache

- **Location**: `{CACHE_DIR}/pysentry/dependency-resolution/`
- **Purpose**: Caches resolved dependencies from `uv`/`pip-tools`
- **TTL**: 24 hours (configurable via `--resolution-cache-ttl`)
- **Benefits**: Dramatically speeds up repeated scans of requirements.txt files
- **Cache Key**: Based on requirements content, resolver version, Python version, platform

#### Platform-Specific Cache Locations

- **Linux**: `~/.cache/pysentry/`
- **macOS**: `~/Library/Caches/pysentry/`
- **Windows**: `%LOCALAPPDATA%\pysentry\`

**Finding Your Cache Location**: Run with `--verbose` to see the actual cache directory path being used.

#### Cache Features

- **Atomic Updates**: Prevents cache corruption during concurrent access
- **Custom Location**: Use `--cache-dir` to specify alternative location
- **Selective Clearing**: Control caching behavior per cache type
- **Content-based Invalidation**: Automatic cache invalidation on content changes

#### Cache Control Examples

```bash
# Disable all caching
pysentry --no-cache

# Disable only resolution caching (keep vulnerability cache)
pysentry --no-resolution-cache

# Set resolution cache TTL to 48 hours
pysentry --resolution-cache-ttl 48

# Clear resolution cache on startup (useful for CI)
pysentry --clear-resolution-cache

# Custom cache directory
pysentry --cache-dir /tmp/my-pysentry-cache
```

To manually clear all caches:

```bash
# Linux
rm -rf ~/.cache/pysentry/

# macOS
rm -rf ~/Library/Caches/pysentry/

# Windows (PowerShell)
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\pysentry"
```

To clear only resolution cache:

```bash
# Linux
rm -rf ~/.cache/pysentry/dependency-resolution/

# macOS
rm -rf ~/Library/Caches/pysentry/dependency-resolution/

# Windows (PowerShell)
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\pysentry\dependency-resolution"
```

## Supported Project Formats

### uv.lock Files (Recommended)

PySentry has support for `uv.lock` files:

- Exact version resolution
- Complete dependency graph analysis
- Source tracking
- Dependency classification (main, dev, optional) including transitive dependencies

### poetry.lock Files

Full support for Poetry lock files:

- **Exact Version Resolution**: Scans exact dependency versions locked by Poetry
- **Lock-File Only Analysis**: Relies purely on the lock file structure, no pyproject.toml parsing needed
- **Complete Dependency Tree**: Analyzes all resolved dependencies including transitive ones
- **Dependency Classification**: Distinguishes between main dependencies and optional groups (dev, test, etc.)
- **Source Tracking**: Supports PyPI registry, Git repositories, local paths, and direct URLs

**Key Features:**

- No external tools required
- Fast parsing with exact version information
- Handles Poetry's dependency groups and optional dependencies
- Perfect for Poetry-managed projects with established lock files

### Pipfile.lock Files

Full support for Pipenv lock files with exact version resolution:

- **Exact Version Resolution**: Scans exact dependency versions locked by Pipenv
- **Lock-File Only Analysis**: Relies purely on the lock file structure, no Pipfile parsing needed
- **Complete Dependency Tree**: Analyzes all resolved dependencies including transitive ones
- **Dependency Classification**: Distinguishes between default dependencies and development groups

**Key Features:**

- No external tools required
- Fast parsing with exact version information
- Handles Pipenv's dependency groups (default and develop)
- Perfect for Pipenv-managed projects with established lock files

### Pipfile Files (External Resolution)

Support for Pipfile specification files using external dependency resolvers:

**Key Features:**

- **Dependencies Resolution**: Converts version constraints from Pipfile to exact versions using mature external tools
- **Multiple Resolver Support**:
  - **uv**: Rust-based resolver, extremely fast and reliable (recommended)
  - **pip-tools**: Python-based resolver using `pip-compile`, widely compatible
- **Auto-detection**: Automatically detects and uses the best available resolver in your environment
- **Dependency Groups**: Supports both default packages and dev-packages sections
- **Complex Constraint Handling**: Supports version ranges, Git dependencies, and environment markers

**Resolution Workflow:**

1. Detects `Pipfile` in your project (when `Pipfile.lock` is not present)
2. Auto-detects available resolver (`uv` or `pip-tools`) in current environment
3. Resolves version constraints to exact dependency versions
4. Scans resolved dependencies for vulnerabilities
5. Reports findings with dependency group classification

**Note**: When both `Pipfile` and `Pipfile.lock` are present, PySentry prioritizes the lock file for better accuracy. Consider using `pipenv lock` to generate a lock file for the most precise vulnerability scanning.

### requirements.txt Files (External Resolution)

Advanced support for `requirements.txt` files using external dependency resolvers:

**Key Features:**

- **Dependencies Resolution**: Converts version constraints (e.g., `flask>=2.0,<3.0`) to exact versions using mature external tools
- **Multiple Resolver Support**:
  - **uv**: Rust-based resolver, extremely fast and reliable (recommended)
  - **pip-tools**: Python-based resolver using `pip-compile`, widely compatible
- **Auto-detection**: Automatically detects and uses the best available resolver in your environment
- **Multiple File Support**: Combines `requirements.txt`, `requirements-dev.txt`, `requirements-test.txt`, etc.
- **Dependency Classification**: Distinguishes between direct and transitive dependencies
- **Isolated Execution**: Resolvers run in temporary directories to prevent project pollution
- **Complex Constraint Handling**: Supports version ranges, extras, environment markers, and conflict resolution

**Resolution Workflow:**

1. Detects `requirements.txt` files in your project
2. Auto-detects available resolver (`uv` or `pip-tools`) in current environment
3. Resolves version constraints to exact dependency versions
4. Scans resolved dependencies for vulnerabilities
5. Reports findings with direct vs. transitive classification

**Environment Setup:**

```bash
# Ensure resolver is available in your environment
source venv/bin/activate      # Activate virtual environment
pip install uv               # Install preferred resolver
pysentry /path/to/project    # Run security scan
```

### pyproject.toml Files (External Resolution)

Support for projects without lock files:

- Parses version constraints from `pyproject.toml`
- **Resolver Required**: Like requirements.txt, needs external resolvers (`uv` or `pip-tools`) to convert version constraints to exact versions for accurate vulnerability scanning
- Limited dependency graph information compared to lock files
- Works with both Poetry and PEP 621 formats

## Vulnerability Data Sources

### PyPA Advisory Database (Default)

- Comprehensive coverage of Python ecosystem
- Community-maintained vulnerability database
- Regular updates from security researchers

### PyPI JSON API

- Official PyPI vulnerability data
- Real-time information
- Limited to packages hosted on PyPI

### OSV.dev

- Cross-ecosystem vulnerability database
- Google-maintained infrastructure

## Output Formats

### Human-Readable (Default)

Most comfortable to read.

### Markdown

GitHub-friendly format with structured sections and severity indicators. Perfect for documentation, GitHub issues, and security reports.

### JSON

```json
{
  "summary": {
    "total_dependencies": 245,
    "vulnerable_packages": 2,
    "total_vulnerabilities": 3,
    "by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 1,
      "low": 0
    }
  },
  "vulnerabilities": [...]
}
```

### SARIF (Static Analysis Results Interchange Format)

Compatible with GitHub Security tab, VS Code, and other security tools.

## Performance

PySentry is designed for speed and efficiency:

- **Concurrent Processing**: Vulnerability data fetched in parallel from multiple sources
- **Multi-tier Caching**: Intelligent caching for both vulnerability data and resolved dependencies
- **Efficient Matching**: In-memory indexing for fast vulnerability lookups
- **Streaming**: Large databases processed without excessive memory usage

### Resolution Cache Performance

The resolution cache provides dramatic performance improvements for requirements.txt files:

- **First scan**: Standard resolution time using `uv` or `pip-tools`
- **Subsequent scans**: Near-instantaneous when cache is fresh (>90% time savings)
- **Cache invalidation**: Automatic when requirements content, resolver, or environment changes
- **Content-aware**: Different cache entries for different Python versions and platforms

### Requirements.txt Resolution Performance

PySentry leverages external resolvers with intelligent caching:

- **uv resolver**: 2-10x faster than pip-tools, handles large dependency trees efficiently
- **pip-tools resolver**: Reliable fallback, slower but widely compatible
- **Isolated execution**: Prevents project pollution while maintaining security
- **Resolution caching**: Eliminates repeated resolver calls for unchanged requirements

## Development

### Building from Source

```bash
git clone https://github.com/nyudenkov/pysentry
cd pysentry
cargo build --release
```

### Running Tests

```bash
cargo test
```

### Project Structure

```
src/
├── main.rs           # CLI interface
├── lib.rs            # Library API
├── cache/            # Caching system
├── dependency/       # Dependency scanning
├── output/           # Report generation
├── parsers/          # Project file parsers
├── providers/        # Vulnerability data sources
├── types.rs          # Core type definitions
└── vulnerability/    # Vulnerability matching
```

## Troubleshooting

### Common Issues

**Error: "No lock file or pyproject.toml found"**

```bash
# Ensure you're in a Python project directory
ls pyproject.toml uv.lock poetry.lock requirements.txt

# Or specify the path explicitly
pysentry /path/to/python/project
```

**Error: "No dependency resolver found" or "uv resolver not available"**

```bash
# Install a supported resolver in your environment
pip install uv           # Recommended - fastest
pip install pip-tools    # Alternative

# Verify resolver is available
uv --version
pip-compile --version

# If using virtual environments, ensure resolver is installed there
source venv/bin/activate
pip install uv
pysentry /path/to/project
```

**Error: "Failed to resolve requirements"**

```bash
# Check your requirements.txt syntax
cat requirements.txt

# Try different resolver
pysentry --resolver pip-tools  # if uv fails
pysentry --resolver uv         # if pip-tools fails

# Ensure you're in correct environment
which python
which uv  # or which pip-compile

# Debug with verbose output
pysentry --verbose /path/to/project
```

**Error: "Failed to fetch vulnerability data"**

```bash
# Check network connectivity
curl -I https://osv-vulnerabilities.storage.googleapis.com/

# Try with different or multiple sources
pysentry --sources pypi
pysentry --sources pypa,osv
```

**Slow requirements.txt resolution**

```bash
# Use faster uv resolver instead of pip-tools
pysentry --resolver uv

# Install uv for better performance (2-10x faster)
pip install uv

# Or use uvx for isolated execution
uvx pysentry-rs --resolver uv /path/to/project
```

**Requirements.txt files not being detected**

```bash
# Ensure requirements.txt exists
ls requirements.txt

# Specify path explicitly
pysentry /path/to/python/project

# Include additional requirements files
pysentry --requirements requirements-dev.txt --requirements requirements-test.txt

# Check if higher-priority files exist (they take precedence)
ls uv.lock poetry.lock Pipfile.lock pyproject.toml Pipfile requirements.txt
```

**Performance Issues**

```bash
# Clear all caches and retry
rm -rf ~/.cache/pysentry      # Linux
rm -rf ~/Library/Caches/pysentry  # macOS
pysentry

# Clear only resolution cache (if vulnerability cache is working)
rm -rf ~/.cache/pysentry/dependency-resolution/      # Linux
rm -rf ~/Library/Caches/pysentry/dependency-resolution/  # macOS
pysentry

# Clear resolution cache via CLI
pysentry --clear-resolution-cache

# Use verbose mode to identify bottlenecks
pysentry --verbose

# Disable caching to isolate issues
pysentry --no-cache
```

**Resolution Cache Issues**

```bash
# Clear stale resolution cache after environment changes
pysentry --clear-resolution-cache

# Disable resolution cache if causing issues
pysentry --no-resolution-cache

# Extend cache TTL for stable environments
pysentry --resolution-cache-ttl 168  # 1 week

# Check cache usage with verbose output
pysentry --verbose  # Shows cache hits/misses

# Force fresh resolution (ignores cache)
pysentry --clear-resolution-cache --no-resolution-cache
```

## Acknowledgments

- Inspired by [pip-audit](https://github.com/pypa/pip-audit) and [uv #9189 issue](https://github.com/astral-sh/uv/issues/9189)
- Originally was a command for [uv](https://github.com/astral-sh/uv)
- Vulnerability data from [PyPA](https://github.com/pypa/advisory-database), [PyPI](https://pypi.org/), and [OSV.dev](https://osv.dev/)
