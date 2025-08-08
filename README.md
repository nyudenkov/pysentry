# 🐍 PySentry

[Help to test and improve](https://github.com/nyudenkov/pysentry/issues/12)

A fast, reliable security vulnerability scanner for Python projects, written in Rust.

## Overview

PySentry audits Python projects for known security vulnerabilities by analyzing dependency files (`uv.lock`, `pyproject.toml`, `requirements.txt`) and cross-referencing them against multiple vulnerability databases. It provides comprehensive reporting with support for various output formats and filtering options.

## Key Features

- **Multiple Project Formats**: Supports `uv.lock`, `pyproject.toml`, and `requirements.txt` files
- **External Resolver Integration**: Leverages `uv` and `pip-tools` for accurate requirements.txt constraint solving
- **Multiple Data Sources**:
  - PyPA Advisory Database (default)
  - PyPI JSON API
  - OSV.dev (Open Source Vulnerabilities)
- **Flexible Output**: Human-readable, JSON, and SARIF formats
- **Performance Focused**:
  - Written in Rust for speed
  - Async/concurrent processing
  - Intelligent caching system
- **Comprehensive Filtering**:
  - Severity levels (low, medium, high, critical)
  - Dependency types (production, development, optional)
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

**Auto-detection:** PySentry automatically detects and prefers: `uv` > `pip-tools`. Without a resolver, only `uv.lock` and `pyproject.toml` files can be scanned.

## Quick Start

### Basic Usage

```bash
# Using uvx (recommended for occasional use)
uvx pysentry-rs
uvx pysentry-rs /path/to/python/project

# Using installed binary
pysentry
pysentry /path/to/python/project

# Scan requirements.txt (auto-detects resolver)
pysentry /path/to/project

# Force specific resolver
pysentry --resolver uv /path/to/project
pysentry --resolver pip-tools /path/to/project

# Include development dependencies
pysentry --dev

# Filter by severity (only show high and critical)
pysentry --severity high

# Output to JSON file
pysentry --format json --output audit-results.json
```

### Advanced Usage

```bash
# Using uvx for comprehensive audit
uvx pysentry-rs --dev --optional --format sarif --output security-report.sarif

# Check only direct dependencies using OSV database
uvx pysentry-rs --direct-only --source osv

# Or with installed binary
pysentry --dev --optional --format sarif --output security-report.sarif
pysentry --direct-only --source osv

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
```

## Configuration

### Command Line Options

| Option           | Description                                           | Default             |
| ---------------- | ----------------------------------------------------- | ------------------- |
| `--format`       | Output format: `human`, `json`, `sarif`               | `human`             |
| `--severity`     | Minimum severity: `low`, `medium`, `high`, `critical` | `low`               |
| `--source`       | Vulnerability source: `pypa`, `pypi`, `osv`           | `pypa`              |
| `--dev`          | Include development dependencies                      | `false`             |
| `--optional`     | Include optional dependencies                         | `false`             |
| `--direct-only`  | Check only direct dependencies                        | `false`             |
| `--ignore`       | Vulnerability IDs to ignore (repeatable)              | `[]`                |
| `--output`       | Output file path                                      | `stdout`            |
| `--no-cache`     | Disable caching                                       | `false`             |
| `--cache-dir`    | Custom cache directory                                | `~/.cache/pysentry` |
| `--verbose`      | Enable verbose output                                 | `false`             |
| `--quiet`        | Suppress non-error output                             | `false`             |
| `--resolver`     | Dependency resolver: `auto`, `uv`, `pip-tools`        | `auto`              |
| `--requirements` | Additional requirements files (repeatable)            | `[]`                |

### Cache Management

PySentry uses an intelligent caching system to avoid redundant API calls:

- **Default Location**: `~/.cache/pysentry/` (or system temp directory)
- **TTL-based Expiration**: Separate expiration for each vulnerability source
- **Atomic Updates**: Prevents cache corruption during concurrent access
- **Custom Location**: Use `--cache-dir` to specify alternative location

To clear the cache:

```bash
rm -rf ~/.cache/pysentry/
```

## Supported Project Formats

### uv.lock Files (Recommended)

PySentry has support for `uv.lock` files:

- Exact version resolution
- Complete dependency graph analysis
- Source tracking
- Dependency classification (main, dev, optional) including transitive dependencies

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

- **Concurrent Processing**: Vulnerability data fetched in parallel
- **Smart Caching**: Reduces API calls and parsing overhead
- **Efficient Matching**: In-memory indexing for fast vulnerability lookups
- **Streaming**: Large databases processed without excessive memory usage

### Requirements.txt Resolution Performance

PySentry leverages external resolvers for optimal performance:

- **uv resolver**: 2-10x faster than pip-tools, handles large dependency trees efficiently
- **pip-tools resolver**: Reliable fallback, slower but widely compatible
- **Isolated execution**: Prevents project pollution while maintaining security

### Benchmarks

Typical performance on a project with 100+ dependencies:

- **Cold cache**: 15-30 seconds
- **Warm cache**: 2-5 seconds
- **Memory usage**: ~50MB peak

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
ls pyproject.toml uv.lock requirements.txt

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

# Try with different source
pysentry --source pypi
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
ls uv.lock pyproject.toml
```

**Performance Issues**

```bash
# Clear cache and retry
rm -rf ~/.cache/pysentry
pysentry

# Use verbose mode to identify bottlenecks
pysentry --verbose
```

## Acknowledgments

- Inspired by [pip-audit](https://github.com/pypa/pip-audit) and [uv #9189 issue](https://github.com/astral-sh/uv/issues/9189)
- Originally was a command for [uv](https://github.com/astral-sh/uv)
- Vulnerability data from [PyPA](https://github.com/pypa/advisory-database), [PyPI](https://pypi.org/), and [OSV.dev](https://osv.dev/)
