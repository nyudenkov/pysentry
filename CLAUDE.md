# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**PySentry** - A fast, reliable security vulnerability scanner for Python projects, written in Rust. Provides comprehensive vulnerability scanning by analyzing dependency files (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `pylock.toml`, `pyproject.toml`, `Pipfile`, `requirements.txt`) against multiple vulnerability databases.

### Core Architecture

- **Primary Language**: Rust (with Python bindings via PyO3)
- **Binary Name**: `pysentry` (Rust), `pysentry-rs` (Python package)
- **Version**: 0.3.7
- **Dual Interface**: Native Rust binary + Python package for maximum deployment flexibility

### Key Components

```
src/
├── main.rs           # CLI entry point
├── lib.rs            # Library API with AuditEngine
├── cache/            # Multi-tier caching (vulnerability DB + dependency resolution)
├── dependency/       # Dependency scanning with external resolver integration
├── parsers/          # Project file parsers (uv.lock, poetry.lock, Pipfile.lock, pylock.toml, pyproject.toml, Pipfile, requirements.txt)
├── providers/        # Vulnerability data sources (PyPA, PyPI, OSV.dev)
├── vulnerability/    # Vulnerability matching engine and database
├── output/           # Report generation (human, JSON, SARIF, markdown)
└── config.rs         # TOML-based configuration system
```

## Common Development Commands

### Building & Testing

```bash
# Build release binary
cargo build --release

# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Build Python bindings (requires maturin)
maturin develop

# Build Python wheel
maturin build --release
```

### Code Quality

```bash
# Format code
cargo fmt --all

# Check formatting (CI)
cargo fmt --all -- --check

# Lint with Clippy
cargo clippy --all-targets --all-features

# Clippy with warnings as errors (CI)
cargo clippy --all-targets --all-features -- -D warnings

# Type checking
cargo check --all-targets --all-features
```

### Development Tools

```bash
# Security audit
cargo audit

# Run benchmarks
cd benchmarks && python main.py

# Pre-commit hooks
pre-commit run --all-files

# Checking out Github (IMPORTANT: YOU SE IT ONLY FOR READING)
gh ...
```

## Architecture Highlights

### Multi-Tier Caching System

**Vulnerability Database Cache**: `~/.cache/pysentry/vulnerability-db/`

- Caches PyPA, PyPI, OSV vulnerability databases
- 24-hour TTL with atomic updates
- Prevents redundant API calls

**Resolution Cache**: `~/.cache/pysentry/dependency-resolution/`

- Caches resolved dependencies from `uv`/`pip-tools`
- Content-based cache keys (requirements + resolver version + Python version)
- Dramatic performance improvements for requirements.txt and Pipfile scanning (>90% time savings)

### External Resolver Integration

PySentry leverages external tools for accurate dependency resolution:

- **uv**: Rust-based resolver (preferred) - extremely fast
- **pip-tools**: Python-based fallback using `pip-compile`
- **Auto-detection**: Automatically selects best available resolver
- **Isolated execution**: Runs in temporary directories to prevent project pollution

### Vulnerability Data Sources

- **PyPA Advisory Database** (default): Community-maintained, comprehensive Python ecosystem coverage
- **PyPI JSON API**: Official PyPI vulnerability data, real-time information
- **OSV.dev**: Google-maintained cross-ecosystem vulnerability database

## Testing Strategy

- **Unit tests**: Embedded in source files with `#[cfg(test)]`
- **Integration tests**: End-to-end CLI testing
- **Benchmark suite**: `benchmarks/` directory with performance comparisons
- **Pre-commit hooks**: Automated formatting, linting, and testing

## Python Bindings Architecture

The project uses **maturin** to create Python bindings:

- `python/pysentry/` contains Python module structure
- `src/python.rs` defines PyO3 bindings (feature-gated)
- `pyproject.toml` configures Python package metadata

## Configuration System

Hierarchical TOML configuration discovery:

1. Project-level: `.pysentry.toml` (current or parent directories)
2. User-level: `~/.config/pysentry/config.toml`
3. System-level: `/etc/pysentry/config.toml`

Environment variables:

- `PYSENTRY_CONFIG`: Override config file path
- `PYSENTRY_NO_CONFIG`: Disable config file loading

## CLI Command Structure

```bash
# Main audit command (no subcommand)
pysentry [options] [path]

# Subcommands
pysentry resolvers          # Check available dependency resolvers
pysentry check-version      # Check for newer versions
pysentry config init        # Initialize configuration
pysentry config show        # Show current configuration
pysentry config validate    # Validate configuration
```

## Performance Characteristics

- **Concurrent processing**: Parallel vulnerability data fetching
- **Streaming**: Large databases processed without excessive memory usage
- **In-memory indexing**: Fast vulnerability lookups
- **Resolution caching**: Near-instantaneous repeated scans of requirements.txt

## Development Notes

- **Error handling**: Uses `anyhow` for error chaining and context
- **Async runtime**: Tokio for concurrent I/O operations
- **Logging**: `tracing` crate with configurable verbosity
- **CLI**: `clap` for command-line interface with derive macros
- **Platform support**: Linux, macOS, Windows (Rust binary); Linux/macOS only (Python wheels)

## Supported Project Formats

1. **uv.lock** (recommended): Complete dependency graph, exact versions
2. **poetry.lock**: Full Poetry lock file support, no external tools needed
3. **Pipfile.lock**: Pipenv lock file with exact versions and cryptographic hashes, no external tools needed
4. **pylock.toml**: PEP 751 standardized lock file format, exact versions with comprehensive metadata
5. **pyproject.toml**: Requires external resolver for constraint resolution
6. **Pipfile**: Pipenv specification file, requires external resolver (uv or pip-tools)
7. **requirements.txt**: Requires external resolver (uv or pip-tools)

## Output Formats

- **Human**: Default, colorized terminal output
- **JSON**: Structured data for programmatic processing
- **SARIF**: Static Analysis Results Interchange Format (IDE/CI integration)
- **Markdown**: GitHub-friendly format for reports and documentation
