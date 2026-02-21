---
sidebar_position: 2
---

# Environment Variables

PySentry supports environment variables for configuration and debugging.

## Configuration Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `PYSENTRY_CONFIG` | Override config file path (supports `.pysentry.toml` or `pyproject.toml`) | `PYSENTRY_CONFIG=/path/to/pyproject.toml` |
| `PYSENTRY_NO_CONFIG` | Disable all config file loading | `PYSENTRY_NO_CONFIG=1` |

## Examples

### Override Configuration File

```bash
# Use a specific configuration file
PYSENTRY_CONFIG=/path/to/.pysentry.toml pysentry

# Use pyproject.toml from a different location
PYSENTRY_CONFIG=/path/to/pyproject.toml pysentry
```

### Disable Configuration Files

```bash
# Run with only CLI arguments, ignore all config files
PYSENTRY_NO_CONFIG=1 pysentry --fail-on high
```

## RUST_LOG for Debugging

For fine-grained logging control, use the `RUST_LOG` environment variable. When set, it takes precedence over `-v` flags.

### Basic Usage

```bash
# Enable debug logging for all pysentry modules
RUST_LOG=pysentry=debug pysentry /path/to/project

# Enable trace logging for specific modules
RUST_LOG=pysentry::parsers=trace pysentry /path/to/project

# Combine multiple module filters
RUST_LOG=pysentry=info,pysentry::dependency=debug pysentry /path/to/project
```

### Common Patterns

```bash
# Debug dependency resolution
RUST_LOG=pysentry::dependency=debug pysentry /path/to/project

# Debug vulnerability matching
RUST_LOG=pysentry::vulnerability=debug pysentry /path/to/project

# Debug parser selection
RUST_LOG=pysentry::parsers=debug pysentry /path/to/project

# Debug caching behavior
RUST_LOG=pysentry::cache=debug pysentry /path/to/project

# Full trace output (very verbose)
RUST_LOG=pysentry=trace pysentry /path/to/project
```

### Use Cases

`RUST_LOG` is useful for:

- **Debugging specific components** without verbose output from others
- **CI/CD environments** where you want consistent log levels
- **Troubleshooting issues** with detailed module-specific logs
- **Performance analysis** by tracing specific subsystems

## Resolver Environment Variables

When using external resolvers for `requirements.txt`, `pyproject.toml`, or `Pipfile` files, PySentry reads these environment variables for cache key differentiation. The resolvers themselves also read these variables from the environment when executed.

This ensures that different index configurations produce different cache entries, preventing incorrect resolution results when switching between package indexes.

### UV Resolver

| Variable | Description |
|----------|-------------|
| `UV_PYTHON` | Python interpreter path |
| `UV_INDEX_URL` | Custom PyPI index URL |
| `UV_EXTRA_INDEX_URL` | Extra PyPI index URL |
| `UV_PRERELEASE` | Allow prerelease versions |

### pip-tools Resolver

| Variable | Description |
|----------|-------------|
| `PIP_INDEX_URL` | Custom PyPI index URL |
| `PIP_EXTRA_INDEX_URL` | Extra PyPI index URL |
| `PIP_TRUSTED_HOST` | Trusted host for pip |
| `PIP_PRE` | Allow prerelease versions |

## Platform-Specific Variables

### Cache Directory

PySentry respects standard cache directory environment variables:

| Platform | Variable | Default |
|----------|----------|---------|
| Linux | `XDG_CACHE_HOME` | `~/.cache` |
| macOS | - | `~/Library/Caches` |
| Windows | `LOCALAPPDATA` | `%LOCALAPPDATA%` |

Override with `--cache-dir` flag:

```bash
pysentry --cache-dir /custom/cache/path
```
