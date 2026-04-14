---
sidebar_position: 6
---

# Troubleshooting

Common issues and their solutions.

## Project Detection

### "No dependency information found"

```bash
# Error: No dependency information found. Generate a lock file (uv.lock, poetry.lock,
# Pipfile.lock, pylock.toml) or add pyproject.toml/requirements.txt

# Ensure you're in a Python project directory
ls pyproject.toml uv.lock poetry.lock pylock.toml requirements.txt

# Or specify the path explicitly
pysentry-rs /path/to/python/project
```

### Requirements.txt files not being detected

```bash
# Ensure requirements.txt exists
ls requirements.txt

# Specify path explicitly
pysentry-rs /path/to/python/project

# Include additional requirements files
pysentry-rs --requirements-files requirements-dev.txt requirements-test.txt

# Check if higher-priority files exist (they take precedence)
ls uv.lock poetry.lock Pipfile.lock pyproject.toml Pipfile requirements.txt
```

## Resolver Issues

### "No supported dependency resolver found"

```bash
# Error: No supported dependency resolver found. Please install uv or pip-tools.

# Install a supported resolver in your environment
pip install uv           # Recommended - fastest
pip install pip-tools    # Alternative

# Verify resolver is available
uv --version
pip-compile --version

# If using virtual environments, ensure resolver is installed there
source venv/bin/activate
pip install uv
pysentry-rs /path/to/project
```

### "uv resolver not available"

```bash
# Install uv
pip install uv

# Verify installation
which uv
uv --version

# Ensure it's in your PATH
export PATH="$PATH:$(python -m site --user-base)/bin"
```

### "Failed to resolve requirements"

```bash
# Check your requirements.txt syntax
cat requirements.txt

# Try different resolver
pysentry-rs --resolver pip-tools  # if uv fails
pysentry-rs --resolver uv         # if pip-tools fails

# Ensure you're in correct environment
which python
which uv  # or which pip-compile

# Debug with verbose output
pysentry-rs -vvv /path/to/project
```

## Network Issues

### "Failed to fetch vulnerability data"

```bash
# Check network connectivity to OSV API
curl -I https://api.osv.dev/v1

# Try with different or fewer sources
pysentry-rs --sources pypi
pysentry-rs --sources pypa,osv
```

### Network timeout errors

PySentry includes automatic retry with exponential backoff. The default timeout is 120 seconds. For persistent timeouts:

```toml
# .pysentry.toml
[http]
timeout = 300           # 5 minute timeout (default: 120)
max_retries = 5         # More retry attempts (default: 3)
retry_max_backoff = 120 # Longer backoff delays (default: 60)
```

```bash
# Then run again
pysentry-rs
```

### Resolver timeout errors

If you see `UvTimeout` or `PipToolsTimeout` errors, the resolver is taking too long to resolve dependencies. This can happen with large dependency trees or slow network connections. Consider generating a lock file instead:

```bash
# Generate lock file with uv (faster than scanning requirements.txt)
uv lock

# Then scan the lock file
pysentry-rs /path/to/project
```

### Rate limiting (HTTP 429 errors)

PySentry handles rate limiting automatically. If rate limits persist:

```toml
# .pysentry.toml
[http]
max_retries = 5              # More attempts
retry_initial_backoff = 5    # Longer initial wait
retry_max_backoff = 300      # Up to 5 minute backoff
```

## Performance Issues

### Slow requirements.txt resolution

```bash
# Use faster uv resolver instead of pip-tools
pysentry-rs --resolver uv

# Install uv for better performance (2-10x faster)
pip install uv

# Or use uvx for isolated execution
uvx pysentry-rs --resolver uv /path/to/project
```

### General slow performance

```bash
# Clear all caches and retry
rm -rf ~/.cache/pysentry      # Linux
rm -rf ~/Library/Caches/pysentry  # macOS
pysentry-rs

# Clear only resolution cache (if vulnerability cache is working)
rm -rf ~/.cache/pysentry/dependency-resolution/      # Linux
rm -rf ~/Library/Caches/pysentry/dependency-resolution/  # macOS
pysentry-rs

# Clear resolution cache via CLI
pysentry-rs --clear-resolution-cache

# Use verbose mode to identify bottlenecks
pysentry-rs -vvv

# Disable caching to isolate issues
pysentry-rs --no-cache
```

## Cache Issues

### Stale cache causing problems

```bash
# Clear stale resolution cache after environment changes
pysentry-rs --clear-resolution-cache

# Disable resolution cache if causing issues
pysentry-rs --no-resolution-cache

# Force fresh resolution (ignores cache)
pysentry-rs --clear-resolution-cache --no-resolution-cache
```

### Cache corruption

```bash
# Delete all caches and rebuild
rm -rf ~/.cache/pysentry/
pysentry-rs /path/to/project
```

### Extend cache TTL for stable environments

```bash
pysentry-rs --resolution-cache-ttl 168  # 1 week
```

### Check cache usage

```bash
# Verbose output shows cache hits/misses
pysentry-rs -vv
```

## Configuration Issues

### Configuration file not being loaded

```bash
# Check configuration paths
pysentry-rs config path

# Validate configuration
pysentry-rs config validate

# Show effective configuration
pysentry-rs config show

# Override configuration path
PYSENTRY_CONFIG=/path/to/.pysentry.toml pysentry-rs

# Disable configuration files
PYSENTRY_NO_CONFIG=1 pysentry-rs
```

### Invalid configuration syntax

```bash
# Validate your configuration file
pysentry-rs config validate

# Check TOML syntax
cat .pysentry.toml
```

## Unknown Severity Vulnerabilities

### What does "UNKNOWN" severity mean?

Some vulnerability advisories don't include CVSS scoring data, so PySentry can't determine their severity level. These are reported as `UNKNOWN`.

By default, unknown severity vulnerabilities cause a non-zero exit code (same as any other severity). To change this:

```bash
# Don't fail on unknown severity vulnerabilities
pysentry-rs --no-fail-on-unknown

# Combine with fail-on to only fail on high+ but still report unknowns
pysentry-rs --fail-on high --no-fail-on-unknown
```

### Why are some vulnerabilities showing UNKNOWN?

This typically happens with:

- Newly published advisories that haven't been scored yet
- Advisories from sources that don't provide CVSS data (e.g., PyPI JSON API)
- Withdrawn or partially retracted advisories

Use `--detailed` to see more information about the vulnerability, including its source and any available references.

## CI/CD Issues

### GitHub Actions annotations not appearing

PySentry auto-detects GitHub Actions via the `GITHUB_ACTIONS` environment variable. If annotations aren't showing:

```bash
# Verify CI detection is not disabled
# Check your .pysentry.toml for no_ci_detect = true

# Run with verbose output to see CI detection
pysentry-rs -vv
```

### Disabling CI behavior

If CI auto-detection interferes with your workflow:

```bash
# Disable via CLI flag
pysentry-rs --no-ci-detect

# Or via configuration
# .pysentry.toml
# [defaults]
# no_ci_detect = true
```

### Feedback messages appearing in CI

PySentry automatically suppresses feedback and survey messages in detected CI environments. If they still appear, ensure the CI environment variable is set (e.g., `GITHUB_ACTIONS`, `GITLAB_CI`, `CI`).

## Output Issues

### No output displayed

```bash
# Check if quiet mode is enabled
pysentry-rs  # Without -q flag

# Enable verbose output
pysentry-rs -v
```

### Output format issues

```bash
# Explicitly specify format
pysentry-rs --format human
pysentry-rs --format json --output results.json
```

## Pre-commit Issues

### Hook takes too long

```yaml
# Use faster resolver and limit sources
repos:
  - repo: https://github.com/pysentry/pysentry-pre-commit
    rev: v0.4.5
    hooks:
      - id: pysentry
        args: ["--resolver", "uv", "--sources", "pypa"]
```

### Resolver not found in pre-commit

```bash
# Update pre-commit environments
pre-commit clean
pre-commit install --install-hooks
```

## Debug Commands

### Check available resolvers

```bash
pysentry-rs resolvers
```

### Show configuration

```bash
pysentry-rs config show
```

### Validate configuration

```bash
pysentry-rs config validate
```

### Verbose debugging

```bash
# Warnings
pysentry-rs -v

# Info (recommended for troubleshooting)
pysentry-rs -vv

# Debug (detailed)
pysentry-rs -vvv

# Trace (maximum verbosity)
pysentry-rs -vvvv
```

### Module-specific debugging

```bash
# Debug dependency resolution
RUST_LOG=pysentry::dependency=debug pysentry-rs /path/to/project

# Debug parser selection
RUST_LOG=pysentry::parsers=debug pysentry-rs /path/to/project

# Debug caching
RUST_LOG=pysentry::cache=debug pysentry-rs /path/to/project
```

## Getting Help

If these solutions don't resolve your issue:

1. **Check existing issues**: [GitHub Issues](https://github.com/nyudenkov/pysentry/issues)
2. **Open a new issue**: Include verbose output (`pysentry-rs -vvv`)
3. **Join discussions**: [GitHub Discussions](https://github.com/nyudenkov/pysentry/discussions)
4. **Email support**: nikita@pysentry.com
