---
sidebar_position: 1
---

# Configuration Files

PySentry supports TOML-based configuration files for persistent settings management.

## Configuration Discovery

Configuration files follow a hierarchical discovery pattern:

1. **Project-level** (in current or parent directories, walking up to `.git` root):
   - `.pysentry.toml` (highest priority)
   - `pyproject.toml` `[tool.pysentry]` section (lower priority)
2. **User-level**: `~/.config/pysentry/config.toml` (Linux/macOS)
3. **System-level**: `/etc/pysentry/config.toml` (Unix systems)

**Priority**: When both `.pysentry.toml` and `pyproject.toml` exist in the same directory, `.pysentry.toml` takes precedence.

## Configuration File Example (.pysentry.toml)

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

[cache]
enabled = true
resolution_ttl = 48
vulnerability_ttl = 48

[ignore]
ids = ["CVE-2023-12345", "GHSA-xxxx-yyyy-zzzz"]
while_no_fix = ["CVE-2025-8869"]

[maintenance]
enabled = true
forbid_archived = false
forbid_deprecated = false
forbid_quarantined = true
forbid_unmaintained = false
check_direct_only = false
cache_ttl = 1

[http]
timeout = 120
connect_timeout = 30
max_retries = 3
retry_initial_backoff = 1
retry_max_backoff = 60
show_progress = true
```

## pyproject.toml Configuration

You can configure PySentry directly in your `pyproject.toml` using the `[tool.pysentry]` section:

```toml
[project]
name = "my-project"
version = "1.0.0"

[tool.pysentry]
version = 1

[tool.pysentry.defaults]
format = "json"
severity = "medium"
fail_on = "high"
scope = "main"
direct_only = false

[tool.pysentry.sources]
enabled = ["pypa", "osv"]

[tool.pysentry.resolver]
type = "uv"

[tool.pysentry.cache]
enabled = true
resolution_ttl = 48
vulnerability_ttl = 48

[tool.pysentry.ignore]
ids = ["CVE-2023-12345"]
while_no_fix = ["CVE-2025-8869"]

[tool.pysentry.maintenance]
enabled = true
forbid_archived = false
forbid_deprecated = false
forbid_quarantined = true
forbid_unmaintained = false
check_direct_only = false
cache_ttl = 1

[tool.pysentry.http]
timeout = 120
connect_timeout = 30
max_retries = 3
```

**Benefits of pyproject.toml configuration:**

- Keep all project configuration in a single file
- No additional config files to manage
- Works seamlessly with existing Python project tooling
- Graceful fallback: Invalid `[tool.pysentry]` sections log a warning and continue to next configuration source

## Configuration Sections

### `[defaults]`

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `format` | string | Output format: `human`, `json`, `sarif`, `markdown` | `human` |
| `severity` | string | Minimum severity to report | `low` |
| `fail_on` | string | Minimum severity to cause non-zero exit | `medium` |
| `scope` | string | Dependency scope: `all` or `main` | `all` |
| `direct_only` | bool | Only check direct dependencies | `false` |
| `detailed` | bool | Enable detailed output with full descriptions | `false` |
| `include_withdrawn` | bool | Include withdrawn vulnerabilities in results | `false` |

### `[sources]`

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `enabled` | array | Vulnerability sources to use | `["pypa", "pypi", "osv"]` |

### `[resolver]`

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `type` | string | Dependency resolver: `uv`, `pip-tools` | `uv` |

### `[cache]`

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `enabled` | bool | Enable caching | `true` |
| `directory` | string | Custom cache directory path | Platform-specific |
| `resolution_ttl` | int | Resolution cache TTL in hours | `24` |
| `vulnerability_ttl` | int | Vulnerability cache TTL in hours | `48` |

### `[ignore]`

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `ids` | array | Vulnerability IDs to always ignore | `[]` |
| `while_no_fix` | array | Vulnerability IDs to ignore while no fix exists | `[]` |

### `[maintenance]`

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `enabled` | bool | Enable PEP 792 checks | `true` |
| `forbid_archived` | bool | Fail on archived packages | `false` |
| `forbid_deprecated` | bool | Fail on deprecated packages | `false` |
| `forbid_quarantined` | bool | Fail on quarantined packages | `false` |
| `forbid_unmaintained` | bool | Fail on any unmaintained packages | `false` |
| `check_direct_only` | bool | Only check direct dependencies | `false` |
| `cache_ttl` | int | Maintenance status cache TTL in hours | `1` |

### `[http]`

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `timeout` | int | Request timeout in seconds | `120` |
| `connect_timeout` | int | Connection timeout in seconds | `30` |
| `max_retries` | int | Maximum retry attempts | `3` |
| `retry_initial_backoff` | int | Initial retry backoff in seconds | `1` |
| `retry_max_backoff` | int | Maximum retry backoff in seconds | `60` |
| `show_progress` | bool | Show download progress | `true` |

## Creating a Configuration File

Use the built-in command to generate a configuration file:

```bash
pysentry config init --output .pysentry.toml

# Generate minimal configuration
pysentry config init --minimal --output .pysentry.toml

# Overwrite existing file
pysentry config init --force --output .pysentry.toml
```

This creates a configuration file with default values that you can customize.
