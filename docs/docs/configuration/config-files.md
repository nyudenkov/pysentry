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
fail_on = "high"
scope = "all"
direct_only = false
no_ci_detect = false
display = "table"
include_scripts = false

[sources]
enabled = ["pypa", "osv"]

[resolver]
type = "uv"
no_resolver = false

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
show_progress = false

[output]
quiet = false
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
fail_on = "high"
scope = "main"
direct_only = false
no_ci_detect = false
display = "table"
include_scripts = false

[tool.pysentry.sources]
enabled = ["pypa", "osv"]

[tool.pysentry.resolver]
type = "uv"
no_resolver = false

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

[tool.pysentry.output]
quiet = false
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
| `fail_on` | string | Minimum severity to cause non-zero exit | `medium` |
| `scope` | string | Dependency scope: `all` or `main` | `all` |
| `groups` | array | Audit only the named dependency group(s) plus main dependencies. Requires a lock file. Conflicts with `scope = "main"` | `[]` |
| `include_scripts` | bool | Also scan PEP 723 Python scripts found under the project directory | `false` |
| `direct_only` | bool | Only check direct dependencies | `false` |
| `detailed` | bool | Enable detailed output with full vulnerability descriptions | `false` |
| `compact` | bool | Compact output: summary + one-liner per vulnerability, no descriptions or fix suggestions | `false` |
| `display` | string | Output display style for compact mode: `text` or `table` | `table` |
| `include_withdrawn` | bool | Include withdrawn vulnerabilities in results | `false` |
| `no_ci_detect` | bool | Disable automatic CI environment detection | `false` |

:::note
Human output is **compact by default** (since v0.5.0): a summary plus a one-line table row per finding (including its severity level). Set `detailed = true` (or pass `--detailed`) for full descriptions, numeric CVSS scores, and references. `compact` and `detailed` are mutually exclusive — setting both to `true` in your configuration file causes a validation error.
:::

:::note
`groups` and `scope = "main"` cannot be used together — `groups` already narrows scope, and `scope = "main"` would strip the very groups you selected. `groups` also requires a group-aware lock file (`uv.lock`, `poetry.lock`, or `pylock.toml`, including named `pylock.<name>.toml` variants). See [`--group`](./cli-options.md#dependency-group-filtering---group) for the full rules.
:::

### `[sources]`

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `enabled` | array | Vulnerability sources to use | `["pypa", "pypi", "osv"]` |
| `service_url` | string | Override the OSV API base URL (custom/self-hosted OSV-compatible endpoint). Only valid when `enabled` is exactly `["osv"]` | public OSV API |
| `fail_on_partial` | bool | When a source fails but at least one succeeds, fail the run (exit 2) because the scan is incomplete. Set `false` (or pass `--no-fail-on-partial`) to continue on the sources that succeeded | `true` |

When `fail_on_partial` is `true` (the default, fail-closed) a partial scan still prints its full findings **and** a partial-scan marker before exiting `2`, so the incompleteness is visible. If every source fails, the run is always a hard error regardless of this setting.

### `[resolver]`

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `type` | string | Dependency resolver: `uv`, `pip-tools` | `uv` |
| `no_resolver` | bool | Skip resolver; audit only pinned (`package==version`) packages directly. Implies `direct_only` | `false` |

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
| `ids` | array | Vulnerability IDs or aliases to always ignore | `[]` |
| `while_no_fix` | array | Vulnerability IDs or aliases to ignore while no fix exists | `[]` |
| `packages` | array | Package names whose findings are suppressed entirely (config-only) | `[]` |

Ignore entries match the advisory's primary ID and aliases, so a CVE suppression can match a GHSA or PYSEC advisory for the same vulnerability. PySentry logs a warning when an ignore entry did not match any advisory during the run.

`packages` suppresses every finding for the named packages — names are compared with full PEP 503 normalization, so `zope.interface`, `Zope_Interface`, and `zope-interface` are equivalent. Suppressed findings are **still reported** (tagged as suppressed in every format) but never trigger the non-zero exit. A `packages` entry that matches nothing logs a warning, mirroring `ids`.

```toml
[ignore]
packages = ["internal-first-party-lib"]
```

### `[groups.<name>]`

Set a per-group `fail_on` threshold that overrides the global one for findings reaching a specific dependency group (config-only; there is no CLI flag). Requires a group-aware lock file (`uv.lock`, `poetry.lock`, or `pylock.toml`) — PySentry warns and ignores the thresholds otherwise.

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `fail_on` | string | Minimum severity that fails the run for this group (`low`, `medium`, `high`, `critical`) | global `fail_on` |

```toml
[defaults]
fail_on = "medium"      # global default

[groups.dev]
fail_on = "critical"    # be lenient on dev-only dependencies

[groups.benchmark]
fail_on = "critical"
```

Thresholds resolve **strictest-wins per context**: a finding's effective threshold is the lowest (strictest) across every context that reaches it. A group-only package (never pulled into your main/production dependencies) takes its group threshold outright, so it can be *looser* than global — that is how `[groups.dev] fail_on = "critical"` lets a medium-severity dev-only advisory pass while production still fails on medium. A package that also ships to production keeps the global `fail_on` as a floor that a permissive group can only tighten, never loosen.

### `[output]`

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `quiet` | bool | Suppress all output (equivalent to `--quiet`) | `false` |

### `[maintenance]`

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `enabled` | bool | Enable PEP 792 checks | `true` |
| `forbid_archived` | bool | Fail on archived packages | `false` |
| `forbid_deprecated` | bool | Fail on deprecated packages | `false` |
| `forbid_quarantined` | bool | Fail on quarantined packages | `true` |
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
| `show_progress` | bool | Show download progress | `false` |

## Creating a Configuration File

Use the built-in command to generate a configuration file:

```bash
pysentry-rs config init --output .pysentry.toml

# Generate minimal configuration
pysentry-rs config init --minimal --output .pysentry.toml

# Overwrite existing file
pysentry-rs config init --force --output .pysentry.toml
```

This creates a configuration file with default values that you can customize.
