---
sidebar_position: 5
---

# Changelog

## v0.4.5

### ✨ New Features

#### `--direct-only` Now Works for All Lock File Formats

`--direct-only` now correctly identifies direct dependencies when used with any lock file format — `uv.lock`, `Pipfile.lock`, `poetry.lock`, and `pylock.toml`.

PySentry reads the companion manifest alongside the lock file (pyproject.toml, Pipfile) to determine which packages are declared as direct dependencies. When no companion manifest is found, it falls back to lock-graph inference.

```bash
pysentry --direct-only
```

### ⚠️ Breaking Changes

#### `--severity` Flag Removed

The `--severity` display filter, deprecated since v0.4.3, has been removed. Use `--fail-on` to control exit behavior based on severity level.

#### `severity` Config Field Removed

The `severity` field in `[defaults]` (`.pysentry.toml` / `[tool.pysentry]` in `pyproject.toml`) has been removed alongside the CLI flag. Remove it from your config if present.

#### `--all` / `--all-extras` Flags Removed

The hidden `--all` and `--all-extras` flags have been removed. Extra dependencies are included by default; use `--exclude-extra` to opt out.

---

**Full Changelog**: https://github.com/nyudenkov/pysentry/compare/v0.4.4...v0.4.5

---

## v0.4.4

### ✨ New Features

#### Audit Without a Resolver (`--no-resolver`)

The new `--no-resolver` flag lets you audit `requirements.txt` files that are already fully pinned without invoking an external resolver (uv or pip-compile):

```bash
pysentry --no-resolver
pysentry --no-resolver --requirements-files requirements.txt requirements-prod.txt
```

Only `package==version` lines are processed. Unpinned entries (`requests>=2.0`), URL dependencies, and editable installs are skipped and reported. Include directives (`-r other.txt`) are also skipped with a warning — pass those files explicitly via `--requirements-files`.

`--no-resolver` automatically implies `--direct-only`. It can also be set in config:

```toml
# .pysentry.toml
[resolver]
no_resolver = true
```

Resolves [#150](https://github.com/nyudenkov/pysentry/issues/150).

### 🐛 Bug Fixes

#### Cross-Package Vulnerability Contamination

Advisories covering multiple packages (e.g. a CVE affecting both `package-a` and `package-b`) could incorrectly report a vulnerability against the wrong package. Version ranges from all affected packages in a shared advisory were merged and attributed to whichever package triggered the lookup. PySentry now filters advisory entries to the queried package before converting them, and merges vulnerabilities per-package rather than globally.

Resolves [#148](https://github.com/nyudenkov/pysentry/issues/148).

---

**Full Changelog**: https://github.com/nyudenkov/pysentry/compare/v0.4.3...v0.4.4

---

## v0.4.3

### ✨ New Features

#### Color Control (`--color`)

PySentry now has a `--color` global flag for explicit control over ANSI color output:

```bash
pysentry --color auto    # Default: auto-detect from terminal and environment
pysentry --color always  # Force colors even when piping to a file or CI log
pysentry --color never   # Disable colors entirely
```

`auto` (default) follows terminal standards: it respects `NO_COLOR` (any value disables colors), `FORCE_COLOR`, `CI`, `TERM=dumb`, and whether stdout is a TTY. Windows ANSI color output is now also enabled automatically.

#### Table Display Mode (`--display`)

Compact output can now render structured tables, making it easier to scan vulnerability data at a glance:

```bash
pysentry --compact                 # Table layout (default)
pysentry --compact --display table # Explicit table layout
pysentry --compact --display text  # Traditional indented text layout
```

Tables adapt to terminal width automatically. The display mode can be set in config:

```toml
# .pysentry.toml
[defaults]
display = "table"  # or "text"
```

### 🔧 Improvements

#### Direct/Transitive Tags in All Output

Every vulnerability entry now includes a `[direct]` or `[transitive]` tag in human-readable and markdown output, making it immediately clear whether the affected package is a direct dependency or pulled in transitively.

#### CVSS Version Tag in Detailed Mode

Detailed human and markdown output now shows the CVSS version alongside the score (e.g., `7.5 (v3)`), so you know which scoring standard applies.

#### Consolidated Markdown Fix Suggestions

Markdown reports now consolidate fix suggestions into package-level tables — one row per CVE — instead of repeating package information for each finding.

#### SARIF Output Enrichment

SARIF output now includes:
- SHA-256 `partialFingerprints` for stable result identity across scans
- `originalUriBaseIds` with `%SRCROOT%` for portable path resolution in GitHub Code Scanning
- CVE alias tags in rule metadata
- Actual CVSS score in `security-severity` extension property
- `precision: very-high` on all rules

#### Deterministic Fix Suggestion Ordering

Fix suggestions in all output formats are now ordered deterministically, giving consistent output across runs.

#### Default Changes

- `show_progress` is now **`false`** by default — download progress bars no longer appear unless explicitly enabled.
- `maintenance.forbid_quarantined` is now **`true`** by default — quarantined packages (confirmed malware or compromised distributions) now fail audits by default.

### 🐛 Bug Fixes

#### `output.quiet` Config Not Applied

`[output] quiet = true` in `.pysentry.toml` or `pyproject.toml` was silently ignored. The config file setting now works correctly.

Resolves [#146](https://github.com/nyudenkov/pysentry/issues/146).

#### `--severity` Decoupled from `--fail-on`

Previously, setting `--severity high` could hide medium vulnerabilities that `--fail-on medium` needed to evaluate, causing a silent mismatch: the audit would display as clean while still exiting with a failure code (or vice versa).

`--severity` is now a **display-only post-hoc filter**. `--fail-on` always evaluates the full set of vulnerabilities regardless of `--severity`. `--severity` will be removed in v0.5 — use `--fail-on` for exit-code control.

#### SARIF File URIs on Windows

Windows paths produced invalid `file://C:\Users\...` URIs in SARIF output. PySentry now generates RFC 8089-compliant `file:///C:/Users/...` URIs, enabling correct path resolution in GitHub Code Scanning on Windows runners.

:::warning Breaking Change

**JSON `severity` values are now lowercase.** The `severity` field in JSON output serializes as `"medium"` instead of `"MEDIUM"`. Update any JSON consumers (scripts, dashboards, integrations) that check or compare severity strings.

:::

---

**Full Changelog**: https://github.com/nyudenkov/pysentry/compare/v0.4.2...v0.4.3

---
