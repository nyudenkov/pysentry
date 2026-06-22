---
sidebar_position: 5
---

# Changelog

## v0.4.7 "Hardening"

### ✨ New Features

#### PEP 723 Inline Script Metadata

PySentry can now audit single-file Python scripts that declare dependencies using PEP 723 inline metadata:

```python
# /// script
# dependencies = [
#   "requests==2.31.0",
#   "click==8.1.7",
# ]
# ///
```

Run PySentry directly against the script:

```bash
pysentry-rs script.py
```

Pinned dependencies are audited directly under `--no-resolver`; unpinned dependencies are resolved through the configured resolver when resolution is enabled. This makes PySentry work with modern `uv run script.py` style workflows without requiring a separate project directory.

Directory scans can also include PEP 723 scripts with `--include-scripts` or `[defaults] include_scripts = true`. Script-origin findings are marked with the script path in human output, for example `direct @ tools/audit.py`.

#### Transitive Findings Show Their Top-Level Dependency

Human output now explains why a vulnerable transitive package is present by showing the top-level dependency that pulled it in:

```text
urllib3 2.0.0 [transitive] (via requests)
```

For packages reachable from multiple direct dependencies, PySentry lists up to three roots and summarizes the rest. This is display-only context; it does not change matching, filtering, or exit-code behavior.

Supported lock formats are `uv.lock`, `poetry.lock`, and `pylock.toml` / `pylock.<name>.toml`. Formats without dependency edges, such as `Pipfile.lock` and resolved `requirements.txt`, continue to render as before.

#### Maintenance Cache TTL

PEP 792 maintenance status checks now have a configurable cache TTL:

```bash
pysentry-rs --maintenance-cache-ttl 6
```

```toml
# .pysentry.toml
[maintenance]
cache_ttl = 6
```

The default remains 1 hour. This is useful in CI environments that want fewer Simple API requests while still keeping archived, deprecated, and quarantined package status reasonably fresh.

### 🔧 Improvements

#### Alias-Aware Ignores and Unmatched Ignore Warnings

`--ignore` and `--ignore-while-no-fix` now match both the advisory's primary ID and its aliases. Ignoring a CVE now works even when the provider's canonical advisory ID is a GHSA or PYSEC ID:

```bash
pysentry-rs --ignore CVE-2024-12345
```

PySentry also logs a warning when an ignore ID did not match any advisory during the run. This catches typoed suppressions that previously looked active but did nothing.

#### Unknown Config Fields Are Rejected

Configuration files now reject unknown keys instead of silently ignoring them. A typo like `formatt = "json"` now fails validation rather than leaving `format` at its default.

This applies to `.pysentry.toml` and `[tool.pysentry]` in `pyproject.toml`.

#### Friendlier Cache and Database Download Errors

Cache-format mismatches and failed advisory database downloads now surface clearer error messages with better context. PySentry no longer leaks low-level ZIP or serde errors in places where the actionable problem is stale cache data or a provider download failure.

#### Stricter Internal Safety Checks

The codebase now enforces clippy lints for production `unwrap`, `expect`, and indexing usage. Existing intentional exceptions are documented with invariants. This does not change CLI behavior, but it reduces the chance that malformed project data or provider data can crash the binary.

### 🐛 Bug Fixes

#### OSV `affected.versions` Advisories Were Missed

Some OSV advisories enumerate affected releases in `affected.versions` instead of, or in addition to, range events. PySentry previously ignored that field, so single-source OSV scans could miss advisories whose affected versions were listed explicitly.

PySentry now converts every explicit OSV affected version into an exact inclusive range, so those advisories match correctly.

:::warning
If you run PySentry with `--sources osv`, affected findings may have been missing from previous reports. Re-run your audit on this release.
:::

#### PyPI Advisories Without Usable Fix Ranges Were Missed

The PyPI JSON API returns vulnerabilities for the specific package version being queried. When PyPI returned an advisory with no usable `fixed_in` value, PySentry emitted no affected range, and the matcher treated the advisory as not affecting the installed version.

PySentry now trusts PyPI's per-version response and emits a match-all range for these advisories, preventing them from being silently dropped.

#### PyPI Multi-Branch Fixes Dropped Later Affected Branches

PyPI advisories can list multiple fixed versions for different release branches. PySentry previously used only the first fixed version, which could miss vulnerabilities in a later branch, such as a package fixed in both `2.31.1` and `3.0.2` while `3.0.1` remained vulnerable.

PySentry now emits one affected range per fixed version, preserving multi-branch fix semantics.

#### PEP 503 Package Name Normalization

Package names are now normalized using the full PEP 503 rule: lowercase and collapse every run of `-`, `_`, and `.` to a single `-`. This fixes dotted-name mismatches such as `zope.interface`, `Zope_Interface`, and `zope-interface` referring to the same package.

The PyPA advisory cache key was bumped to `pypa-v3` because cached package indexes serialized with the old normalization could miss dotted packages.

#### Provider Cache Keys Versioned for v0.4.7 Conversions

The OSV and PyPI provider caches now use versioned keys for the v0.4.7 conversion changes. Old cache files deserialize successfully but lack the new exact, wildcard, and multi-branch ranges, so reusing them would preserve the false negatives fixed in this release.

PySentry now writes fresh provider cache entries under new prefixes and ignores the old unversioned entries.

#### Resolution Cache Key Versioning

Dependency resolution cache files now include a format version in their filename. This prevents future serialized payload changes from colliding with older binaries or older cache entries.

---

**Full Changelog**: https://github.com/nyudenkov/pysentry/compare/v0.4.6...v0.4.7

---

## v0.4.6

### ✨ New Features

#### Audit a Single Dependency Group (`--group`)

The new `--group` flag scopes an audit to specific dependency groups instead of the whole dependency tree. It is supported for uv (`uv.lock`), Poetry (`poetry.lock`), and PEP 751 (`pylock.toml`) projects. PySentry audits your main dependencies (`[project].dependencies` / `[tool.poetry.dependencies]`) plus the selected group(s) and their transitive closure, leaving the rest out:

```bash
# Audit main dependencies + the "dev" group only
pysentry-rs --group dev

# Multiple groups (repeatable or comma-separated)
pysentry-rs --group dev --group docs
pysentry-rs --group dev,docs
```

Group names are read from any of the standard locations:

- PEP 735 `[dependency-groups]` (with `include-group` recursion)
- PEP 621 `[project.optional-dependencies]`
- Poetry `[tool.poetry.group.*]`

Names are matched using PEP 735 normalization, so `--group typing-test` matches a declared `typing_test`. An unknown name fails with the list of available groups.

**`--group` requires a lock file.** Group filtering relies on a group-aware lock file — `uv.lock`, `poetry.lock`, or `pylock.toml` (including named `pylock.<name>.toml` variants) — alongside your `pyproject.toml`. On a project without one, PySentry fails fast with a clear error instead of silently auditing the full dependency set. (`Pipfile.lock` is not supported — Pipfile has no dependency-group concept.)

`--group` cannot be combined with `--exclude-extra` (or config `scope = "main"`), `--requirements-files`, or `--no-resolver`. It can also be set in config:

```toml
# .pysentry.toml
[defaults]
groups = ["dev", "docs"]
```

Resolves [#151](https://github.com/nyudenkov/pysentry/issues/151).

### 🐛 Bug Fixes

#### `fail_on` Silently Hid Vulnerabilities Below Its Threshold

`fail_on` (CLI `--fail-on`, config `defaults.fail_on`) is meant to control **only the exit code** — the severity at which an audit is considered a failure. A regression in v0.4.5 instead wired it into the matcher as a minimum-severity filter, so any vulnerability below the `fail_on` level was dropped from the report entirely rather than just being excluded from the pass/fail decision.

The effect scaled with the threshold. With the default `fail_on = "medium"`, low-severity findings disappeared from the report. With `fail_on = "critical"`, a project could contain many real high- and medium-severity vulnerabilities and still print `✓ No vulnerabilities found!` with a clean exit. On one real `uv.lock` project (90 packages), v0.4.5 reported **0** vulnerabilities under `fail_on = "critical"` while the project actually had **31**, several of them high severity.

PySentry now reports every matched vulnerability regardless of `fail_on`, and uses `fail_on` strictly to decide the exit code.

:::warning
If you run PySentry with `fail_on` set above `low` (via `--fail-on` or config), affected vulnerabilities were missing from your reports while the audit may have exited successfully. Re-run your audit on this release.
:::

Regression introduced in v0.4.5; the original decoupling shipped in v0.4.3.

#### Shared PyPA Cache Crashed Older PySentry Versions

v0.4.5 changed the on-disk format of the cached PyPA advisory database from a raw ZIP archive to JSON, but kept writing it to the same cache file. When an older PySentry (`<= 0.4.4`) then read that file, it tried to parse the JSON as a ZIP and crashed with `Cache operation failed: invalid Zip archive: Could not find EOCD`. This bit anyone running multiple PySentry versions against the same cache — for example a project that pins an older `pysentry-rs` in a dependency group while a newer one is installed elsewhere.

The PyPA database now uses a version-tagged cache file, so different formats never collide. New and old versions keep separate cache files and stop corrupting each other's reads. Already-released versions cannot be retro-fixed; if you are still on `<= 0.4.4` and hit this, run once with `--no-cache` or clear `pysentry/vulnerability-db` from your cache directory.

#### `scope = "main"` / `--exclude-extra` Ignored Dependency Groups (uv.lock)

On a `uv.lock` project, `--exclude-extra` (or config `scope = "main"`) did not exclude PEP 735 `[dependency-groups]` such as `dev` — every group member was still scanned, so a vulnerability in a dev-only tool like `pytest` was reported even though you asked for main dependencies only. uv records group members in `uv.lock` without marking *why* they were pulled in, and PySentry did not yet read those group tables.

PySentry now recognizes uv's group encoding and treats `[dependency-groups]` members as optional, so `--exclude-extra` and `scope = "main"` correctly narrow the audit to your main dependencies and their transitive closure.

Resolves [#158](https://github.com/nyudenkov/pysentry/issues/158).

#### Shared Transitive Dependencies Skipped Under `--exclude-extra` (uv.lock)

When auditing a `uv.lock` project with `--exclude-extra` (or config `scope = "main"`), a transitive dependency shared between your main dependencies and an optional dependency (a `[project.optional-dependencies]` extra) — for example a package like `certifi` reached by both — could be misclassified as optional and excluded from the scan.

:::warning
Because an excluded package is never checked, any vulnerabilities in it were silently missed while the audit still reported clean. If you rely on `--exclude-extra` or `scope = "main"` with a `uv.lock` project, re-run your audit on this release.
:::

PySentry now computes the set of packages reachable from `[project].dependencies` and subtracts it from the optional set, so a shared transitive stays in scope as long as a main dependency reaches it. Packages reachable *only* through an extra are still excluded, exactly as before.

This affects `uv.lock` projects with a companion `pyproject.toml`; other lock formats already relied on their native optional markers.

---

**Full Changelog**: https://github.com/nyudenkov/pysentry/compare/v0.4.5...v0.4.6

---

## v0.4.5

### ✨ New Features

#### `--direct-only` Now Works for All Lock File Formats

`--direct-only` now correctly identifies direct dependencies when used with any lock file format — `uv.lock`, `Pipfile.lock`, `poetry.lock`, and `pylock.toml`.

PySentry reads the companion manifest alongside the lock file (pyproject.toml, Pipfile) to determine which packages are declared as direct dependencies. When no companion manifest is found, it falls back to lock-graph inference.

```bash
pysentry-rs --direct-only
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
pysentry-rs --no-resolver
pysentry-rs --no-resolver --requirements-files requirements.txt requirements-prod.txt
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
pysentry-rs --color auto    # Default: auto-detect from terminal and environment
pysentry-rs --color always  # Force colors even when piping to a file or CI log
pysentry-rs --color never   # Disable colors entirely
```

`auto` (default) follows terminal standards: it respects `NO_COLOR` (any value disables colors), `FORCE_COLOR`, `CI`, `TERM=dumb`, and whether stdout is a TTY. Windows ANSI color output is now also enabled automatically.

#### Table Display Mode (`--display`)

Compact output can now render structured tables, making it easier to scan vulnerability data at a glance:

```bash
pysentry-rs --compact                 # Table layout (default)
pysentry-rs --compact --display table # Explicit table layout
pysentry-rs --compact --display text  # Traditional indented text layout
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
