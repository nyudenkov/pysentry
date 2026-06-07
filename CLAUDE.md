# CLAUDE.md

**PySentry** - A fast, reliable security vulnerability scanner for Python projects, written in Rust.

## Critical Rules - Read First

These override defaults. Violations cause production bugs, panics, or security issues.

**Scope Discipline:**
- NEVER add files, abstractions, dependencies, or features not explicitly requested
- NEVER refactor surrounding code when fixing a bug - fix only what is broken
- NEVER add docstrings, comments, or type annotations to code you did not change
- `src/python.rs` mirrors the `Commands`/`ConfigCommands` match arms from `src/main.rs`. Update it ONLY when: (1) a `Commands`/`ConfigCommands` variant is added or removed, or (2) a function called directly inside a match arm in `main.rs` is renamed or moved to a new module path. Functions called from *within* a handler body (not from the match arm itself) do NOT require `python.rs` changes.

**Resolver Isolation (CRITICAL):**
- Resolvers MUST run in isolated temp directories - shared state causes cross-project contamination
- ALWAYS force cache to temp dir (`UV_CACHE_DIR`, `PIP_CACHE_DIR`) - NEVER use project cache
- Reference: `UvResolver::create_isolated_temp_dir()`, `PipToolsResolver::create_isolated_temp_dir()`
- Default timeout: 5 minutes (hardcoded) - may fail on slow networks/large dependency trees

**Error Handling:**
- MUST use `?` operator. NEVER use `.unwrap()` or `.expect()` in production code - panics crash the binary for all users
- Replace `.unwrap()` with `.ok_or_else()` or `.context()` for propagation
- Exception: `let _ = self.cached_*.set()` is intentional - OnceLock set failure is benign
- All errors MUST propagate with context or be logged at WARN level
- NEVER use `let _ =` on fallible operations without logging at WARN level

**Safety:**
- MUST use `.get()` over `[]` indexing - `[]` panics on out-of-bounds
- MUST use `Option` and `Result` extensively - NEVER bypass with unwrap
- All public APIs MUST return `Result<T>` for fallible operations

## Codebase Map

**Architecture:** Dual interface (Rust binary `pysentry` + Python package `pysentry-rs`)

**Key Modules:**
- `src/main.rs` - CLI entry point
- `src/lib.rs` - `AuditEngine` API (high-level audit orchestrator)
- `src/audit/` - Audit orchestration (split from `cli.rs` in v0.4.5)
  - `merge.rs` - CLI arg / config merging, dependency stats calculation
  - `pipeline.rs` - Main audit pipeline execution
- `src/commands/` - CLI command handlers (split from `cli.rs` in v0.4.5)
  - `config.rs` - `config_init`, `config_validate`, `config_show`
  - `resolvers.rs` - `check_resolvers`
  - `version.rs` - `check_version`
- `src/cache/` - Multi-tier caching
  - `audit.rs` - `AuditCache` interface
  - `storage.rs` - `CacheEntry` abstraction
- `src/dependency/` - Dependency scanning + external resolvers
  - `scanner.rs` - `DependencyScanner` (main orchestration)
  - `resolvers/uv.rs` - UV resolver (preferred, Rust-based)
  - `resolvers/pip_tools.rs` - pip-compile fallback
  - `resolvers/shared.rs` - Shared resolver utilities
- `src/parsers/` - 7 parsers with priority system
  - Priority 1: `lock.rs` (uv.lock), `poetry_lock.rs`, `pipfile_lock.rs`, `pylock.rs`
  - Priority 3: `pyproject.rs` (requires external resolver)
  - Priority 4: `pipfile.rs` (requires external resolver)
  - Priority 5: `requirements.rs` (requires external resolver)
  - `manifest_reader.rs` - Reads direct deps from companion manifests (pyproject.toml, Pipfile)
  - See `ParserTrait::priority()` for implementation details
- `src/providers/` - PyPA, PyPI, OSV.dev integrations
- `src/vulnerability/` - Matching engine + database
- `src/output/` - Human, JSON, SARIF, markdown reports
- `src/config.rs` - Hierarchical TOML config

## Parser Rules

**Priority System:**
- Lower number = higher priority (1–5 scale)
- Lock files (priority 1) ALWAYS take precedence over manifest files (priority 3–5)
- New parsers MUST return priority via `ParserTrait::priority()`

**Known Limitations:**
- Path dependencies NOT extracted from lock files - virtual/editable installs skipped
- Poetry 2.x uses different marker format than 1.x - custom deserializer handles this
- Virtual packages and editable installs are excluded from vulnerability scans

## Cache Safety

- Atomic writes via temp-file + rename pattern - see `CacheEntry::write_atomic_sync`
- Idempotent deletes - `NotFound` errors treated as success
- Write failures only logged at WARN level, NEVER retried - retry storms corrupt the cache
- Resolution cache: 24h TTL, content-based keys (requirements + resolver + Python version)
- Vuln DB cache: 24h TTL

**Cache Locations:** `~/.cache/pysentry/vulnerability-db/`, `~/.cache/pysentry/dependency-resolution/`

## Rust Code Style

- MUST use `module_name.rs` over `mod.rs` - Rust 2024 convention, avoids ambiguous `mod.rs` in nested directories
- Only "why" comments, NEVER organizational/summary comments - code structure MUST be self-documenting
- Full words for variable names (`package_name` not `pkg`) - reduces cognitive load when scanning unfamiliar code. Exception: standard idioms like `i` for index

## Config & Runtime

**Config Discovery:** `.pysentry.toml` (project) → `~/.config/pysentry/config.toml` (user) → `/etc/pysentry/config.toml` (system)
**Override Env Vars:** `PYSENTRY_CONFIG` (path override), `PYSENTRY_NO_CONFIG` (disable all config)

**CLI Structure:** See `src/cli.rs` (arg definitions), `src/audit/pipeline.rs` (audit execution), `src/commands/` (subcommand handlers), `src/main.rs` (dispatch)
- Main: `pysentry [options] [path]`
- Subcommands: `resolvers`, `check-version`, `config {init|show|validate}`

## Development Commands

```bash
# Build
cargo build --release

# Test
cargo test                                             # all tests
cargo test -- --nocapture                              # with output
cargo test test_name                                   # specific test

# Code quality
cargo fmt --all                                        # format
cargo fmt --all -- --check                             # CI format check
cargo clippy --all-targets --all-features              # lint
cargo clippy --all-targets --all-features -- -D warnings  # CI lint (warnings = errors)
cargo check --all-targets --all-features               # type check

# Python bindings (requires maturin)
maturin develop                                        # dev build
maturin build --release                                # release wheel

# Tools
cargo audit                                            # security audit
cd benchmarks && python main.py                        # benchmarks
pre-commit run --all-files                             # hooks
gh pr view <number>                                    # GitHub CLI (READ-ONLY)
gh issue view <number>
```
