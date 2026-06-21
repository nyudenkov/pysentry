# CLAUDE.md

**PySentry** - A fast, reliable security vulnerability scanner for Python projects, written in Rust.

## Critical Rules - Read First

These override defaults. Violations cause production bugs, panics, or security issues.

**Scope Discipline:**
- NEVER add files, abstractions, dependencies, or features not explicitly requested
- NEVER refactor surrounding code when fixing a bug - fix only what is broken
- NEVER add docstrings, comments, or type annotations to code you did not change

**Stability Policy:**
- The CLI is the ONLY stable interface. Public Rust API stability is a non-goal - never propose compat shims or deprecation cycles for `lib.rs` items; prefer breaking changes. (The `rlib` crate type exists solely for the Python bindings.)
- `gh` CLI is READ-ONLY in this repo: `gh pr view`, `gh issue view`, etc. NEVER create/edit/comment via `gh`

**Resolver Isolation (CRITICAL):**
- Resolvers MUST run in isolated temp directories - shared state causes cross-project contamination
- ALWAYS force cache to temp dir (`UV_CACHE_DIR`, `PIP_CACHE_DIR`) - NEVER use project cache
- Reference: `UvResolver::create_isolated_temp_dir()`, `PipToolsResolver::create_isolated_temp_dir()`
- Default timeout: 5 minutes (hardcoded) - may fail on slow networks/large dependency trees

**Error Handling & Safety:**
- MUST use `?` operator and propagate errors with context (`.ok_or_else()`, `.context()`) - panics crash the binary for all users
- `.unwrap()`/`.expect()` are forbidden in production code. Exceptions: tests, and infallible-by-invariant calls (e.g. `write!` into a `String`) which MUST carry a `// invariant: ...` comment explaining why they cannot fail
- Exception: `let _ = self.cached_*.set()` is intentional - OnceLock set failure is benign
- NEVER use `let _ =` on other fallible operations without logging at WARN level - silently swallowed errors are undebuggable in the field
- MUST use `.get()` over `[]` indexing - `[]` panics on out-of-bounds
- All public APIs MUST return `Result<T>` for fallible operations

**Behavioral Invariants (each shipped as a bug at least once):**
- `fail_on` selects the EXIT CONDITION only - it must NEVER filter matching, reporting, or display. This regressed twice (v0.4.3, v0.4.6); `build_matcher_config` in `src/audit/pipeline.rs` pins `min_severity=Low` with a guard comment - do not "optimize" it
- Compare package names ONLY via `PackageName` (`src/types.rs`), never raw strings - raw comparison caused cross-package vulnerability contamination (v0.4.4). `PackageName::new` performs full PEP 503 normalization (lowercase, then collapse `[-_.]+` runs to a single `-`), so `zope.interface`, `Zope_Interface`, and `zope-interface` all compare equal. Do NOT re-implement name normalization elsewhere - route every comparison through `PackageName` (a property test in `src/types.rs` pins this against the PEP 503 reference)

## Cross-File Invariants

When you change the left column, you MUST also do the middle column:

| If you change | You must also | Verify with |
|---|---|---|
| `Commands`/`ConfigCommands` dispatch in `src/main.rs` | mirror it in `src/python.rs` | `cargo check --all-features` |
| Serialization format of any cached payload | bump that cache's version marker (see Cache Safety) | grep `pypa-v2` / `RESOLUTION_CACHE_FORMAT_VERSION` |
| CLI args with `conflicts_with` constraints | re-check the invariant post-merge in `perform_audit` - clap only validates CLI args, NOT config-file values merged in later | regression test |
| Version in `Cargo.toml` | update hardcoded version strings in `README.md`, `docs/docs/troubleshooting.md`, `.github/ISSUE_TEMPLATE/bug_report.yml` (`pyproject.toml` is dynamic via maturin - no edit needed) | `rg '<old-version>'` returns nothing |
| Any user-facing option (new flag, or changed semantics) | wire BOTH entry paths - the CLI flag in `cli.rs` AND the config field through `merge.rs` - and test via a config file, not just the CLI. Three shipped bugs came from options that worked on one path only | regression test with a `.pysentry.toml` fixture |

Note on `python.rs`: it is feature-gated (`#[cfg(feature = "python")]` in `lib.rs`), so plain `cargo check` will NOT compile it - drift only surfaces under `--all-features`. Do not edit `python.rs` preemptively; the exhaustive match makes the compiler catch real drift.

## Definition of Done

Before declaring any change complete, the gate must pass. Run it with one command:

```bash
just done
```

`just done` runs all three checks below. If `just` is unavailable, run them directly (`--all-features` is load-bearing - it compiles the feature-gated `python.rs`; note `cargo test` itself runs on default features because `--all-features` cannot link a test binary against the pyo3 extension-module):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Codebase Map

**Architecture:** Dual interface (Rust binary `pysentry` + Python package `pysentry-rs`)

One line per directory; read the module's `mod.rs`/source for current file layout.

- `src/main.rs` - CLI entry point and command dispatch
- `src/lib.rs` - `AuditEngine` API (high-level audit orchestrator)
- `src/cli.rs` - clap arg definitions
- `src/audit/` - Audit orchestration: CLI/config merging (`merge.rs`), pipeline execution (`pipeline.rs`)
- `src/commands/` - Subcommand handlers (`config`, `resolvers`, `check-version`)
- `src/cache/` - Multi-tier caching (`AuditCache`, `CacheEntry`)
- `src/dependency/` - Dependency scanning + external resolvers (uv preferred, pip-tools fallback)
- `src/parsers/` - Lock file and manifest parsers with priority system (see Parser Rules)
- `src/providers/` - Vulnerability data sources: PyPA, PyPI, OSV.dev + shared retry logic
- `src/vulnerability/` - Matching engine + database
- `src/output/` - Human, JSON, SARIF, markdown reports
- `src/maintenance/` - Package maintenance status checks
- `src/notifications/` - User-facing notices (e.g. version updates)
- `src/ci.rs` - CI environment detection
- `src/config.rs` - Hierarchical TOML config
- `src/python.rs` - PyO3 bindings mirroring `main.rs` dispatch (feature-gated, see Cross-File Invariants)

## Parser Rules

**Priority System:**
- Lower number = higher priority (1–5 scale); lock files ALWAYS take precedence over manifest files
- Priority 1 (lock files): `lock.rs` (uv.lock), `poetry_lock.rs`, `pipfile_lock.rs`, `pylock.rs`
- Priority 3–5 (manifests, require external resolver): `pyproject.rs` (3), `pipfile.rs` (4), `requirements.rs` (5)
- When adding a parser: return its priority via `ParserTrait::priority()`
- `manifest_reader.rs` reads direct deps from companion manifests (pyproject.toml, Pipfile)

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
- **Versioned cache keys:** any change to a cached payload's serialization format MUST bump that cache's version marker so old and new binaries never read each other's files. Vuln DB: the source string passed to `database_entry` (e.g. `pypa-v2`). Resolution: `RESOLUTION_CACHE_FORMAT_VERSION` in `src/cache/audit.rs`. The PyPA case is why this rule exists — releases ≤0.4.4 read JSON as a ZIP and panicked in `ZipArchive::new`.

**Cache Locations:** `~/.cache/pysentry/vulnerability-db/`, `~/.cache/pysentry/dependency-resolution/`

## Rust Code Style

- New modules use `module_name.rs` (Rust 2024 convention). Existing `mod.rs` files stay as-is - renaming them is a forbidden drive-by refactor
- Only "why" comments, NEVER organizational/summary comments - code structure MUST be self-documenting
- Full words for variable names (`package_name` not `pkg`) - reduces cognitive load when scanning unfamiliar code. Exception: standard idioms like `i` for index

## Config & Runtime

**Config Discovery:** `.pysentry.toml` (project) → `~/.config/pysentry/config.toml` (user) → `/etc/pysentry/config.toml` (system)
**Override Env Vars:** `PYSENTRY_CONFIG` (path override), `PYSENTRY_NO_CONFIG` (disable all config)

**CLI Structure:** See `src/cli.rs` (arg definitions), `src/audit/pipeline.rs` (audit execution), `src/commands/` (subcommand handlers), `src/main.rs` (dispatch)
- Main: `pysentry [options] [path]`
- Subcommands: `resolvers`, `check-version`, `config {init|show|validate}`

## Git Workflow

- Feature work lands on `dev`; releases merge `dev` → `main` via PR. NEVER target `main` directly
- Commit subjects: lowercase `type:` prefix - `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `ci:`, `deps:`, and `ai:` for agent-tooling changes (CLAUDE.md, .claude/). Release commits are bare `vX.Y.Z`
- `AGENTS.md` is a symlink to `CLAUDE.md` - edit `CLAUDE.md` only
- Benchmarks are added AFTER a release via a `benchmark-X.Y.Z` branch - not part of the release PR

## Development Commands

```bash
# Build
cargo build --release

# Test
cargo test                                             # all tests
cargo test -- --nocapture                              # with output
cargo test test_name                                   # specific test

# Code quality (see Definition of Done for the required gate)
just done                                              # full gate: fmt-check + clippy + test
cargo fmt --all                                        # format
cargo clippy --all-targets --all-features              # lint
cargo check --all-targets --all-features               # type check

# Python bindings (requires maturin)
maturin develop                                        # dev build
maturin build --release                                # release wheel

# Tools
cargo audit                                            # security audit
cd benchmarks && python main.py                        # benchmarks
pre-commit run --all-files                             # hooks
gh pr view <number>                                    # GitHub CLI - READ-ONLY (see Stability Policy)
gh issue view <number>
```
