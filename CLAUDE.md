# CLAUDE.md

**PySentry** - A fast, reliable security vulnerability scanner for Python projects, written in Rust.

## Codebase Map

**Architecture:** Dual interface (Rust binary `pysentry` + Python package `pysentry-rs`)

**Key Modules:**
- `src/main.rs` - CLI entry point
- `src/lib.rs` - `AuditEngine` API (high-level audit orchestrator)
- `src/cache/` - Multi-tier caching
  - `audit.rs` - `AuditCache` interface
  - `storage.rs` - `CacheEntry` abstraction
- `src/dependency/` - Dependency scanning + external resolvers
  - `scanner.rs` - `DependencyScanner` (main orchestration)
  - `resolvers/uv.rs` - UV resolver (preferred, Rust-based)
  - `resolvers/pip_tools.rs` - pip-compile fallback
- `src/parsers/` - 7 parsers with priority system
  - Priority 1: lock.rs (uv.lock), poetry_lock.rs, pipfile_lock.rs, pylock.rs
  - Priority 3: pyproject.rs (requires external resolver)
  - Priority 4: pipfile.rs (requires external resolver)
  - Priority 5: requirements.rs (requires external resolver)
  - See `ParserTrait::priority()` for implementation details
- `src/providers/` - PyPA, PyPI, OSV.dev integrations
- `src/vulnerability/` - Matching engine + database
- `src/output/` - Human, JSON, SARIF, markdown reports
- `src/config.rs` - Hierarchical TOML config

**Cache Locations:** `~/.cache/pysentry/vulnerability-db/`, `~/.cache/pysentry/dependency-resolution/`

## Common Development Commands

### Building & Testing

```bash
# Build release binary
cargo build --release

# Run all tests (embedded #[cfg(test)] modules)
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

# GitHub CLI (READ-ONLY)
gh pr view <number>
gh issue view <number>
```

## Critical Development Rules

**Resolver Isolation (CRITICAL):**
- Resolvers MUST run in isolated temp directories
- ALWAYS force cache to temp dir (`UV_CACHE_DIR`, `PIP_CACHE_DIR`) - never use project cache
- See `UvResolver::create_isolated_temp_dir()` and `PipToolsResolver::create_isolated_temp_dir()` for reference
- Default timeout: 5 minutes (hardcoded) - may fail on slow networks/large dependency trees

**Error Handling:**
- Use `?` operator, NEVER `.unwrap()` or `.expect()` in production code
- Replace `.unwrap()` with `.ok_or_else()` or `.context()` for proper error propagation
- Exception: `let _ = self.cached_*.set()` is intentional (OnceLock set failure is benign)
- All errors should propagate with context or be logged at WARN level
- Never `let _ =` on fallible operations without logging at WARN level

**Parser Priority System:**
- Lower number = higher priority (1-5 scale)
- Lock files (priority 1) always preferred over manifest files (priority 3-5)
- When implementing new parsers, return priority via `ParserTrait::priority()`

**Parser Limitations to Remember:**
- Path dependencies NOT extracted from lock files (virtual/editable installs skipped)
- Poetry 2.x uses different marker format than 1.x (custom deserializer handles this)
- Virtual packages and editable installs are excluded from vulnerability scans

**Cache Safety:**
- NO concurrent access protection - avoid parallel scans on same cache directory
- Write failures only logged at WARN level, never retried
- Resolution cache: 24h TTL, content-based keys (requirements + resolver + Python version)
- Vuln DB cache: 24h TTL, atomic updates

## Rust Guidelines (PySentry-Specific)

**Code Structure:**
- Prefer `module_name.rs` over `mod.rs` (Rust 2024 / Zed guideline)
- Only "why" comments, NO organizational/summary comments
- Full words for variable names (avoid single-letter except standard idioms like `i` for index)

**Safety:**
- Prefer `.get()` over `[]` indexing to avoid panic-on-bounds
- Use `Option` and `Result` extensively, never bypass with unwrap
- All public APIs should return `Result<T>` for fallible operations

## Config & Runtime

**Config Discovery:** `.pysentry.toml` (project) → `~/.config/pysentry/config.toml` (user) → `/etc/pysentry/config.toml` (system)
**Override Env Vars:** `PYSENTRY_CONFIG` (path override), `PYSENTRY_NO_CONFIG` (disable all config)

**CLI Structure:** See src/cli.rs and src/main.rs
- Main: `pysentry [options] [path]`
- Subcommands: `resolvers`, `check-version`, `config {init|show|validate}`
