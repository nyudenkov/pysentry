# Contributing to PySentry

Thank you for your interest in contributing to PySentry.

## Prerequisites

- Rust toolchain (stable) — install via [rustup](https://rustup.rs/)
- Python 3.8+ (for Python bindings)
- [maturin](https://github.com/PyO3/maturin) for Python bindings development
- [pre-commit](https://pre-commit.com/) for running hooks locally

## Building

```bash
cargo build --release
```

## Running Tests

```bash
# All tests
cargo test

# With output
cargo test -- --nocapture

# Specific test
cargo test test_name
```

## Code Quality

Before submitting a pull request, ensure all checks pass:

```bash
cargo fmt --all                                            # Format
cargo clippy --all-targets --all-features -- -D warnings   # Lint (warnings = errors)
cargo check --all-targets --all-features                   # Type check
pre-commit run --all-files                                 # All hooks
```

## Submitting Changes

1. Fork the repository and create a branch from `dev`.
2. Make your changes, following the code style guidelines below.
3. Add tests for any new functionality.
4. Ensure all checks pass (see above).
5. Open a pull request against the `dev` branch.

## Python Bindings

```bash
maturin develop   # Development build
maturin build --release  # Release wheel
```
