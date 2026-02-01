---
sidebar_position: 1
---

# Installation

Choose the installation method that works best for you.

## Via uvx (Recommended for occasional use)

Run directly without installing (requires [uv](https://docs.astral.sh/uv/)):

```bash
uvx pysentry-rs /path/to/project
```

This method:

- Runs the latest version without installation
- Automatically manages Python environment
- Perfect for CI/CD or occasional security audits
- No need to manage package versions or updates

## From PyPI (Python Package)

For Python 3.9-3.14 on Linux, macOS, and Windows:

```bash
pip install pysentry-rs
```

Then use it with Python:

```bash
python -m pysentry /path/to/project
# or directly if scripts are in PATH
pysentry-rs /path/to/project
```

## From Crates.io (Rust Package)

If you have Rust installed:

```bash
cargo install pysentry
```

## From GitHub Releases (Pre-built Binaries)

Download the latest release for your platform:

- **Linux x64**: `pysentry-linux-x64.tar.gz`
- **Linux x64 (musl)**: `pysentry-linux-x64-musl.tar.gz`
- **Linux ARM64**: `pysentry-linux-arm64.tar.gz`
- **macOS x64**: `pysentry-macos-x64.tar.gz`
- **macOS ARM64**: `pysentry-macos-arm64.tar.gz`
- **Windows x64**: `pysentry-windows-x64.zip`

```bash
# Example for Linux x64
curl -L https://github.com/nyudenkov/pysentry/releases/latest/download/pysentry-linux-x64.tar.gz | tar -xz
./pysentry-linux-x64/pysentry --help
```

## From Source

```bash
git clone https://github.com/nyudenkov/pysentry
cd pysentry
cargo build --release
```

The binary will be available at `target/release/pysentry`.

## Requirements

| Method | Requirements |
|--------|-------------|
| uvx | Python 3.9-3.14 and [uv](https://docs.astral.sh/uv/) |
| Binaries | No additional dependencies |
| Python package | Python 3.9-3.14 |
| Rust package / Source | Rust 1.79+ |

## Platform Support

| Installation Method | Linux (x64) | Linux (ARM64) | macOS (x64) | macOS (ARM64) | Windows (x64) |
|---------------------|-------------|---------------|-------------|---------------|---------------|
| uvx | ✅ | ✅ | ✅ | ✅ | ✅ |
| PyPI (pip) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Crates.io (cargo) | ✅ | ✅ | ✅ | ✅ | ✅ |
| GitHub Releases | ✅ | ✅ | ✅ | ✅ | ✅ |
| From Source | ✅ | ✅ | ✅ | ✅ | ✅ |

**Supported Python Versions**: 3.9, 3.10, 3.11, 3.12, 3.13, 3.14

**Supported Architectures**: x86_64 (x64), ARM64 (aarch64)

## CLI Command Names

- **Rust binary**: `pysentry` (when installed via cargo or binary releases)
- **Python package**: `pysentry-rs` (when installed via pip or uvx)

Both variants support identical functionality. The resolver tools (`uv`, `pip-tools`) must be available in your current environment regardless of which PySentry variant you use.
