"""pysentry-rs: Security vulnerability auditing tool for Python packages."""

from ._internal import get_version, run_cli

__version__ = get_version()
__all__ = ["get_version", "run_cli", "main"]


def main():
    """CLI entry point that provides the exact same interface as the Rust binary."""
    import sys

    try:
        # Pass all arguments directly to the Rust CLI - this ensures perfect compatibility
        exit_code = run_cli(sys.argv)
        sys.exit(exit_code)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
