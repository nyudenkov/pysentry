"""pysentry-rs: Security vulnerability auditing tool for Python packages."""

import sys
import threading

from ._internal import get_version, run_cli

__version__ = get_version()
__all__ = ["get_version", "run_cli", "main"]


def main():
    """CLI entry point that provides the exact same interface as the Rust binary."""
    result = [None]
    exception = [None]

    def worker():
        try:
            result[0] = run_cli(sys.argv)
        except Exception as e:
            exception[0] = e

    # Run Rust code in daemon thread so main thread can handle signals
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    try:
        while thread.is_alive():
            thread.join(timeout=0.1)  # Check for signals every 100ms
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        sys.exit(130)  # 128 + SIGINT(2) - Unix convention

    if exception[0] is not None:
        print(f"Error: {exception[0]}", file=sys.stderr)
        sys.exit(1)

    sys.exit(result[0] if result[0] is not None else 1)


if __name__ == "__main__":
    main()
