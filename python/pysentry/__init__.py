"""pysentry: Security vulnerability auditing tool for Python packages."""

from ._internal import audit_python, audit_with_options

__version__ = "0.1.1"
__all__ = ["audit_python", "audit_with_options", "main"]


def main():
    """CLI entry point."""
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        prog="pysentry-rs", description="Audit Python packages for vulnerabilities"
    )
    parser.add_argument("path", help="Path to Python project")
    parser.add_argument(
        "--format",
        choices=["human", "json", "sarif"],
        default="human",
        help="Output format",
    )
    parser.add_argument(
        "--source",
        choices=["pypa", "pypi", "osv"],
        default="pypa",
        help="Vulnerability data source",
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity level",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        dest="ignore_ids",
        help="Vulnerability IDs to ignore (can be used multiple times)",
    )

    args = parser.parse_args()

    try:
        if args.source != "pypa" or args.min_severity != "low" or args.ignore_ids:
            result = audit_with_options(
                args.path, args.format, args.source, args.min_severity, args.ignore_ids
            )
        else:
            result = audit_python(args.path, args.format)

        print(result)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
