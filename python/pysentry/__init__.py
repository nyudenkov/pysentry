"""pysentry: Security vulnerability auditing tool for Python packages."""

from ._internal import audit_python, audit_with_options, check_resolvers, check_version

__version__ = "0.1.5"
__all__ = [
    "audit_python",
    "audit_with_options",
    "check_resolvers",
    "check_version",
    "main",
]


def main():
    """CLI entry point."""
    import sys
    import argparse

    # Handle the case where first argument is 'resolvers'
    if len(sys.argv) > 1 and sys.argv[1] == "resolvers":
        # Parse resolvers subcommand
        parser = argparse.ArgumentParser(
            prog="pysentry-rs resolvers",
            description="Check available dependency resolvers",
        )
        parser.add_argument(
            "--verbose", "-v", action="store_true", help="Enable verbose output"
        )

        # Remove 'resolvers' from args and parse the rest
        args = parser.parse_args(sys.argv[2:])

        try:
            result = check_resolvers(args.verbose)
            print(result)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # Handle the case where first argument is 'check-version'
    if len(sys.argv) > 1 and sys.argv[1] == "check-version":
        # Parse check-version subcommand
        parser = argparse.ArgumentParser(
            prog="pysentry-rs check-version",
            description="Check if a newer version is available",
        )
        parser.add_argument(
            "--verbose", "-v", action="store_true", help="Enable verbose output"
        )

        # Remove 'check-version' from args and parse the rest
        args = parser.parse_args(sys.argv[2:])

        try:
            result = check_version(args.verbose)
            print(result)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # Default audit command parser
    parser = argparse.ArgumentParser(
        prog="pysentry-rs",
        description="Security vulnerability auditing for Python packages",
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to the project directory to audit (default: current directory)",
    )
    parser.add_argument(
        "--format",
        choices=["human", "json", "sarif"],
        default="human",
        help="Output format (default: human)",
    )
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity level to report (default: low)",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        dest="ignore_ids",
        metavar="ID",
        help="Vulnerability IDs to ignore (can be specified multiple times)",
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE", help="Output file path (defaults to stdout)"
    )
    parser.add_argument(
        "--dev", action="store_true", help="Include development dependencies"
    )
    parser.add_argument(
        "--optional", action="store_true", help="Include optional dependencies"
    )
    parser.add_argument(
        "--direct-only",
        action="store_true",
        help="Only check direct dependencies (exclude transitive)",
    )
    parser.add_argument("--no-cache", action="store_true", help="Disable caching")
    parser.add_argument("--cache-dir", metavar="DIR", help="Custom cache directory")
    parser.add_argument(
        "--source",
        choices=["pypa", "pypi", "osv"],
        default="pypa",
        help="Vulnerability data source (default: pypa)",
    )
    parser.add_argument(
        "--resolver",
        choices=["uv", "pip-tools"],
        default="uv",
        help="Dependency resolver for requirements.txt files (default: uv)",
    )
    parser.add_argument(
        "--requirements-files",
        nargs="+",
        metavar="FILE",
        help="Specific requirements files to audit (disables auto-discovery)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress non-error output"
    )

    args = parser.parse_args()

    try:
        # Main audit functionality
        result = audit_with_options(
            path=args.path,
            format=args.format,
            source=args.source,
            min_severity=args.severity,
            ignore_ids=args.ignore_ids,
            output=args.output,
            dev=args.dev,
            optional=args.optional,
            direct_only=args.direct_only,
            no_cache=args.no_cache,
            cache_dir=args.cache_dir,
            resolver=args.resolver,
            requirements_files=args.requirements_files,
            verbose=args.verbose,
            quiet=args.quiet,
        )

        if not args.output:
            print(result)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
