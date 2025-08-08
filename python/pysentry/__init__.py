"""pysentry: Security vulnerability auditing tool for Python packages."""

from ._internal import audit_python, audit_with_options, check_resolvers, check_version

__version__ = "0.2.0"
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

    # Handle subcommands manually to match Rust CLI structure exactly
    if len(sys.argv) > 1:
        if sys.argv[1] == "resolvers":
            # Resolvers subcommand
            parser = argparse.ArgumentParser(
                prog="pysentry resolvers",
                description="Check available dependency resolvers",
            )
            parser.add_argument(
                "-v", "--verbose", action="store_true", help="Enable verbose output"
            )

            args = parser.parse_args(sys.argv[2:])
            try:
                result = check_resolvers(args.verbose)
                print(result)
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
            return

        elif sys.argv[1] == "check-version":
            # Check-version subcommand
            parser = argparse.ArgumentParser(
                prog="pysentry-rs check-version",
                description="Check if a newer version is available",
            )
            parser.add_argument(
                "-v", "--verbose", action="store_true", help="Enable verbose output"
            )

            args = parser.parse_args(sys.argv[2:])
            try:
                result = check_version(args.verbose)
                print(result)
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
            return
        elif sys.argv[1] in ["-h", "--help"]:
            # Show main help
            pass
        elif sys.argv[1] in ["-V", "--version"]:
            print(f"pysentry-rs {__version__}")
            return

    # Main parser for audit command (default) and help
    parser = argparse.ArgumentParser(
        prog="pysentry-rs",
        description="Security vulnerability auditing for Python packages",
        usage="pysentry-rs [OPTIONS] [PATH] [COMMAND]",
    )

    # Add version argument
    parser.add_argument(
        "-V", "--version", action="version", version=f"pysentry-rs {__version__}"
    )

    # Main audit arguments
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        metavar="PATH",
        help="Path to the project directory to audit [default: .]",
    )
    parser.add_argument(
        "--format",
        choices=["human", "json", "sarif"],
        default="human",
        help="Output format [default: human] [possible values: human, json, sarif]",
    )
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity level to report [default: low] [possible values: low, medium, high, critical]",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        dest="ignore_ids",
        metavar="ID",
        help="Vulnerability IDs to ignore (can be specified multiple times)",
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE", help="Output file path (defaults to stdout)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Include ALL dependencies (main + dev, optional, etc)",
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
        help="Vulnerability data source [default: pypa] [possible values: pypa, pypi, osv]",
    )
    parser.add_argument(
        "--resolver",
        choices=["uv", "pip-tools"],
        default="uv",
        help="Dependency resolver for requirements.txt files [default: uv] [possible values: uv, pip-tools]",
    )
    parser.add_argument(
        "--requirements-files",
        nargs="+",
        metavar="FILE",
        help="Specific requirements files to audit (disables auto-discovery)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress non-error output"
    )

    # Add custom help text for commands
    parser.epilog = """
Commands:
  resolvers      Check available dependency resolvers
  check-version  Check if a newer version is available
  help           Print this message or the help of the given subcommand(s)
"""

    args = parser.parse_args()

    try:
        # Main audit functionality - convert --all to dev/optional
        dev = args.all
        optional = args.all

        result = audit_with_options(
            path=args.path,
            format=args.format,
            source=args.source,
            min_severity=args.severity,
            ignore_ids=args.ignore_ids,
            output=args.output,
            dev=dev,
            optional=optional,
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
