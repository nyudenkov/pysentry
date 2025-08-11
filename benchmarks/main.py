import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.benchmark_runner import BenchmarkRunner


def main():
    parser = argparse.ArgumentParser(
        description="PySentry vs pip-audit benchmark suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Run full benchmark suite
  python main.py --quick           # Run only small dataset for quick testing
  python main.py --output-dir ./custom-results  # Custom output directory
        """,
    )

    parser.add_argument(
        "--quick", action="store_true", help="Run only small dataset for quick testing"
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Custom output directory for results (default: ./results/)",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip PySentry build check (assume it's already built)",
    )

    args = parser.parse_args()

    try:
        benchmark_dir = Path(__file__).parent
        if args.output_dir:
            runner = BenchmarkRunner(benchmark_dir)
            runner.results_dir = args.output_dir
            runner.results_dir.mkdir(parents=True, exist_ok=True)
        else:
            runner = BenchmarkRunner(benchmark_dir)

        if args.verbose:
            print(f"Benchmark directory: {benchmark_dir}")
            print(f"Results directory: {runner.results_dir}")

        if args.quick:
            print("Quick mode: Running only small dataset...")
            large_dataset = runner.test_data_dir / "large_requirements.txt"
            backup_path = None
            if large_dataset.exists():
                backup_path = runner.test_data_dir / "large_requirements.txt.backup"
                large_dataset.rename(backup_path)

        try:
            print("Starting benchmark suite...")
            suite = runner.run_full_benchmark_suite()

            report_path = runner.save_and_generate_report(suite)

            successful_runs = len(
                [r for r in suite.results if r.metrics.exit_code <= 1]
            )
            total_runs = len(suite.results)

            print("\n" + "=" * 60)
            print("BENCHMARK SUITE COMPLETED")
            print("=" * 60)
            print(f"Total runs: {total_runs}")
            print(f"Successful: {successful_runs}")
            print(f"Failed: {total_runs - successful_runs}")
            print(f"Duration: {suite.total_duration:.2f} seconds")
            print(f"Report saved to: {report_path}")
            print("=" * 60)

            exit_code = 0 if successful_runs == total_runs else 1

            if exit_code != 0:
                print(f"WARNING: {total_runs - successful_runs} benchmark runs failed!")

            return exit_code

        finally:
            if args.quick and backup_path and backup_path.exists():
                backup_path.rename(large_dataset)

    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user.")
        return 1

    except Exception as e:
        print(f"Error running benchmark suite: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
