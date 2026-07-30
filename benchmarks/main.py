import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.benchmark_runner import DATASETS, MODE_RESOLVE, BenchmarkRunner


def main():
    parser = argparse.ArgumentParser(
        description="PySentry vs pip-audit benchmark suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                 # Full suite (median of --runs per config)
  python main.py --quick         # Only the small resolve dataset
  python main.py --runs 3        # Fewer repetitions per config
        """,
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run only the small resolve dataset for a quick check",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=5,
        help="Repetitions per config; the median is reported (default: 5)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Custom output directory for results (default: ./results/)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    args = parser.parse_args()

    try:
        benchmark_dir = Path(__file__).parent
        runner = BenchmarkRunner(benchmark_dir, runs_per_config=args.runs)
        if args.output_dir:
            runner.results_dir = args.output_dir
            runner.results_dir.mkdir(parents=True, exist_ok=True)

        datasets = (
            [("small_requirements.txt", MODE_RESOLVE)] if args.quick else DATASETS
        )
        if args.quick:
            print("Quick mode: small resolve dataset only")

        print("Starting benchmark suite...")
        suite = runner.run_full_benchmark_suite(datasets=datasets)
        report_path = runner.save_and_generate_report(suite)

        total = len(suite.results)
        successful = len([r for r in suite.results if r.metrics.exit_code <= 1])

        print("\n" + "=" * 60)
        print("BENCHMARK SUITE COMPLETED")
        print("=" * 60)
        print(f"Total configs: {total}")
        print(f"Successful: {successful}")
        print(f"Failed: {total - successful}")
        print(f"Duration: {suite.total_duration:.2f} seconds")
        print(f"Report saved to: {report_path}")
        print("=" * 60)

        if successful != total:
            print(f"WARNING: {total - successful} benchmark configs failed!")
            return 1
        return 0

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
