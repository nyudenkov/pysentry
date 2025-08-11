import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict

from .tool_wrapper import ToolRegistry, BenchmarkConfig
from .performance_monitor import PerformanceMetrics, SystemInfo
from .report_generator import ReportGenerator


@dataclass
class BenchmarkResult:
    config_name: str
    tool_name: str
    dataset_name: str
    cache_type: str
    metrics: PerformanceMetrics
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["metrics"] = asdict(self.metrics)
        return data


@dataclass
class BenchmarkSuite:
    system_info: SystemInfo
    results: List[BenchmarkResult]
    start_time: str
    end_time: str
    total_duration: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "system_info": asdict(self.system_info),
            "results": [result.to_dict() for result in self.results],
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_duration": self.total_duration,
        }


class BenchmarkRunner:
    def __init__(self, benchmark_dir: Optional[Path] = None):
        if benchmark_dir is None:
            benchmark_dir = Path(__file__).parent.parent

        self.benchmark_dir = benchmark_dir
        self.test_data_dir = benchmark_dir / "test_data"
        self.results_dir = benchmark_dir / "results"
        self.cache_dir = benchmark_dir / "cache"
        self.workdirs = benchmark_dir / "workdirs"

        self.results_dir.mkdir(exist_ok=True)
        self.cache_dir.mkdir(exist_ok=True)
        self.workdirs.mkdir(exist_ok=True)

        self.tool_registry = ToolRegistry(cache_dir=self.cache_dir)
        self.report_generator = ReportGenerator()

    def initialize_cache_directory(self):
        print(f"Using cache directory: {self.cache_dir}")

        self.cache_dir.mkdir(exist_ok=True)

        if self.cache_dir.exists():
            for cache_file in self.cache_dir.glob("*"):
                if cache_file.is_file():
                    cache_file.unlink()
                elif cache_file.is_dir():
                    shutil.rmtree(cache_file)

        print("Initialized clean cache directory")

    def clear_cache_directory(self):
        print(f"Clearing cache directory: {self.cache_dir}")

        if self.cache_dir.exists():
            for cache_file in self.cache_dir.glob("*"):
                if cache_file.is_file():
                    cache_file.unlink()
                elif cache_file.is_dir():
                    shutil.rmtree(cache_file)

        print("Cache directory cleared")

    def clean_work_directories(self):
        print(f"Cleaning work directories in: {self.workdirs}")

        if self.workdirs.exists():
            for work_dir in self.workdirs.glob("*"):
                if work_dir.is_dir():
                    try:
                        shutil.rmtree(work_dir)
                    except Exception as e:
                        print(f"Warning: Could not remove {work_dir}: {e}")

        print("Work directories cleaned")

    def run_single_benchmark(
        self, config: BenchmarkConfig, dataset_path: Path, cache_type: str
    ) -> BenchmarkResult:
        dataset_name = dataset_path.stem

        print(f"Running {config.config_name} on {dataset_name} ({cache_type} cache)...")

        tool = self.tool_registry.get_tool(config.tool_name)
        if not tool:
            raise ValueError(f"Tool {config.tool_name} not available")

        work_dir_name = f"{dataset_name}_{config.config_name}_{cache_type}"
        work_path = self.workdirs / work_dir_name

        if work_path.exists():
            shutil.rmtree(work_path)
        work_path.mkdir()

        try:
            temp_requirements = work_path / "requirements.txt"
            shutil.copy2(dataset_path, temp_requirements)

            (work_path / "setup.py").write_text("# Minimal setup.py for benchmarking")

            print(f"  Working in: {work_path}")

            use_cache = cache_type == "hot"
            metrics = tool.execute(
                config,
                temp_requirements,
                use_cache=use_cache,
                working_dir=work_path,
                dataset_name=dataset_name,
                cache_type=cache_type,
            )
        except Exception as e:
            print(f"  ✗ Exception during execution: {e}")
            raise

        if metrics.exit_code <= 1:
            try:
                shutil.rmtree(work_path)
            except:
                pass
        else:
            print(f"  ! Work directory preserved for debugging: {work_path}")

        return BenchmarkResult(
            config_name=config.config_name,
            tool_name=config.tool_name,
            dataset_name=dataset_name,
            cache_type=cache_type,
            metrics=metrics,
            timestamp=datetime.now().isoformat(),
        )

    def run_dataset_benchmarks(self, dataset_path: Path) -> List[BenchmarkResult]:
        results = []
        configs = self.tool_registry.get_all_benchmark_configs(dataset_path)

        if not configs:
            print("No benchmark configurations available!")
            return results

        print(
            f"Running benchmarks on {dataset_path.name} ({len(configs)} configurations)"
        )
        print("Testing strategy:")
        print("  - Cold phase: Clear cache → Run cold → Record")
        print("  - Hot phase: Clear cache → Run cold (warmup) → Run hot → Record")

        print(f"\n🧊 COLD TESTING PHASE - {dataset_path.name}")
        print("=" * 60)
        for i, config in enumerate(configs):
            print(f"\nCold test {i + 1}/{len(configs)}: {config.config_name}")
            print("-" * 40)

            print("🧽 Clearing all caches...")
            self.tool_registry.clear_all_caches()

            try:
                cold_result = self.run_single_benchmark(config, dataset_path, "cold")
                results.append(cold_result)
                self._show_result_feedback(cold_result, "cold")

            except Exception as e:
                print(f"  ✗ Error running {config.config_name} (cold): {e}")
                error_result = self._create_error_result(
                    config, dataset_path, "cold", str(e)
                )
                results.append(error_result)

        print(f"\n🔥 HOT TESTING PHASE - {dataset_path.name}")
        print("=" * 60)
        for i, config in enumerate(configs):
            print(f"\nHot test {i + 1}/{len(configs)}: {config.config_name}")
            print("-" * 40)

            print("🧽 Clearing all caches...")
            self.tool_registry.clear_all_caches()

            print("🌡️  Running warmup (cold test to populate cache)...")
            try:
                warmup_result = self.run_single_benchmark(config, dataset_path, "cold")
                if warmup_result.metrics.exit_code <= 1:
                    print(
                        f"  ✓ Warmup completed ({warmup_result.metrics.execution_time:.2f}s)"
                    )
                else:
                    print(
                        f"  ✗ Warmup failed (exit code {warmup_result.metrics.exit_code})"
                    )
            except Exception as e:
                print(f"  ⚠️  Warmup failed: {e}")

            print("🔥 Running hot test (with cache from warmup)...")
            try:
                hot_result = self.run_single_benchmark(config, dataset_path, "hot")
                results.append(hot_result)
                self._show_result_feedback(hot_result, "hot")

            except Exception as e:
                print(f"  ✗ Error running {config.config_name} (hot): {e}")
                error_result = self._create_error_result(
                    config, dataset_path, "hot", str(e)
                )
                results.append(error_result)

        print(f"\n✅ Completed all configurations for {dataset_path.name}")
        return results

    def _show_result_feedback(self, result: BenchmarkResult, cache_type: str):
        if result.metrics.exit_code == 0:
            print(
                f"  ✓ {result.config_name} ({cache_type}): "
                f"{result.metrics.execution_time:.2f}s, "
                f"{result.metrics.peak_memory_mb:.1f}MB (no vulnerabilities)"
            )
        elif result.metrics.exit_code == 1:
            print(
                f"  ✓ {result.config_name} ({cache_type}): "
                f"{result.metrics.execution_time:.2f}s, "
                f"{result.metrics.peak_memory_mb:.1f}MB (vulnerabilities found)"
            )
        else:
            print(
                f"  ✗ {result.config_name} ({cache_type}): FAILED (exit code {result.metrics.exit_code})"
            )

    def _create_error_result(
        self,
        config: BenchmarkConfig,
        dataset_path: Path,
        cache_type: str,
        error_msg: str,
    ) -> BenchmarkResult:
        return BenchmarkResult(
            config_name=config.config_name,
            tool_name=config.tool_name,
            dataset_name=dataset_path.stem,
            cache_type=cache_type,
            metrics=PerformanceMetrics(
                execution_time=0.0,
                peak_memory_mb=0.0,
                avg_memory_mb=0.0,
                cpu_percent=0.0,
                exit_code=-1,
                stdout="",
                stderr=f"Benchmark error: {error_msg}",
            ),
            timestamp=datetime.now().isoformat(),
        )

    def run_full_benchmark_suite(self) -> BenchmarkSuite:
        start_time = datetime.now()
        print(f"Starting full benchmark suite at {start_time.isoformat()}")

        self.clean_work_directories()

        if not self.tool_registry.ensure_pysentry_built():
            raise RuntimeError("Could not build or find PySentry binary")

        available_tools = self.tool_registry.get_available_tools()
        print(f"Available tools: {', '.join(available_tools)}")

        if not available_tools:
            raise RuntimeError("No tools available for benchmarking")

        datasets = []
        for pattern in ["small_requirements.txt", "large_requirements.txt"]:
            dataset_path = self.test_data_dir / pattern
            if dataset_path.exists():
                datasets.append(dataset_path)
            else:
                print(f"Warning: Dataset {pattern} not found")

        if not datasets:
            raise RuntimeError("No benchmark datasets found")

        print(f"Found {len(datasets)} datasets: {[d.name for d in datasets]}")

        all_results = []
        for i, dataset in enumerate(datasets):
            print(f"\n{'=' * 80}")
            print(f"TESTING DATASET {i + 1}/{len(datasets)}: {dataset.name}")
            print(f"{'=' * 80}")

            results = self.run_dataset_benchmarks(dataset)
            all_results.extend(results)
            print(f"Completed {dataset.name}: {len(results)} results")

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        suite = BenchmarkSuite(
            system_info=SystemInfo.get_current(),
            results=all_results,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            total_duration=duration,
        )

        print(f"Benchmark suite completed in {duration:.2f} seconds")
        print(f"Total results: {len(all_results)}")

        return suite

    def get_pysentry_version(self) -> str:
        try:
            pysentry_tool = self.tool_registry.get_tool("pysentry")
            if pysentry_tool and pysentry_tool.binary_path:
                import subprocess

                result = subprocess.run(
                    [str(pysentry_tool.binary_path), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    version_line = result.stdout.strip()
                    if " " in version_line:
                        return version_line.split()[-1]
                    return version_line
        except Exception:
            pass
        return "unknown"

    def save_and_generate_report(self, suite: BenchmarkSuite) -> Path:
        version = self.get_pysentry_version()
        report_filename = f"{version}.md"
        report_path = self.results_dir / report_filename

        print(f"Generating report: {report_path}")

        markdown_content = self.report_generator.generate_report(suite)

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)

        print(f"Report saved to: {report_path}")

        return report_path
