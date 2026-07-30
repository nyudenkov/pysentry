import json
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .performance_monitor import AggregatedMetrics, RunResult, SystemInfo, aggregate
from .report_generator import ReportGenerator
from .tool_wrapper import (
    MODE_AUDIT_ONLY,
    MODE_RESOLVE,
    BenchmarkConfig,
    ToolRegistry,
)

# (filename, mode). "resolve" datasets use unpinned specs and exercise the
# resolver; the "audit-only" dataset is pinned and reproducible (see README).
DATASETS = [
    ("small_requirements.txt", MODE_RESOLVE),
    ("large_requirements.txt", MODE_RESOLVE),
    ("pinned_requirements.txt", MODE_AUDIT_ONLY),
    # Real large manifest (~690 pkgs, Apache Airflow constraints) — scale check.
    ("pinned_large_requirements.txt", MODE_AUDIT_ONLY),
]


@dataclass
class BenchmarkResult:
    config_name: str
    tool_name: str
    dataset_name: str
    mode: str
    cache_type: str
    command: str
    metrics: AggregatedMetrics
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["metrics"] = asdict(self.metrics)
        return data


@dataclass
class BenchmarkSuite:
    system_info: SystemInfo
    tool_versions: dict[str, str]
    dataset_packages: dict[str, int]
    runs_per_config: int
    results: list[BenchmarkResult]
    start_time: str
    end_time: str
    total_duration: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "system_info": asdict(self.system_info),
            "tool_versions": self.tool_versions,
            "dataset_packages": self.dataset_packages,
            "runs_per_config": self.runs_per_config,
            "results": [result.to_dict() for result in self.results],
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_duration": self.total_duration,
        }


def _package_count(path: Path) -> int:
    lines = path.read_text(encoding="utf-8").splitlines()
    return sum(
        1 for line in lines if line.strip() and not line.lstrip().startswith("#")
    )


def _command_str(config: BenchmarkConfig) -> str:
    parts = list(config.command_args)
    if parts:
        parts[0] = Path(parts[0]).name  # basename of the binary, not abs path
    return " ".join(parts) + " <path>"


class BenchmarkRunner:
    def __init__(self, benchmark_dir: Path | None = None, runs_per_config: int = 5):
        if benchmark_dir is None:
            benchmark_dir = Path(__file__).parent.parent
        # Absolute so the path handed to each tool is unambiguous even though we
        # also set its cwd to the workdir (a relative path double-nests).
        benchmark_dir = benchmark_dir.resolve()

        self.benchmark_dir = benchmark_dir
        self.test_data_dir = benchmark_dir / "test_data"
        self.results_dir = benchmark_dir / "results"
        self.cache_dir = benchmark_dir / "cache"
        self.workdirs = benchmark_dir / "workdirs"
        self.runs_per_config = runs_per_config

        self.results_dir.mkdir(exist_ok=True)
        self.cache_dir.mkdir(exist_ok=True)
        self.workdirs.mkdir(exist_ok=True)

        self.tool_registry = ToolRegistry(cache_dir=self.cache_dir)
        self.report_generator = ReportGenerator()

    def clean_work_directories(self):
        if self.workdirs.exists():
            for work_dir in self.workdirs.glob("*"):
                if work_dir.is_dir():
                    try:
                        shutil.rmtree(work_dir)
                    except Exception as e:
                        print(f"Warning: Could not remove {work_dir}: {e}")

    def _run_once(
        self, config: BenchmarkConfig, dataset_path: Path, cache_type: str
    ) -> RunResult:
        tool = self.tool_registry.get_tool(config.tool_name)
        if not tool:
            raise ValueError(f"Tool {config.tool_name} not available")

        work_dir_name = f"{dataset_path.stem}_{config.config_name}_{cache_type}"
        work_path = self.workdirs / work_dir_name
        if work_path.exists():
            shutil.rmtree(work_path)
        work_path.mkdir()

        temp_requirements = work_path / "requirements.txt"
        shutil.copy2(dataset_path, temp_requirements)

        result = tool.execute(
            config, temp_requirements, working_dir=work_path, cache_type=cache_type
        )

        if result.exit_code <= 1:
            shutil.rmtree(work_path, ignore_errors=True)
        else:
            print(f"  ! Work directory preserved for debugging: {work_path}")
        return result

    def run_config(
        self, config: BenchmarkConfig, dataset_path: Path, mode: str, cache_type: str
    ) -> BenchmarkResult:
        print(
            f"Running {config.config_name} on {dataset_path.stem} "
            f"({cache_type} cache, {self.runs_per_config} runs)..."
        )

        if cache_type == "hot":
            self.tool_registry.clear_all_caches()
            # Warm with a real hot run: a cold run appends --no-cache for pysentry,
            # which suppresses cache *writes* too, so it would populate nothing and
            # the first measured run would pay the full fetch.
            print("🌡️  Warmup (hot run to populate cache)...")
            self._run_once(config, dataset_path, "hot")

        runs: list[RunResult] = []
        for i in range(self.runs_per_config):
            if cache_type == "cold":
                self.tool_registry.clear_all_caches()
            runs.append(self._run_once(config, dataset_path, cache_type))
            print(
                f"    run {i + 1}/{self.runs_per_config}: "
                f"{runs[-1].execution_time:.3f}s, "
                f"{runs[-1].peak_memory_mb:.1f}MB, "
                f"exit {runs[-1].exit_code}"
            )

        metrics = aggregate(runs)
        self._show_result_feedback(config.config_name, cache_type, metrics)

        return BenchmarkResult(
            config_name=config.config_name,
            tool_name=config.tool_name,
            dataset_name=dataset_path.stem,
            mode=mode,
            cache_type=cache_type,
            command=_command_str(config),
            metrics=metrics,
            timestamp=datetime.now().isoformat(),
        )

    def run_dataset_benchmarks(
        self, dataset_path: Path, mode: str
    ) -> list[BenchmarkResult]:
        configs = self.tool_registry.get_all_benchmark_configs(dataset_path, mode)
        if not configs:
            print("No benchmark configurations available!")
            return []

        cache_types = ["cold", "hot"]
        results = []
        for cache_type in cache_types:
            for config in configs:
                try:
                    results.append(
                        self.run_config(config, dataset_path, mode, cache_type)
                    )
                except Exception as e:
                    print(f"  ✗ Error running {config.config_name} ({cache_type}): {e}")
                    results.append(
                        self._error_result(
                            config, dataset_path, mode, cache_type, str(e)
                        )
                    )
        return results

    def _show_result_feedback(
        self, config_name: str, cache_type: str, metrics: AggregatedMetrics
    ):
        if metrics.exit_code <= 1:
            print(
                f"  ✓ {config_name} ({cache_type}): "
                f"median {metrics.execution_time:.3f}s "
                f"(min {metrics.time_min:.3f}s, ±{metrics.time_stdev:.3f}s), "
                f"{metrics.peak_memory_mb:.1f}MB, "
                f"{metrics.canonical_vulns} vulns (reported {metrics.raw_vulns})"
            )
        else:
            print(
                f"  ✗ {config_name} ({cache_type}): FAILED "
                f"(exit code {metrics.exit_code})"
            )

    def _error_result(
        self,
        config: BenchmarkConfig,
        dataset_path: Path,
        mode: str,
        cache_type: str,
        error_msg: str,
    ) -> BenchmarkResult:
        return BenchmarkResult(
            config_name=config.config_name,
            tool_name=config.tool_name,
            dataset_name=dataset_path.stem,
            mode=mode,
            cache_type=cache_type,
            command=_command_str(config),
            metrics=AggregatedMetrics(
                execution_time=0.0,
                peak_memory_mb=0.0,
                time_min=0.0,
                time_stdev=0.0,
                mem_min=0.0,
                mem_stdev=0.0,
                raw_vulns=-1,
                canonical_vulns=-1,
                exit_code=-1,
                runs=0,
            ),
            timestamp=datetime.now().isoformat(),
        )

    def run_full_benchmark_suite(
        self, datasets: list[tuple] | None = None
    ) -> BenchmarkSuite:
        start_time = datetime.now()
        print(f"Starting full benchmark suite at {start_time.isoformat()}")

        self.clean_work_directories()

        if not self.tool_registry.ensure_pysentry_built():
            raise RuntimeError("Could not build or find PySentry binary")

        available_tools = self.tool_registry.get_available_tools()
        print(f"Available tools: {', '.join(available_tools)}")
        if not available_tools:
            raise RuntimeError("No tools available for benchmarking")

        resolved = []
        for filename, mode in datasets or DATASETS:
            path = self.test_data_dir / filename
            if path.exists():
                resolved.append((path, mode))
            else:
                print(f"Warning: Dataset {filename} not found")
        if not resolved:
            raise RuntimeError("No benchmark datasets found")

        all_results = []
        for i, (dataset, mode) in enumerate(resolved):
            print(f"\n{'=' * 80}")
            print(f"DATASET {i + 1}/{len(resolved)}: {dataset.name} (mode: {mode})")
            print(f"{'=' * 80}")
            all_results.extend(self.run_dataset_benchmarks(dataset, mode))

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        suite = BenchmarkSuite(
            system_info=SystemInfo.get_current(),
            tool_versions=self._tool_versions(),
            dataset_packages={p.stem: _package_count(p) for p, _ in resolved},
            runs_per_config=self.runs_per_config,
            results=all_results,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            total_duration=duration,
        )

        print(f"Benchmark suite completed in {duration:.2f} seconds")
        print(f"Total results: {len(all_results)}")
        return suite

    def _tool_versions(self) -> dict[str, str]:
        return {name: tool.version() for name, tool in self.tool_registry.tools.items()}

    def get_pysentry_version(self) -> str:
        tool = self.tool_registry.get_tool("pysentry")
        return tool.version() if tool else "unknown"

    def save_and_generate_report(self, suite: BenchmarkSuite) -> Path:
        version = suite.tool_versions.get("pysentry", "unknown")
        report_path = self.results_dir / f"{version}.md"

        markdown_content = self.report_generator.generate_report(suite)
        report_path.write_text(markdown_content, encoding="utf-8")
        print(f"Report saved to: {report_path}")

        json_path = self.results_dir / f"{version}.json"
        suite_dict = suite.to_dict()
        suite_dict["pysentry_version"] = version
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(suite_dict, f, indent=2)
        print(f"JSON data saved to: {json_path}")

        return report_path
