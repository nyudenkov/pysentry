from typing import List, Dict
from dataclasses import dataclass
from datetime import datetime
import statistics

from .performance_monitor import format_memory, format_time


@dataclass
class ComparisonResult:
    winner: str
    loser: str
    improvement_factor: float
    metric_name: str
    winner_value: float
    loser_value: float


class ReportGenerator:
    def generate_report(self, suite) -> str:
        sections = []
        sections.append(self._generate_header(suite))
        sections.append(self._generate_executive_summary(suite))
        sections.append(self._generate_system_info(suite))
        sections.append(self._generate_performance_tables(suite))
        sections.append(self._generate_detailed_analysis(suite))

        return "\n\n".join(sections)

    def _generate_header(self, suite) -> str:
        timestamp = datetime.fromisoformat(suite.start_time).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        duration = format_time(suite.total_duration)

        return f"""# PySentry - pip-audit Benchmark Report

**Generated:** {timestamp}
**Duration:** {duration}
**Total Tests:** {len(suite.results)}"""

    def _generate_executive_summary(self, suite) -> str:
        results_by_config = self._group_results(suite.results)

        summaries = []

        for key, results in results_by_config.items():
            dataset, cache_type = key

            if len(results) < 2:
                continue

            fastest = min(results, key=lambda r: r.metrics.execution_time)
            slowest = max(results, key=lambda r: r.metrics.execution_time)

            most_efficient = min(results, key=lambda r: r.metrics.peak_memory_mb)
            least_efficient = max(results, key=lambda r: r.metrics.peak_memory_mb)

            speed_improvement = (
                slowest.metrics.execution_time / fastest.metrics.execution_time
            )
            memory_improvement = (
                least_efficient.metrics.peak_memory_mb
                / most_efficient.metrics.peak_memory_mb
            )

            summaries.append(f"""### {dataset.title()} Dataset - {cache_type.title()} Cache
- **Fastest:** {fastest.config_name} ({format_time(fastest.metrics.execution_time)}) - {speed_improvement:.2f}x faster than slowest
- **Memory Efficient:** {most_efficient.config_name} ({format_memory(most_efficient.metrics.peak_memory_mb)}) - {memory_improvement:.2f}x less memory than highest""")

        successful_runs = [r for r in suite.results if r.metrics.exit_code <= 1]
        success_rate = len(successful_runs) / len(suite.results) * 100

        header = f"""## Executive Summary

**Overall Success Rate:** {success_rate:.1f}% ({len(successful_runs)}/{len(suite.results)} successful runs)

"""

        return header + "\n\n".join(summaries)

    def _generate_system_info(self, suite) -> str:
        sys_info = suite.system_info

        return f"""## Test Environment

- **Platform:** {sys_info.platform}
- **Python Version:** {sys_info.python_version}
- **CPU Cores:** {sys_info.cpu_count}
- **Total Memory:** {sys_info.total_memory_gb:.2f} GB
- **Available Memory:** {sys_info.available_memory_gb:.2f} GB"""

    def _generate_performance_tables(self, suite) -> str:
        sections = []

        results_by_config = self._group_results(suite.results)

        for (dataset, cache_type), results in results_by_config.items():
            if not results:
                continue

            sections.append(
                f"### {dataset.title()} Dataset - {cache_type.title()} Cache"
            )

            sections.append("#### Execution Time Comparison")
            sections.append(
                self._create_performance_table(
                    results, "execution_time", "Execution Time", format_time
                )
            )

            sections.append("#### Memory Usage Comparison")
            sections.append(
                self._create_performance_table(
                    results, "peak_memory_mb", "Peak Memory", format_memory
                )
            )

        return "\n\n".join(["## Performance Comparison"] + sections)

    def _create_performance_table(
        self, results: List, metric_attr: str, metric_name: str, formatter
    ) -> str:
        """Create a performance comparison table."""
        if not results:
            return "No data available."

        sorted_results = sorted(results, key=lambda r: getattr(r.metrics, metric_attr))

        rows = [
            "| Tool Configuration | " + metric_name + " | Relative Performance |",
            "|---------------------|---------------------|---------------------|",
        ]

        best_value = getattr(sorted_results[0].metrics, metric_attr)

        for result in sorted_results:
            value = getattr(result.metrics, metric_attr)
            relative = value / best_value if best_value > 0 else 1.0

            status_emoji = (
                "🥇"
                if result == sorted_results[0]
                else "🥈"
                if result == sorted_results[1]
                else ""
            )

            rows.append(
                f"| {status_emoji} {result.config_name} | {formatter(value)} | {relative:.2f}x |"
            )

        return "\n".join(rows)

    def _generate_detailed_analysis(self, suite) -> str:
        sections = ["## Detailed Analysis"]

        tool_results = {}
        for result in suite.results:
            tool_name = result.tool_name
            if tool_name not in tool_results:
                tool_results[tool_name] = []
            tool_results[tool_name].append(result)

        for tool_name, results in tool_results.items():
            sections.append(f"### {tool_name.title()} Performance")

            if not results:
                sections.append("No data available.")
                continue

            exec_times = [
                r.metrics.execution_time for r in results if r.metrics.exit_code == 0
            ]
            memory_usage = [
                r.metrics.peak_memory_mb for r in results if r.metrics.exit_code == 0
            ]

            if exec_times:
                avg_time = statistics.mean(exec_times)
                min_time = min(exec_times)
                max_time = max(exec_times)

                sections.append(
                    f"- **Execution Time:** Avg: {format_time(avg_time)}, "
                    f"Min: {format_time(min_time)}, Max: {format_time(max_time)}"
                )

            if memory_usage:
                avg_memory = statistics.mean(memory_usage)
                min_memory = min(memory_usage)
                max_memory = max(memory_usage)

                sections.append(
                    f"- **Memory Usage:** Avg: {format_memory(avg_memory)}, "
                    f"Min: {format_memory(min_memory)}, Max: {format_memory(max_memory)}"
                )

            errors = [r for r in results if r.metrics.exit_code != 0]
            error_rate = len(errors) / len(results) * 100
            sections.append(
                f"- **Success Rate:** {100 - error_rate:.1f}% ({len(results) - len(errors)}/{len(results)})"
            )

            if errors:
                sections.append(
                    f"- **Failed Configurations:** {', '.join([e.config_name for e in errors])}"
                )

        return "\n\n".join(sections)

    def _group_results(self, results: List) -> Dict:
        grouped = {}

        for result in results:
            key = (result.dataset_name, result.cache_type)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(result)

        return grouped
