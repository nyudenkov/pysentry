from datetime import datetime

from .performance_monitor import format_memory, format_time
from .tool_wrapper import MODE_AUDIT_ONLY


def _distinct(m) -> str:
    return "n/a" if m.canonical_vulns < 0 else str(m.canonical_vulns)


def _reported(m) -> str:
    if m.raw_vulns < 0:
        return "n/a"
    # ⚠️ flags a tool that printed more entries than distinct vulns — i.e. it did
    # not collapse advisory aliases (pip-audit's OSV service).
    if m.raw_vulns > m.canonical_vulns >= 0:
        return f"{m.raw_vulns} ⚠️"
    return str(m.raw_vulns)


class ReportGenerator:
    def generate_report(self, suite) -> str:
        sections = [
            self._header(suite),
            self._methodology(suite),
            self._system_info(suite),
            self._performance_tables(suite),
            self._config_guide(suite),
        ]
        return "\n\n".join(s for s in sections if s)

    def _header(self, suite) -> str:
        timestamp = datetime.fromisoformat(suite.start_time).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        versions = ", ".join(f"{k} {v}" for k, v in sorted(suite.tool_versions.items()))
        return (
            "# PySentry vs pip-audit Benchmark Report\n\n"
            f"**Generated:** {timestamp}  \n"
            f"**Duration:** {format_time(suite.total_duration)}  \n"
            f"**Tools:** {versions}  \n"
            f"**Runs per config:** {suite.runs_per_config} "
            "(reported value is the **median**; ± is stdev)"
        )

    def _methodology(self, suite) -> str:
        lines = [
            "## Methodology",
            "",
            (
                "Each configuration is run multiple times; the table shows the median "
                "execution time with min and stdev, median peak memory (summed over "
                "the process tree — both tools shell out to a resolver), and the "
                "vulnerability count each tool reported."
            ),
            "",
            (
                "**Read speed alongside the vuln count.** The tools query different "
                "advisory databases, so a faster tool that reports fewer "
                "vulnerabilities is not strictly faster at the same work."
            ),
            "",
            (
                "The vuln columns are **Distinct** (unique flaws after collapsing "
                "GHSA/PYSEC/CVE aliases — the real coverage, comparable across tools) "
                "and **Reported** (what the tool actually printed). A ⚠️ marks a "
                "Reported count higher than Distinct: the tool lists the same flaw "
                "under several advisory IDs. pysentry collapses them; pip-audit's OSV "
                "service does not, so it over-reports."
            ),
            "",
            (
                "Every dataset is measured **cold** and **hot**. Cold clears all "
                "caches first — it is the fresh-CI-run experience (includes the "
                "vulnerability DB download and is network-sensitive). Hot has a warm "
                "DB and reflects steady-state throughput."
            ),
            "",
            (
                "Most pysentry configs run with PEP 792 maintenance checks **off** "
                "(pip-audit has no equivalent, so this keeps the core comparison "
                "vuln-vs-vuln). The `pysentry-pypi-maintenance` config leaves them "
                "**on** so the feature's cost is visible."
            ),
            "",
            "### Datasets",
            "",
            "| Dataset | Packages | Mode |",
            "|---------|----------|------|",
        ]
        modes = {r.dataset_name: r.mode for r in suite.results}
        for name, count in suite.dataset_packages.items():
            mode = modes.get(name, "?")
            note = " (pinned, reproducible)" if mode == MODE_AUDIT_ONLY else ""
            lines.append(f"| {name} | {count} | {mode}{note} |")

        lines += [
            "",
            (
                "- **resolve** — unpinned specs, dependency resolution ON. Includes "
                "resolver cost; pysentry uses `uv`, pip-audit uses `pip`. Not pinned, "
                "so results drift as the ecosystem and advisory DB change over time."
            ),
            (
                "- **audit-only** — pinned input, resolution OFF on both tools "
                "(`--no-resolver` / `--no-deps --disable-pip`). This isolates audit "
                "throughput from resolver choice and is reproducible."
            ),
            "",
            "### Commands",
            "",
            "| Config | Command |",
            "|--------|---------|",
        ]
        seen = {}
        for r in suite.results:
            seen.setdefault(r.config_name, r.command)
        for config_name, command in seen.items():
            lines.append(f"| {config_name} | `{command}` |")
        return "\n".join(lines)

    def _system_info(self, suite) -> str:
        info = suite.system_info
        return (
            "## Test Environment\n\n"
            f"- **Platform:** {info.platform}\n"
            f"- **Python:** {info.python_version}\n"
            f"- **CPU Cores:** {info.cpu_count}\n"
            f"- **Total Memory:** {info.total_memory_gb:.2f} GB"
        )

    def _performance_tables(self, suite) -> str:
        grouped: dict[tuple, list] = {}
        for result in suite.results:
            grouped.setdefault((result.dataset_name, result.cache_type), []).append(
                result
            )

        sections = ["## Performance"]
        for (dataset, cache_type), results in grouped.items():
            sections.append(f"### {dataset} — {cache_type} cache")
            sections.append(self._table(results))
        return "\n\n".join(sections)

    def _table(self, results: list) -> str:
        ranked = sorted(results, key=lambda r: r.metrics.execution_time)
        fastest = ranked[0].metrics.execution_time

        rows = [
            "| Config | Median Time | Min | Stdev | Rel | Peak Mem | Distinct | Reported |",
            "|--------|-------------|-----|-------|-----|----------|----------|----------|",
        ]
        for i, result in enumerate(ranked):
            m = result.metrics
            relative = m.execution_time / fastest if fastest > 0 else 1.0
            medal = "🥇 " if i == 0 else "🥈 " if i == 1 else ""
            rows.append(
                f"| {medal}{result.config_name} "
                f"| {format_time(m.execution_time)} "
                f"| {format_time(m.time_min)} "
                f"| ±{m.time_stdev:.3f}s "
                f"| {relative:.2f}x "
                f"| {format_memory(m.peak_memory_mb)} "
                f"| {_distinct(m)} "
                f"| {_reported(m)} |"
            )
        return "\n".join(rows)

    def _config_guide(self, suite) -> str:
        """pysentry-only view: what each source / maintenance option costs, so a
        reader deciding what to enable can lean on concrete numbers."""
        grouped: dict[tuple, list] = {}
        for r in suite.results:
            if r.tool_name == "pysentry":
                grouped.setdefault((r.dataset_name, r.cache_type), []).append(r)
        if not grouped:
            return ""

        sections = [
            "## Choosing a pysentry configuration",
            (
                "Concrete cost of each pysentry option. `vs best` is relative to the "
                "fastest pysentry config on that row. Source choice (`pypa` / `osv` / "
                "`pypi` / `all-sources`) trades coverage against speed and memory; "
                "`pysentry-pypi-maintenance` is the only config with PEP 792 "
                "maintenance checks on, so its delta is that feature's cost."
            ),
        ]
        for (dataset, cache_type), results in grouped.items():
            ranked = sorted(results, key=lambda r: r.metrics.execution_time)
            best = ranked[0].metrics.execution_time
            sections.append(f"### {dataset} — {cache_type} cache")
            rows = [
                "| Config | Median Time | Peak Mem | Distinct | Reported | vs best |",
                "|--------|-------------|----------|----------|----------|---------|",
            ]
            for r in ranked:
                m = r.metrics
                rel = m.execution_time / best if best > 0 else 1.0
                rows.append(
                    f"| {r.config_name} "
                    f"| {format_time(m.execution_time)} "
                    f"| {format_memory(m.peak_memory_mb)} "
                    f"| {_distinct(m)} "
                    f"| {_reported(m)} "
                    f"| {rel:.2f}x |"
                )
            sections.append("\n".join(rows))
        return "\n\n".join(sections)
