"""Compare benchmark results and generate a Markdown report for PR comments."""
from __future__ import annotations

import sys
import json
import argparse
from pathlib import Path


def load_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def index_results(results: list, tool: str) -> dict:
    """Index results by (dataset_name, cache_type, config_name) for a specific tool."""
    index = {}
    for r in results:
        if r["tool_name"] == tool:
            key = (r["dataset_name"], r["cache_type"], r["config_name"])
            index[key] = r
    return index


def fmt_time(seconds: float) -> str:
    if seconds >= 60:
        m = int(seconds // 60)
        s = seconds % 60
        return f"{m}m {s:.2f}s"
    return f"{seconds:.3f}s"


def fmt_memory(mb: float) -> str:
    if mb >= 1024:
        return f"{mb / 1024:.2f} GB"
    return f"{mb:.1f} MB"


def pct_change(old: float, new: float) -> str:
    if old == 0:
        return "N/A"
    pct = (new - old) / old * 100
    if pct <= -5:
        return f"{pct:+.1f}% ✅"
    if pct >= 10:
        return f"{pct:+.1f}% ⚠️"
    return f"{pct:+.1f}%"


def generate_comparison(
    current_path: Path,
    baseline_path: Path | None,
    baseline_label: str,
) -> str:
    current = load_json(current_path)
    sections = ["## Benchmark Results\n"]

    if baseline_path and baseline_path.exists():
        baseline = load_json(baseline_path)
        label = baseline.get("pysentry_version", baseline_label)

        curr_ps = index_results(current["results"], "pysentry")
        base_ps = index_results(baseline["results"], "pysentry")

        if curr_ps and base_ps:
            sections.append(f"### PySentry: PR vs baseline (`{label}`)\n")
            header = (
                "| Dataset | Cache | Config"
                " | PR Time | Baseline | Δ Time"
                " | PR Memory | Baseline | Δ Memory |"
            )
            separator = "|---------|-------|--------|---------|----------|--------|-----------|----------|----------|"
            rows = [header, separator]

            for key in sorted(curr_ps.keys()):
                dataset, cache, config = key
                c = curr_ps[key]["metrics"]
                if key in base_ps:
                    b = base_ps[key]["metrics"]
                    rows.append(
                        f"| {dataset} | {cache} | {config}"
                        f" | {fmt_time(c['execution_time'])} | {fmt_time(b['execution_time'])}"
                        f" | {pct_change(b['execution_time'], c['execution_time'])}"
                        f" | {fmt_memory(c['peak_memory_mb'])} | {fmt_memory(b['peak_memory_mb'])}"
                        f" | {pct_change(b['peak_memory_mb'], c['peak_memory_mb'])} |"
                    )
                else:
                    rows.append(
                        f"| {dataset} | {cache} | {config}"
                        f" | {fmt_time(c['execution_time'])} | —"
                        f" | —"
                        f" | {fmt_memory(c['peak_memory_mb'])} | —"
                        f" | — |"
                    )
            sections.append("\n".join(rows))
    else:
        sections.append("> No baseline found — showing current results only.\n")

    curr_ps = index_results(current["results"], "pysentry")
    curr_pa = index_results(current["results"], "pip-audit")

    if curr_ps and curr_pa:
        sections.append("### Speedup vs pip-audit (this run)\n")
        header = "| Dataset | Cache | Config | PySentry | pip-audit | Speedup |"
        separator = "|---------|-------|--------|----------|-----------|---------|"
        rows = [header, separator]

        pa_by_dataset_cache = {}
        for (dataset, cache, _config), r in curr_pa.items():
            pa_by_dataset_cache[(dataset, cache)] = r

        for key in sorted(curr_ps.keys()):
            dataset, cache, config = key
            pa_key = (dataset, cache)
            if pa_key in pa_by_dataset_cache:
                ps_time = curr_ps[key]["metrics"]["execution_time"]
                pa_time = pa_by_dataset_cache[pa_key]["metrics"]["execution_time"]
                speedup = pa_time / ps_time if ps_time > 0 else 0
                rows.append(
                    f"| {dataset} | {cache} | {config}"
                    f" | {fmt_time(ps_time)} | {fmt_time(pa_time)} | {speedup:.1f}x |"
                )
        sections.append("\n".join(rows))

    si = current.get("system_info", {})
    if si:
        sections.append(
            "<details><summary>System info</summary>\n\n"
            f"**Platform:** {si.get('platform', 'unknown')}  \n"
            f"**CPU cores:** {si.get('cpu_count', 'unknown')}  \n"
            f"**Total memory:** {si.get('total_memory_gb', 0):.1f} GB\n\n"
            "</details>"
        )

    return "\n\n".join(sections)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare benchmark results for PR comments"
    )
    parser.add_argument(
        "--current", type=Path, required=True, help="Path to current benchmark JSON"
    )
    parser.add_argument(
        "--baseline", type=Path, help="Path to baseline benchmark JSON"
    )
    parser.add_argument(
        "--baseline-label",
        default="main",
        help="Fallback label for baseline when version is missing from JSON",
    )
    parser.add_argument(
        "--output", type=Path, help="Write output to file (default: stdout)"
    )
    args = parser.parse_args()

    report = generate_comparison(args.current, args.baseline, args.baseline_label)

    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"Comparison written to {args.output}")
    else:
        print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
