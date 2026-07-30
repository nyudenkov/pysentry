"""Self-checks for the non-trivial pure logic: aggregation and vuln parsing.

Run: python test_metrics.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.performance_monitor import RunResult, aggregate
from src.tool_wrapper import (
    PipAuditWrapper,
    PySentryWrapper,
    canonical_vuln_count,
)


def _run(t, m, exit_code=1, canonical=5, raw=None):
    return RunResult(
        execution_time=t,
        peak_memory_mb=m,
        exit_code=exit_code,
        raw_vulns=canonical if raw is None else raw,
        canonical_vulns=canonical,
    )


def test_aggregate_median_min_stdev():
    agg = aggregate([_run(3.0, 30), _run(1.0, 10), _run(2.0, 20)])
    assert agg.execution_time == 2.0, agg.execution_time  # median, not mean
    assert agg.time_min == 1.0
    assert agg.peak_memory_mb == 20.0
    assert round(agg.time_stdev, 3) == 1.0
    assert agg.runs == 3


def test_aggregate_single_run_zero_stdev():
    agg = aggregate([_run(2.0, 20)])
    assert agg.time_stdev == 0.0
    assert agg.mem_stdev == 0.0
    assert agg.runs == 1


def test_aggregate_takes_best_vuln_and_ok_exit():
    agg = aggregate(
        [
            _run(1.0, 10, exit_code=1, canonical=5, raw=8),
            _run(1.0, 10, exit_code=0, canonical=7, raw=9),
        ]
    )
    assert agg.canonical_vulns == 7  # best parsed distinct count
    assert agg.raw_vulns == 9  # tool's reported count carried through
    assert agg.exit_code == 0


def test_aggregate_ignores_transient_failure():
    # One run fetched fine (2.0s, 95 vulns); one blipped (0.1s, exit 2, -1).
    agg = aggregate(
        [
            _run(2.0, 50, exit_code=1, canonical=95),
            _run(0.1, 5, exit_code=2, canonical=-1),
        ]
    )
    assert agg.execution_time == 2.0  # median over the successful run only
    assert agg.canonical_vulns == 95  # not the -1
    assert agg.runs == 1


def test_canonical_collapses_aliases():
    # GHSA and PYSEC are the same flaw (linked by alias) -> one vuln.
    entries = [
        ("django", {"GHSA-1", "PYSEC-1", "CVE-1"}),
        ("django", {"PYSEC-1"}),  # alias of the above -> merges
        ("django", {"PYSEC-2"}),  # distinct -> separate
        ("pillow", {"GHSA-9"}),  # different package
    ]
    assert canonical_vuln_count(entries) == 3
    assert canonical_vuln_count([]) == 0


def test_pysentry_count_reports_raw_and_distinct():
    ps = PySentryWrapper.__new__(PySentryWrapper)  # no binary needed
    # pysentry dedupes natively: total_vulnerabilities == distinct.
    doc = (
        '{"total_vulnerabilities": 2, "vulnerabilities": ['
        '{"package_name": "django", "id": "GHSA-1", "aliases": ["PYSEC-1"]},'
        '{"package_name": "django", "id": "PYSEC-1", "aliases": []},'
        '{"package_name": "django", "id": "PYSEC-2", "aliases": []}'
        "]}"
    )
    assert ps.count_vulns(doc) == (2, 2)  # (raw, canonical)
    # A trailing version-update notice must not break parsing.
    assert ps.count_vulns(doc + "\n\nA new version is available!\n") == (2, 2)
    assert ps.count_vulns("not json") == (-1, -1)
    assert ps.count_vulns('{"other": 1}') == (-1, -1)


def test_pipaudit_count_exposes_alias_inflation():
    pa = PipAuditWrapper.__new__(PipAuditWrapper)
    # 3 printed advisories, but GHSA-X/CVE-X are one flaw -> 2 distinct.
    doc = (
        '{"dependencies": ['
        '{"name": "a", "vulns": [{"id": "GHSA-X", "aliases": ["CVE-X"]},'
        ' {"id": "CVE-X", "aliases": []}]},'
        '{"name": "b", "vulns": []},'
        '{"name": "c", "vulns": [{"id": "Z", "aliases": []}]}'
        '], "fixes": []}'
    )
    assert pa.count_vulns(doc) == (3, 2)  # (raw over-reports, canonical)
    assert pa.count_vulns("") == (-1, -1)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
