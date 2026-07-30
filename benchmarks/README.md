# PySentry vs pip-audit Benchmark Suite

Results are written per pysentry version to [`results/`](results/) as `<version>.md`
(human report) and `<version>.json` (raw data for `compare.py`).

## What it measures

Each configuration is run `--runs` times (default 5). The report shows, per config:

- **Median execution time** with min and stdev — a single run is too noisy to trust.
- **Peak memory**, summed over the whole process tree. Both tools shell out to a
  resolver (pysentry → `uv`, pip-audit → `pip`); sampling only the parent process
  undercounts memory badly, so we sum children too.
- **Vulnerability count** each tool reported. Read speed *alongside* this: the tools
  query different advisory databases, so a faster tool that finds fewer vulns is not
  doing the same work.

## Two modes

- **resolve** (`small_requirements.txt`, `large_requirements.txt`) — unpinned specs,
  dependency resolution ON. This is the real-world path but includes resolver cost
  (uv vs pip), and it is **not reproducible**: results drift as the ecosystem and the
  advisory DB change over time.
- **audit-only** (`pinned_requirements.txt` ~185 pkgs, `pinned_large_requirements.txt`
  ~690 pkgs) — pinned input, resolution OFF on both tools (`--no-resolver` vs
  `--no-deps --disable-pip`). Same input file, resolver choice removed, so this
  isolates pure audit throughput and is reproducible. Two scales show how the gap
  changes as the dependency tree grows.

Every dataset is measured **cold** (caches cleared first — the fresh-CI-run
experience, includes the vuln DB download, network-sensitive) and **hot** (warm DB,
steady-state throughput). Cold is the number most CI users actually feel.

**Config matrix.** pysentry runs each of its 4 sources (pypa / osv / pypi /
all-sources) plus a `pysentry-pypi-maintenance` config with PEP 792 maintenance
checks ON — the others leave them off so the core comparison is vuln-vs-vuln (pip-audit
has no such feature). pip-audit runs both its services (pypi / osv). The report shows
all of them so a reader can pick the config matching their own setup.

Datasets: `pinned_requirements.txt` from `test_data/uv.lock`; `pinned_large_requirements.txt`
is a real Apache Airflow constraints file (provenance in the file header). Regenerate
the former with `python test_data/gen_pinned.py`.

## Running

```bash
uv run python main.py            # full suite, median of 5 runs
uv run python main.py --quick    # only the small resolve dataset
uv run python main.py --runs 3   # fewer repetitions
uv run python test_metrics.py    # self-checks for aggregation + vuln parsing
```

## Comparing against a baseline (for PR comments)

```bash
uv run python compare.py --current results/<new>.json --baseline results/<old>.json
```

## ⚠️ Continuity

Results from **0.4.7 and earlier** used a different methodology (single run, unpinned
inputs, parent-process-only memory) and are **not comparable** to newer runs. Treat
them as historical. The `audit-only` mode is the number to track release-to-release,
because it is the only one held stable against a fixed input.
