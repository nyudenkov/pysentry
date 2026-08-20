# PySentry vs pip-audit Benchmark Report

**Generated:** 2026-08-20 20:09:19  
**Duration:** 42m 33.68s  
**Tools:** pip-audit 2.10.1, pysentry 0.5.0  
**Runs per config:** 5 (reported value is the **median**; ± is stdev)

## Methodology

Each configuration is run multiple times; the table shows the median execution time with min and stdev, median peak memory (summed over the process tree — both tools shell out to a resolver), and the vulnerability count each tool reported.

**Read speed alongside the vuln count.** The tools query different advisory databases, so a faster tool that reports fewer vulnerabilities is not strictly faster at the same work.

The vuln columns are **Distinct** (unique flaws after collapsing GHSA/PYSEC/CVE aliases — the real coverage, comparable across tools) and **Reported** (what the tool actually printed). A ⚠️ marks a Reported count higher than Distinct: the tool lists the same flaw under several advisory IDs. pysentry collapses them; pip-audit's OSV service does not, so it over-reports.

Every dataset is measured **cold** and **hot**. Cold clears all caches first — it is the fresh-CI-run experience (includes the vulnerability DB download and is network-sensitive). Hot has a warm DB and reflects steady-state throughput.

Most pysentry configs run with PEP 792 maintenance checks **off** (pip-audit has no equivalent, so this keeps the core comparison vuln-vs-vuln). The `pysentry-pypi-maintenance` config leaves them **on** so the feature's cost is visible.

### Datasets

| Dataset | Packages | Mode |
|---------|----------|------|
| small_requirements | 10 | resolve |
| large_requirements | 55 | resolve |
| pinned_requirements | 185 | audit-only (pinned, reproducible) |
| pinned_large_requirements | 692 | audit-only (pinned, reproducible) |

- **resolve** — unpinned specs, dependency resolution ON. Includes resolver cost; pysentry uses `uv`, pip-audit uses `pip`. Not pinned, so results drift as the ecosystem and advisory DB change over time.
- **audit-only** — pinned input, resolution OFF on both tools (`--no-resolver` / `--no-deps --disable-pip`). This isolates audit throughput from resolver choice and is reproducible.

### Commands

| Config | Command |
|--------|---------|
| pysentry-pypa | `pysentry --format json --resolver uv --sources pypa --no-maintenance-check <path>` |
| pysentry-osv | `pysentry --format json --resolver uv --sources osv --no-maintenance-check <path>` |
| pysentry-pypi | `pysentry --format json --resolver uv --sources pypi --no-maintenance-check <path>` |
| pysentry-all-sources | `pysentry --format json --resolver uv --sources pypa,osv,pypi --no-maintenance-check <path>` |
| pysentry-pypi-maintenance | `pysentry --format json --resolver uv --sources pypi <path>` |
| pip-audit-pypi | `pip-audit --format json -s pypi --requirement <path>` |
| pip-audit-osv | `pip-audit --format json -s osv --requirement <path>` |

## Test Environment

- **Platform:** Linux-6.17.0-1022-azure-x86_64-with-glibc2.39
- **Python:** 3.11.16
- **CPU Cores:** 4
- **Total Memory:** 15.61 GB

## Performance

### small_requirements — cold cache

| Config | Median Time | Min | Stdev | Rel | Peak Mem | Distinct | Reported |
|--------|-------------|-----|-------|-----|----------|----------|----------|
| 🥇 pysentry-pypi | 0.581s | 0.522s | ±0.091s | 1.00x | 126.95 MB | 0 | 0 |
| 🥈 pysentry-osv | 0.686s | 0.596s | ±0.061s | 1.18x | 127.21 MB | 0 | 0 |
| pysentry-pypi-maintenance | 0.933s | 0.596s | ±0.200s | 1.61x | 127.10 MB | 0 | 0 |
| pysentry-pypa | 2.017s | 1.963s | ±0.138s | 3.47x | 254.42 MB | 0 | 0 |
| pysentry-all-sources | 2.096s | 2.024s | ±0.166s | 3.61x | 255.94 MB | 0 | 0 |
| pip-audit-pypi | 8.709s | 7.532s | ±1.817s | 15.00x | 139.54 MB | 0 | 0 |
| pip-audit-osv | 12.020s | 11.429s | ±0.762s | 20.70x | 135.70 MB | 0 | 0 |

### small_requirements — hot cache

| Config | Median Time | Min | Stdev | Rel | Peak Mem | Distinct | Reported |
|--------|-------------|-----|-------|-----|----------|----------|----------|
| 🥇 pysentry-pypi | 0.273s | 0.265s | ±0.030s | 1.00x | 126.93 MB | 0 | 0 |
| 🥈 pysentry-osv | 0.291s | 0.239s | ±0.050s | 1.06x | 126.82 MB | 0 | 0 |
| pysentry-pypi-maintenance | 0.329s | 0.240s | ±0.055s | 1.20x | 127.06 MB | 0 | 0 |
| pysentry-pypa | 0.826s | 0.797s | ±0.129s | 3.02x | 341.63 MB | 0 | 0 |
| pysentry-all-sources | 0.910s | 0.806s | ±0.061s | 3.33x | 341.50 MB | 0 | 0 |
| pip-audit-pypi | 5.164s | 5.124s | ±0.125s | 18.89x | 138.12 MB | 0 | 0 |
| pip-audit-osv | 8.338s | 8.198s | ±0.109s | 30.51x | 135.48 MB | 0 | 0 |

### large_requirements — cold cache

| Config | Median Time | Min | Stdev | Rel | Peak Mem | Distinct | Reported |
|--------|-------------|-----|-------|-----|----------|----------|----------|
| 🥇 pysentry-pypi | 1.291s | 1.220s | ±0.116s | 1.00x | 195.28 MB | 0 | 0 |
| 🥈 pysentry-osv | 1.482s | 1.187s | ±0.330s | 1.15x | 194.62 MB | 0 | 0 |
| pysentry-pypi-maintenance | 1.966s | 1.722s | ±0.179s | 1.52x | 197.55 MB | 0 | 0 |
| pysentry-pypa | 2.767s | 2.452s | ±0.330s | 2.14x | 254.50 MB | 0 | 0 |
| pysentry-all-sources | 2.852s | 2.694s | ±0.119s | 2.21x | 256.65 MB | 0 | 0 |
| pip-audit-pypi | 24.879s | 19.682s | ±2.684s | 19.28x | 206.44 MB | 0 | 0 |
| pip-audit-osv | 35.670s | 32.237s | ±3.160s | 27.64x | 206.29 MB | 0 | 0 |

### large_requirements — hot cache

| Config | Median Time | Min | Stdev | Rel | Peak Mem | Distinct | Reported |
|--------|-------------|-----|-------|-----|----------|----------|----------|
| 🥇 pysentry-pypi-maintenance | 0.649s | 0.628s | ±0.081s | 1.00x | 191.56 MB | 0 | 0 |
| 🥈 pysentry-pypi | 0.670s | 0.630s | ±0.019s | 1.03x | 194.67 MB | 0 | 0 |
| pysentry-osv | 0.691s | 0.631s | ±0.098s | 1.06x | 193.26 MB | 0 | 0 |
| pysentry-all-sources | 1.277s | 1.224s | ±0.057s | 1.97x | 341.51 MB | 0 | 0 |
| pysentry-pypa | 1.288s | 1.157s | ±0.093s | 1.99x | 341.65 MB | 0 | 0 |
| pip-audit-pypi | 8.385s | 8.220s | ±0.174s | 12.92x | 205.05 MB | 0 | 0 |
| pip-audit-osv | 24.661s | 23.326s | ±1.093s | 38.00x | 205.21 MB | 0 | 0 |

### pinned_requirements — cold cache

| Config | Median Time | Min | Stdev | Rel | Peak Mem | Distinct | Reported |
|--------|-------------|-----|-------|-----|----------|----------|----------|
| 🥇 pysentry-pypi | 0.541s | 0.464s | ±0.153s | 1.00x | 15.48 MB | 103 | 104 ⚠️ |
| 🥈 pysentry-pypi-maintenance | 0.776s | 0.683s | ±0.284s | 1.44x | 43.32 MB | 103 | 104 ⚠️ |
| pysentry-pypa | 1.960s | 1.737s | ±0.138s | 3.63x | 254.97 MB | 100 | 100 |
| pysentry-osv | 2.783s | 2.638s | ±0.444s | 5.15x | 20.75 MB | 103 | 103 |
| pysentry-all-sources | 3.352s | 3.178s | ±0.364s | 6.20x | 263.70 MB | 104 | 104 |
| pip-audit-pypi | 5.063s | 4.157s | ±1.091s | 9.37x | 56.68 MB | 103 | 143 ⚠️ |
| pip-audit-osv | 27.006s | 24.160s | ±1.919s | 49.96x | 56.89 MB | 103 | 198 ⚠️ |

### pinned_requirements — hot cache

| Config | Median Time | Min | Stdev | Rel | Peak Mem | Distinct | Reported |
|--------|-------------|-----|-------|-----|----------|----------|----------|
| 🥇 pysentry-pypi | 0.011s | 0.011s | ±0.000s | 1.00x | 7.76 MB | 103 | 104 ⚠️ |
| 🥈 pysentry-pypi-maintenance | 0.021s | 0.018s | ±0.003s | 1.91x | 7.52 MB | 103 | 104 ⚠️ |
| pysentry-osv | 0.030s | 0.029s | ±0.002s | 2.76x | 7.67 MB | 103 | 103 |
| pip-audit-pypi | 0.507s | 0.495s | ±0.007s | 46.42x | 56.87 MB | 103 | 143 ⚠️ |
| pysentry-pypa | 0.583s | 0.582s | ±0.001s | 53.38x | 341.71 MB | 100 | 100 |
| pysentry-all-sources | 0.623s | 0.621s | ±0.007s | 57.07x | 353.05 MB | 104 | 104 |
| pip-audit-osv | 28.320s | 25.943s | ±2.160s | 2592.57x | 56.77 MB | 103 | 198 ⚠️ |

### pinned_large_requirements — cold cache

| Config | Median Time | Min | Stdev | Rel | Peak Mem | Distinct | Reported |
|--------|-------------|-----|-------|-----|----------|----------|----------|
| 🥇 pysentry-pypi | 1.206s | 0.847s | ±0.459s | 1.00x | 14.93 MB | 29 | 29 |
| 🥈 pysentry-osv | 1.863s | 1.617s | ±1.931s | 1.55x | 20.79 MB | 30 | 30 |
| pysentry-pypa | 2.001s | 1.749s | ±0.198s | 1.66x | 255.11 MB | 23 | 23 |
| pysentry-all-sources | 2.497s | 2.273s | ±0.166s | 2.07x | 263.66 MB | 30 | 30 |
| pysentry-pypi-maintenance | 2.636s | 1.626s | ±0.726s | 2.19x | 46.02 MB | 29 | 29 |
| pip-audit-pypi | 18.766s | 13.351s | ±11.792s | 15.57x | 56.97 MB | 29 | 30 ⚠️ |
| pip-audit-osv | 1m 40.65s | 1m 20.33s | ±9.938s | 83.48x | 57.04 MB | 30 | 49 ⚠️ |

### pinned_large_requirements — hot cache

| Config | Median Time | Min | Stdev | Rel | Peak Mem | Distinct | Reported |
|--------|-------------|-----|-------|-----|----------|----------|----------|
| 🥇 pysentry-pypi | 0.011s | 0.011s | ±0.001s | 1.00x | 7.67 MB | 29 | 29 |
| 🥈 pysentry-pypi-maintenance | 0.027s | 0.021s | ±0.009s | 2.34x | 7.78 MB | 29 | 29 |
| pysentry-osv | 0.043s | 0.041s | ±0.001s | 3.71x | 7.57 MB | 30 | 30 |
| pysentry-pypa | 0.569s | 0.569s | ±0.002s | 49.63x | 341.84 MB | 23 | 23 |
| pysentry-all-sources | 0.624s | 0.618s | ±0.003s | 54.41x | 353.14 MB | 30 | 30 |
| pip-audit-pypi | 0.890s | 0.884s | ±0.005s | 77.60x | 57.03 MB | 29 | 30 ⚠️ |
| pip-audit-osv | 1m 40.34s | 1m 25.17s | ±10.756s | 8752.16x | 56.88 MB | 30 | 49 ⚠️ |

## Choosing a pysentry configuration

Concrete cost of each pysentry option. `vs best` is relative to the fastest pysentry config on that row. Source choice (`pypa` / `osv` / `pypi` / `all-sources`) trades coverage against speed and memory; `pysentry-pypi-maintenance` is the only config with PEP 792 maintenance checks on, so its delta is that feature's cost.

### small_requirements — cold cache

| Config | Median Time | Peak Mem | Distinct | Reported | vs best |
|--------|-------------|----------|----------|----------|---------|
| pysentry-pypi | 0.581s | 126.95 MB | 0 | 0 | 1.00x |
| pysentry-osv | 0.686s | 127.21 MB | 0 | 0 | 1.18x |
| pysentry-pypi-maintenance | 0.933s | 127.10 MB | 0 | 0 | 1.61x |
| pysentry-pypa | 2.017s | 254.42 MB | 0 | 0 | 3.47x |
| pysentry-all-sources | 2.096s | 255.94 MB | 0 | 0 | 3.61x |

### small_requirements — hot cache

| Config | Median Time | Peak Mem | Distinct | Reported | vs best |
|--------|-------------|----------|----------|----------|---------|
| pysentry-pypi | 0.273s | 126.93 MB | 0 | 0 | 1.00x |
| pysentry-osv | 0.291s | 126.82 MB | 0 | 0 | 1.06x |
| pysentry-pypi-maintenance | 0.329s | 127.06 MB | 0 | 0 | 1.20x |
| pysentry-pypa | 0.826s | 341.63 MB | 0 | 0 | 3.02x |
| pysentry-all-sources | 0.910s | 341.50 MB | 0 | 0 | 3.33x |

### large_requirements — cold cache

| Config | Median Time | Peak Mem | Distinct | Reported | vs best |
|--------|-------------|----------|----------|----------|---------|
| pysentry-pypi | 1.291s | 195.28 MB | 0 | 0 | 1.00x |
| pysentry-osv | 1.482s | 194.62 MB | 0 | 0 | 1.15x |
| pysentry-pypi-maintenance | 1.966s | 197.55 MB | 0 | 0 | 1.52x |
| pysentry-pypa | 2.767s | 254.50 MB | 0 | 0 | 2.14x |
| pysentry-all-sources | 2.852s | 256.65 MB | 0 | 0 | 2.21x |

### large_requirements — hot cache

| Config | Median Time | Peak Mem | Distinct | Reported | vs best |
|--------|-------------|----------|----------|----------|---------|
| pysentry-pypi-maintenance | 0.649s | 191.56 MB | 0 | 0 | 1.00x |
| pysentry-pypi | 0.670s | 194.67 MB | 0 | 0 | 1.03x |
| pysentry-osv | 0.691s | 193.26 MB | 0 | 0 | 1.06x |
| pysentry-all-sources | 1.277s | 341.51 MB | 0 | 0 | 1.97x |
| pysentry-pypa | 1.288s | 341.65 MB | 0 | 0 | 1.99x |

### pinned_requirements — cold cache

| Config | Median Time | Peak Mem | Distinct | Reported | vs best |
|--------|-------------|----------|----------|----------|---------|
| pysentry-pypi | 0.541s | 15.48 MB | 103 | 104 ⚠️ | 1.00x |
| pysentry-pypi-maintenance | 0.776s | 43.32 MB | 103 | 104 ⚠️ | 1.44x |
| pysentry-pypa | 1.960s | 254.97 MB | 100 | 100 | 3.63x |
| pysentry-osv | 2.783s | 20.75 MB | 103 | 103 | 5.15x |
| pysentry-all-sources | 3.352s | 263.70 MB | 104 | 104 | 6.20x |

### pinned_requirements — hot cache

| Config | Median Time | Peak Mem | Distinct | Reported | vs best |
|--------|-------------|----------|----------|----------|---------|
| pysentry-pypi | 0.011s | 7.76 MB | 103 | 104 ⚠️ | 1.00x |
| pysentry-pypi-maintenance | 0.021s | 7.52 MB | 103 | 104 ⚠️ | 1.91x |
| pysentry-osv | 0.030s | 7.67 MB | 103 | 103 | 2.76x |
| pysentry-pypa | 0.583s | 341.71 MB | 100 | 100 | 53.38x |
| pysentry-all-sources | 0.623s | 353.05 MB | 104 | 104 | 57.07x |

### pinned_large_requirements — cold cache

| Config | Median Time | Peak Mem | Distinct | Reported | vs best |
|--------|-------------|----------|----------|----------|---------|
| pysentry-pypi | 1.206s | 14.93 MB | 29 | 29 | 1.00x |
| pysentry-osv | 1.863s | 20.79 MB | 30 | 30 | 1.55x |
| pysentry-pypa | 2.001s | 255.11 MB | 23 | 23 | 1.66x |
| pysentry-all-sources | 2.497s | 263.66 MB | 30 | 30 | 2.07x |
| pysentry-pypi-maintenance | 2.636s | 46.02 MB | 29 | 29 | 2.19x |

### pinned_large_requirements — hot cache

| Config | Median Time | Peak Mem | Distinct | Reported | vs best |
|--------|-------------|----------|----------|----------|---------|
| pysentry-pypi | 0.011s | 7.67 MB | 29 | 29 | 1.00x |
| pysentry-pypi-maintenance | 0.027s | 7.78 MB | 29 | 29 | 2.34x |
| pysentry-osv | 0.043s | 7.57 MB | 30 | 30 | 3.71x |
| pysentry-pypa | 0.569s | 341.84 MB | 23 | 23 | 49.63x |
| pysentry-all-sources | 0.624s | 353.14 MB | 30 | 30 | 54.41x |