# PySentry - pip-audit Benchmark Report

**Generated:** 2025-08-27 10:44:17
**Duration:** 1m 55.07s
**Total Tests:** 20

## Executive Summary

**Overall Success Rate:** 100.0% (20/20 successful runs)

### Small_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.181s) - 48.96x faster than slowest
- **Memory Efficient:** pysentry-pypi (9.20 MB) - 11.55x less memory than highest

### Small_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.236s) - 35.40x faster than slowest
- **Memory Efficient:** pysentry-osv (10.85 MB) - 9.90x less memory than highest

### Large_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.618s) - 30.80x faster than slowest
- **Memory Efficient:** pysentry-osv (10.84 MB) - 8.97x less memory than highest

### Large_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.617s) - 26.89x faster than slowest
- **Memory Efficient:** pysentry-osv (10.62 MB) - 9.02x less memory than highest

## Test Environment

- **Platform:** Linux-6.11.0-1018-azure-x86_64-with-glibc2.39
- **Python Version:** 3.11.13
- **CPU Cores:** 4
- **Total Memory:** 15.62 GB
- **Available Memory:** 14.56 GB

## Performance Comparison

### Small_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.181s | 1.00x |
| 🥈 pysentry-all-sources | 1.082s | 5.97x |
|  pysentry-pypa | 1.127s | 6.21x |
|  pysentry-osv | 1.224s | 6.75x |
|  pip-audit-default | 8.877s | 48.96x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 9.20 MB | 1.00x |
| 🥈 pysentry-osv | 10.64 MB | 1.16x |
|  pip-audit-default | 45.64 MB | 4.96x |
|  pysentry-pypa | 73.93 MB | 8.03x |
|  pysentry-all-sources | 106.27 MB | 11.55x |

### Small_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.236s | 1.00x |
| 🥈 pysentry-pypa | 0.706s | 2.99x |
|  pysentry-osv | 0.967s | 4.10x |
|  pysentry-all-sources | 1.031s | 4.37x |
|  pip-audit-default | 8.358s | 35.40x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.85 MB | 1.00x |
| 🥈 pysentry-pypi | 12.63 MB | 1.16x |
|  pip-audit-default | 45.08 MB | 4.16x |
|  pysentry-pypa | 52.04 MB | 4.80x |
|  pysentry-all-sources | 107.44 MB | 9.90x |

### Large_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.618s | 1.00x |
| 🥈 pysentry-pypa | 1.199s | 1.94x |
|  pysentry-all-sources | 3.060s | 4.95x |
|  pysentry-osv | 4.085s | 6.61x |
|  pip-audit-default | 19.045s | 30.80x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.84 MB | 1.00x |
| 🥈 pysentry-pypi | 14.41 MB | 1.33x |
|  pip-audit-default | 47.55 MB | 4.39x |
|  pysentry-pypa | 67.27 MB | 6.20x |
|  pysentry-all-sources | 97.26 MB | 8.97x |

### Large_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.617s | 1.00x |
| 🥈 pysentry-pypa | 1.091s | 1.77x |
|  pysentry-osv | 2.822s | 4.58x |
|  pysentry-all-sources | 3.368s | 5.46x |
|  pip-audit-default | 16.578s | 26.89x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.62 MB | 1.00x |
| 🥈 pysentry-pypi | 13.52 MB | 1.27x |
|  pip-audit-default | 48.38 MB | 4.56x |
|  pysentry-pypa | 58.75 MB | 5.53x |
|  pysentry-all-sources | 95.80 MB | 9.02x |

## Detailed Analysis

### Pysentry Performance

- **Execution Time:** Avg: 1.463s, Min: 0.181s, Max: 4.085s

- **Memory Usage:** Avg: 46.97 MB, Min: 9.20 MB, Max: 107.44 MB

- **Success Rate:** 100.0% (16/16)

### Pip-Audit Performance

- **Execution Time:** Avg: 13.215s, Min: 8.358s, Max: 19.045s

- **Memory Usage:** Avg: 46.66 MB, Min: 45.08 MB, Max: 48.38 MB

- **Success Rate:** 100.0% (4/4)