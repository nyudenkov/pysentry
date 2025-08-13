# PySentry - pip-audit Benchmark Report

**Generated:** 2025-08-13 12:12:39
**Duration:** 1m 46.86s
**Total Tests:** 20

## Executive Summary

**Overall Success Rate:** 100.0% (20/20 successful runs)

### Small_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.179s) - 46.37x faster than slowest
- **Memory Efficient:** pysentry-pypi (8.52 MB) - 12.47x less memory than highest

### Small_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.163s) - 48.14x faster than slowest
- **Memory Efficient:** pysentry-pypi (8.43 MB) - 11.45x less memory than highest

### Large_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.642s) - 26.63x faster than slowest
- **Memory Efficient:** pysentry-osv (10.42 MB) - 9.72x less memory than highest

### Large_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.594s) - 25.42x faster than slowest
- **Memory Efficient:** pysentry-pypi (8.40 MB) - 12.41x less memory than highest

## Test Environment

- **Platform:** Linux-6.11.0-1018-azure-x86_64-with-glibc2.39
- **Python Version:** 3.11.13
- **CPU Cores:** 4
- **Total Memory:** 15.62 GB
- **Available Memory:** 14.74 GB

## Performance Comparison

### Small_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.179s | 1.00x |
| 🥈 pysentry-all-sources | 1.024s | 5.71x |
|  pysentry-osv | 1.051s | 5.86x |
|  pysentry-pypa | 1.063s | 5.93x |
|  pip-audit-default | 8.310s | 46.37x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 8.52 MB | 1.00x |
| 🥈 pysentry-osv | 10.50 MB | 1.23x |
|  pip-audit-default | 45.38 MB | 5.32x |
|  pysentry-pypa | 65.20 MB | 7.65x |
|  pysentry-all-sources | 106.33 MB | 12.47x |

### Small_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.163s | 1.00x |
| 🥈 pysentry-pypa | 0.651s | 3.99x |
|  pysentry-osv | 0.811s | 4.98x |
|  pysentry-all-sources | 0.980s | 6.01x |
|  pip-audit-default | 7.849s | 48.14x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 8.43 MB | 1.00x |
| 🥈 pysentry-osv | 10.28 MB | 1.22x |
|  pip-audit-default | 44.97 MB | 5.33x |
|  pysentry-pypa | 67.79 MB | 8.04x |
|  pysentry-all-sources | 96.55 MB | 11.45x |

### Large_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.642s | 1.00x |
| 🥈 pysentry-pypa | 1.071s | 1.67x |
|  pysentry-all-sources | 3.248s | 5.06x |
|  pysentry-osv | 3.644s | 5.67x |
|  pip-audit-default | 17.106s | 26.63x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.42 MB | 1.00x |
| 🥈 pysentry-pypi | 13.56 MB | 1.30x |
|  pip-audit-default | 47.45 MB | 4.55x |
|  pysentry-pypa | 64.17 MB | 6.16x |
|  pysentry-all-sources | 101.29 MB | 9.72x |

### Large_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.594s | 1.00x |
| 🥈 pysentry-pypa | 1.133s | 1.91x |
|  pysentry-all-sources | 3.124s | 5.26x |
|  pysentry-osv | 3.124s | 5.26x |
|  pip-audit-default | 15.104s | 25.42x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 8.40 MB | 1.00x |
| 🥈 pysentry-osv | 10.40 MB | 1.24x |
|  pip-audit-default | 47.29 MB | 5.63x |
|  pysentry-pypa | 72.68 MB | 8.65x |
|  pysentry-all-sources | 104.25 MB | 12.41x |

## Detailed Analysis

### Pysentry Performance

- **Execution Time:** Avg: 1.406s, Min: 0.163s, Max: 3.644s

- **Memory Usage:** Avg: 47.42 MB, Min: 8.40 MB, Max: 106.33 MB

- **Success Rate:** 100.0% (16/16)

### Pip-Audit Performance

- **Execution Time:** Avg: 12.092s, Min: 7.849s, Max: 17.106s

- **Memory Usage:** Avg: 46.27 MB, Min: 44.97 MB, Max: 47.45 MB

- **Success Rate:** 100.0% (4/4)