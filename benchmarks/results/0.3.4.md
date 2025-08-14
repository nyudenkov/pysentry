# PySentry - pip-audit Benchmark Report

**Generated:** 2025-08-14 15:42:52
**Duration:** 1m 55.57s
**Total Tests:** 20

## Executive Summary

**Overall Success Rate:** 100.0% (20/20 successful runs)

### Small_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.306s) - 28.70x faster than slowest
- **Memory Efficient:** pysentry-osv (10.63 MB) - 10.15x less memory than highest

### Small_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.224s) - 36.53x faster than slowest
- **Memory Efficient:** pysentry-osv (10.78 MB) - 9.89x less memory than highest

### Large_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.996s) - 18.56x faster than slowest
- **Memory Efficient:** pysentry-osv (10.98 MB) - 9.40x less memory than highest

### Large_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.657s) - 24.63x faster than slowest
- **Memory Efficient:** pysentry-osv (10.68 MB) - 10.06x less memory than highest

## Test Environment

- **Platform:** Linux-6.11.0-1018-azure-x86_64-with-glibc2.39
- **Python Version:** 3.11.13
- **CPU Cores:** 4
- **Total Memory:** 15.62 GB
- **Available Memory:** 14.62 GB

## Performance Comparison

### Small_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.306s | 1.00x |
| 🥈 pysentry-osv | 0.992s | 3.24x |
|  pysentry-pypa | 1.225s | 4.00x |
|  pysentry-all-sources | 1.238s | 4.04x |
|  pip-audit-default | 8.785s | 28.70x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.63 MB | 1.00x |
| 🥈 pysentry-pypi | 12.06 MB | 1.13x |
|  pip-audit-default | 45.50 MB | 4.28x |
|  pysentry-pypa | 73.88 MB | 6.95x |
|  pysentry-all-sources | 107.95 MB | 10.15x |

### Small_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.224s | 1.00x |
| 🥈 pysentry-pypa | 1.027s | 4.59x |
|  pysentry-all-sources | 1.136s | 5.08x |
|  pysentry-osv | 1.142s | 5.11x |
|  pip-audit-default | 8.165s | 36.53x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.78 MB | 1.00x |
| 🥈 pysentry-pypi | 12.29 MB | 1.14x |
|  pip-audit-default | 44.93 MB | 4.17x |
|  pysentry-pypa | 74.12 MB | 6.88x |
|  pysentry-all-sources | 106.62 MB | 9.89x |

### Large_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.996s | 1.00x |
| 🥈 pysentry-pypa | 1.328s | 1.33x |
|  pysentry-osv | 3.112s | 3.13x |
|  pysentry-all-sources | 3.483s | 3.50x |
|  pip-audit-default | 18.476s | 18.56x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.98 MB | 1.00x |
| 🥈 pysentry-pypi | 13.16 MB | 1.20x |
|  pip-audit-default | 47.48 MB | 4.32x |
|  pysentry-pypa | 72.94 MB | 6.64x |
|  pysentry-all-sources | 103.27 MB | 9.40x |

### Large_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.657s | 1.00x |
| 🥈 pysentry-pypa | 1.518s | 2.31x |
|  pysentry-all-sources | 3.055s | 4.65x |
|  pysentry-osv | 3.429s | 5.22x |
|  pip-audit-default | 16.172s | 24.63x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.68 MB | 1.00x |
| 🥈 pysentry-pypi | 13.18 MB | 1.23x |
|  pip-audit-default | 48.80 MB | 4.57x |
|  pysentry-pypa | 72.41 MB | 6.78x |
|  pysentry-all-sources | 107.36 MB | 10.06x |

## Detailed Analysis

### Pysentry Performance

- **Execution Time:** Avg: 1.554s, Min: 0.224s, Max: 3.483s

- **Memory Usage:** Avg: 50.77 MB, Min: 10.63 MB, Max: 107.95 MB

- **Success Rate:** 100.0% (16/16)

### Pip-Audit Performance

- **Execution Time:** Avg: 12.899s, Min: 8.165s, Max: 18.476s

- **Memory Usage:** Avg: 46.68 MB, Min: 44.93 MB, Max: 48.80 MB

- **Success Rate:** 100.0% (4/4)