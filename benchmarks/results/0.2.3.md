# PySentry - pip-audit Benchmark Report

**Generated:** 2025-08-12 00:03:24
**Duration:** 2m 3.83s
**Total Tests:** 20

## Executive Summary

**Overall Success Rate:** 100.0% (20/20 successful runs)

### Small_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.382s) - 24.16x faster than slowest
- **Memory Efficient:** pysentry-osv (10.01 MB) - 9.31x less memory than highest

### Small_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.261s) - 30.71x faster than slowest
- **Memory Efficient:** pysentry-pypi (9.69 MB) - 11.09x less memory than highest

### Large_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (1.160s) - 18.24x faster than slowest
- **Memory Efficient:** pysentry-osv (10.34 MB) - 10.40x less memory than highest

### Large_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.740s) - 21.90x faster than slowest
- **Memory Efficient:** pysentry-osv (10.33 MB) - 10.23x less memory than highest

## Test Environment

- **Platform:** Linux-6.11.0-1018-azure-x86_64-with-glibc2.39
- **Python Version:** 3.11.13
- **CPU Cores:** 4
- **Total Memory:** 15.62 GB
- **Available Memory:** 14.65 GB

## Performance Comparison

### Small_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.382s | 1.00x |
| 🥈 pysentry-osv | 1.080s | 2.83x |
|  pysentry-all-sources | 1.468s | 3.85x |
|  pysentry-pypa | 1.475s | 3.86x |
|  pip-audit-default | 9.222s | 24.16x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.01 MB | 1.00x |
| 🥈 pysentry-pypi | 11.70 MB | 1.17x |
|  pip-audit-default | 45.23 MB | 4.52x |
|  pysentry-pypa | 53.56 MB | 5.35x |
|  pysentry-all-sources | 93.25 MB | 9.31x |

### Small_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.261s | 1.00x |
| 🥈 pysentry-osv | 0.999s | 3.82x |
|  pysentry-pypa | 1.373s | 5.25x |
|  pysentry-all-sources | 1.446s | 5.53x |
|  pip-audit-default | 8.027s | 30.71x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 9.69 MB | 1.00x |
| 🥈 pysentry-osv | 10.16 MB | 1.05x |
|  pip-audit-default | 45.01 MB | 4.64x |
|  pysentry-pypa | 62.62 MB | 6.46x |
|  pysentry-all-sources | 107.48 MB | 11.09x |

### Large_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 1.160s | 1.00x |
| 🥈 pysentry-pypa | 1.800s | 1.55x |
|  pysentry-osv | 3.256s | 2.81x |
|  pysentry-all-sources | 3.333s | 2.87x |
|  pip-audit-default | 21.160s | 18.24x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.34 MB | 1.00x |
| 🥈 pysentry-pypi | 13.09 MB | 1.27x |
|  pip-audit-default | 47.49 MB | 4.59x |
|  pysentry-pypa | 55.27 MB | 5.34x |
|  pysentry-all-sources | 107.62 MB | 10.40x |

### Large_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.740s | 1.00x |
| 🥈 pysentry-pypa | 1.814s | 2.45x |
|  pysentry-osv | 3.453s | 4.67x |
|  pysentry-all-sources | 3.757s | 5.08x |
|  pip-audit-default | 16.199s | 21.90x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.33 MB | 1.00x |
| 🥈 pysentry-pypi | 12.99 MB | 1.26x |
|  pip-audit-default | 46.97 MB | 4.55x |
|  pysentry-pypa | 74.16 MB | 7.18x |
|  pysentry-all-sources | 105.66 MB | 10.23x |

## Detailed Analysis

### Pysentry Performance

- **Execution Time:** Avg: 1.737s, Min: 0.261s, Max: 3.757s

- **Memory Usage:** Avg: 46.75 MB, Min: 9.69 MB, Max: 107.62 MB

- **Success Rate:** 100.0% (16/16)

### Pip-Audit Performance

- **Execution Time:** Avg: 13.652s, Min: 8.027s, Max: 21.160s

- **Memory Usage:** Avg: 46.17 MB, Min: 45.01 MB, Max: 47.49 MB

- **Success Rate:** 100.0% (4/4)