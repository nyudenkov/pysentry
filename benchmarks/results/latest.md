# PySentry - pip-audit Benchmark Report

**Generated:** 2025-09-23 20:02:05
**Duration:** 2m 4.70s
**Total Tests:** 20

## Executive Summary

**Overall Success Rate:** 100.0% (20/20 successful runs)

### Small_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.465s) - 19.39x faster than slowest
- **Memory Efficient:** pysentry-osv (10.39 MB) - 10.28x less memory than highest

### Small_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.169s) - 46.53x faster than slowest
- **Memory Efficient:** pysentry-pypi (7.93 MB) - 13.38x less memory than highest

### Large_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (1.084s) - 20.98x faster than slowest
- **Memory Efficient:** pysentry-osv (10.45 MB) - 10.14x less memory than highest

### Large_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.679s) - 24.45x faster than slowest
- **Memory Efficient:** pysentry-osv (9.78 MB) - 10.90x less memory than highest

## Test Environment

- **Platform:** Linux-6.11.0-1018-azure-x86_64-with-glibc2.39
- **Python Version:** 3.11.13
- **CPU Cores:** 4
- **Total Memory:** 15.62 GB
- **Available Memory:** 14.73 GB

## Performance Comparison

### Small_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.465s | 1.00x |
| 🥈 pysentry-osv | 1.183s | 2.54x |
|  pysentry-all-sources | 1.324s | 2.85x |
|  pysentry-pypa | 1.688s | 3.63x |
|  pip-audit-default | 9.012s | 19.39x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.39 MB | 1.00x |
| 🥈 pysentry-pypi | 11.96 MB | 1.15x |
|  pip-audit-default | 45.69 MB | 4.40x |
|  pysentry-pypa | 66.90 MB | 6.44x |
|  pysentry-all-sources | 106.82 MB | 10.28x |

### Small_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.169s | 1.00x |
| 🥈 pysentry-osv | 0.928s | 5.50x |
|  pysentry-all-sources | 1.036s | 6.15x |
|  pysentry-pypa | 1.051s | 6.23x |
|  pip-audit-default | 7.847s | 46.53x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 7.93 MB | 1.00x |
| 🥈 pysentry-osv | 9.51 MB | 1.20x |
|  pip-audit-default | 45.00 MB | 5.67x |
|  pysentry-pypa | 68.70 MB | 8.66x |
|  pysentry-all-sources | 106.08 MB | 13.38x |

### Large_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 1.084s | 1.00x |
| 🥈 pysentry-pypa | 1.545s | 1.42x |
|  pysentry-osv | 3.444s | 3.18x |
|  pysentry-all-sources | 4.845s | 4.47x |
|  pip-audit-default | 22.747s | 20.98x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.45 MB | 1.00x |
| 🥈 pysentry-pypi | 12.39 MB | 1.19x |
|  pip-audit-default | 47.30 MB | 4.53x |
|  pysentry-pypa | 73.35 MB | 7.02x |
|  pysentry-all-sources | 105.94 MB | 10.14x |

### Large_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.679s | 1.00x |
| 🥈 pysentry-pypa | 1.310s | 1.93x |
|  pysentry-osv | 3.253s | 4.79x |
|  pysentry-all-sources | 3.563s | 5.25x |
|  pip-audit-default | 16.603s | 24.45x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 9.78 MB | 1.00x |
| 🥈 pysentry-pypi | 12.19 MB | 1.25x |
|  pip-audit-default | 47.16 MB | 4.82x |
|  pysentry-pypa | 63.30 MB | 6.47x |
|  pysentry-all-sources | 106.53 MB | 10.90x |

## Detailed Analysis

### Pysentry Performance

- **Execution Time:** Avg: 1.723s, Min: 0.169s, Max: 4.845s

- **Memory Usage:** Avg: 48.89 MB, Min: 7.93 MB, Max: 106.82 MB

- **Success Rate:** 100.0% (16/16)

### Pip-Audit Performance

- **Execution Time:** Avg: 14.052s, Min: 7.847s, Max: 22.747s

- **Memory Usage:** Avg: 46.29 MB, Min: 45.00 MB, Max: 47.30 MB

- **Success Rate:** 100.0% (4/4)