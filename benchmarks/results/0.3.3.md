# PySentry - pip-audit Benchmark Report

**Generated:** 2025-08-13 19:15:14
**Duration:** 2m 31.44s
**Total Tests:** 20

## Executive Summary

**Overall Success Rate:** 100.0% (20/20 successful runs)

### Small_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.256s) - 36.61x faster than slowest
- **Memory Efficient:** pysentry-osv (10.62 MB) - 10.00x less memory than highest

### Small_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.294s) - 26.45x faster than slowest
- **Memory Efficient:** pysentry-pypi (8.86 MB) - 12.13x less memory than highest

### Large_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.761s) - 50.91x faster than slowest
- **Memory Efficient:** pysentry-osv (10.78 MB) - 10.57x less memory than highest

### Large_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.693s) - 22.77x faster than slowest
- **Memory Efficient:** pysentry-pypi (8.71 MB) - 11.50x less memory than highest

## Test Environment

- **Platform:** Linux-6.11.0-1018-azure-x86_64-with-glibc2.39
- **Python Version:** 3.11.13
- **CPU Cores:** 4
- **Total Memory:** 15.62 GB
- **Available Memory:** 14.64 GB

## Performance Comparison

### Small_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.256s | 1.00x |
| 🥈 pysentry-osv | 0.959s | 3.74x |
|  pysentry-pypa | 1.096s | 4.28x |
|  pysentry-all-sources | 4.783s | 18.65x |
|  pip-audit-default | 9.387s | 36.61x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.62 MB | 1.00x |
| 🥈 pysentry-pypi | 10.90 MB | 1.03x |
|  pip-audit-default | 45.28 MB | 4.26x |
|  pysentry-pypa | 55.32 MB | 5.21x |
|  pysentry-all-sources | 106.14 MB | 10.00x |

### Small_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.294s | 1.00x |
| 🥈 pysentry-pypa | 0.854s | 2.90x |
|  pysentry-all-sources | 1.012s | 3.44x |
|  pysentry-osv | 1.217s | 4.13x |
|  pip-audit-default | 7.785s | 26.45x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 8.86 MB | 1.00x |
| 🥈 pysentry-osv | 10.52 MB | 1.19x |
|  pip-audit-default | 44.48 MB | 5.02x |
|  pysentry-pypa | 67.44 MB | 7.61x |
|  pysentry-all-sources | 107.53 MB | 12.13x |

### Large_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.761s | 1.00x |
| 🥈 pysentry-pypa | 1.276s | 1.68x |
|  pysentry-osv | 3.144s | 4.13x |
|  pip-audit-default | 17.817s | 23.41x |
|  pysentry-all-sources | 38.757s | 50.91x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.78 MB | 1.00x |
| 🥈 pysentry-pypi | 12.95 MB | 1.20x |
|  pip-audit-default | 47.48 MB | 4.40x |
|  pysentry-pypa | 62.62 MB | 5.81x |
|  pysentry-all-sources | 113.92 MB | 10.57x |

### Large_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.693s | 1.00x |
| 🥈 pysentry-pypa | 1.308s | 1.89x |
|  pysentry-all-sources | 3.079s | 4.44x |
|  pysentry-osv | 3.115s | 4.50x |
|  pip-audit-default | 15.778s | 22.77x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 8.71 MB | 1.00x |
| 🥈 pysentry-osv | 10.64 MB | 1.22x |
|  pip-audit-default | 46.98 MB | 5.39x |
|  pysentry-pypa | 53.95 MB | 6.19x |
|  pysentry-all-sources | 100.21 MB | 11.50x |

## Detailed Analysis

### Pysentry Performance

- **Execution Time:** Avg: 3.913s, Min: 0.256s, Max: 38.757s

- **Memory Usage:** Avg: 46.95 MB, Min: 8.71 MB, Max: 113.92 MB

- **Success Rate:** 100.0% (16/16)

### Pip-Audit Performance

- **Execution Time:** Avg: 12.692s, Min: 7.785s, Max: 17.817s

- **Memory Usage:** Avg: 46.05 MB, Min: 44.48 MB, Max: 47.48 MB

- **Success Rate:** 100.0% (4/4)