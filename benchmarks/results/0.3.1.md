# PySentry - pip-audit Benchmark Report

**Generated:** 2025-08-12 18:55:26
**Duration:** 1m 54.40s
**Total Tests:** 20

## Executive Summary

**Overall Success Rate:** 100.0% (20/20 successful runs)

### Small_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.213s) - 42.00x faster than slowest
- **Memory Efficient:** pysentry-osv (10.02 MB) - 10.69x less memory than highest

### Small_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.223s) - 35.50x faster than slowest
- **Memory Efficient:** pysentry-osv (10.18 MB) - 9.89x less memory than highest

### Large_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.679s) - 28.20x faster than slowest
- **Memory Efficient:** pysentry-osv (10.27 MB) - 10.21x less memory than highest

### Large_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.692s) - 23.06x faster than slowest
- **Memory Efficient:** pysentry-pypi (9.86 MB) - 9.55x less memory than highest

## Test Environment

- **Platform:** Linux-6.11.0-1018-azure-x86_64-with-glibc2.39
- **Python Version:** 3.11.13
- **CPU Cores:** 4
- **Total Memory:** 15.62 GB
- **Available Memory:** 14.60 GB

## Performance Comparison

### Small_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.213s | 1.00x |
| 🥈 pysentry-pypa | 1.004s | 4.71x |
|  pysentry-osv | 1.006s | 4.72x |
|  pysentry-all-sources | 1.013s | 4.75x |
|  pip-audit-default | 8.951s | 42.00x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.02 MB | 1.00x |
| 🥈 pysentry-pypi | 11.68 MB | 1.17x |
|  pip-audit-default | 45.42 MB | 4.53x |
|  pysentry-pypa | 52.72 MB | 5.26x |
|  pysentry-all-sources | 107.07 MB | 10.69x |

### Small_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.223s | 1.00x |
| 🥈 pysentry-pypa | 0.723s | 3.24x |
|  pysentry-osv | 0.969s | 4.34x |
|  pysentry-all-sources | 1.037s | 4.65x |
|  pip-audit-default | 7.922s | 35.50x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.18 MB | 1.00x |
| 🥈 pysentry-pypi | 10.59 MB | 1.04x |
|  pip-audit-default | 44.28 MB | 4.35x |
|  pysentry-pypa | 73.74 MB | 7.24x |
|  pysentry-all-sources | 100.68 MB | 9.89x |

### Large_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.679s | 1.00x |
| 🥈 pysentry-pypa | 1.142s | 1.68x |
|  pysentry-osv | 3.365s | 4.95x |
|  pysentry-all-sources | 3.649s | 5.37x |
|  pip-audit-default | 19.161s | 28.20x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.27 MB | 1.00x |
| 🥈 pysentry-pypi | 10.36 MB | 1.01x |
|  pip-audit-default | 47.43 MB | 4.62x |
|  pysentry-pypa | 70.21 MB | 6.84x |
|  pysentry-all-sources | 104.85 MB | 10.21x |

### Large_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.692s | 1.00x |
| 🥈 pysentry-pypa | 1.119s | 1.62x |
|  pysentry-osv | 2.963s | 4.28x |
|  pysentry-all-sources | 4.382s | 6.33x |
|  pip-audit-default | 15.954s | 23.06x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 9.86 MB | 1.00x |
| 🥈 pysentry-osv | 10.14 MB | 1.03x |
|  pip-audit-default | 47.00 MB | 4.77x |
|  pysentry-pypa | 73.75 MB | 7.48x |
|  pysentry-all-sources | 94.11 MB | 9.55x |

## Detailed Analysis

### Pysentry Performance

- **Execution Time:** Avg: 1.511s, Min: 0.213s, Max: 4.382s

- **Memory Usage:** Avg: 47.51 MB, Min: 9.86 MB, Max: 107.07 MB

- **Success Rate:** 100.0% (16/16)

### Pip-Audit Performance

- **Execution Time:** Avg: 12.997s, Min: 7.922s, Max: 19.161s

- **Memory Usage:** Avg: 46.03 MB, Min: 44.28 MB, Max: 47.43 MB

- **Success Rate:** 100.0% (4/4)