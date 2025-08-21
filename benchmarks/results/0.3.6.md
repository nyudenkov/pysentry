# PySentry - pip-audit Benchmark Report

**Generated:** 2025-08-21 19:52:35
**Duration:** 1m 56.44s
**Total Tests:** 20

## Executive Summary

**Overall Success Rate:** 100.0% (20/20 successful runs)

### Small_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.250s) - 35.37x faster than slowest
- **Memory Efficient:** pysentry-osv (11.03 MB) - 9.68x less memory than highest

### Small_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.221s) - 35.46x faster than slowest
- **Memory Efficient:** pysentry-osv (10.81 MB) - 9.68x less memory than highest

### Large_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.722s) - 27.16x faster than slowest
- **Memory Efficient:** pysentry-osv (10.93 MB) - 9.84x less memory than highest

### Large_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.686s) - 23.48x faster than slowest
- **Memory Efficient:** pysentry-osv (11.07 MB) - 9.83x less memory than highest

## Test Environment

- **Platform:** Linux-6.11.0-1018-azure-x86_64-with-glibc2.39
- **Python Version:** 3.11.13
- **CPU Cores:** 4
- **Total Memory:** 15.62 GB
- **Available Memory:** 14.63 GB

## Performance Comparison

### Small_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.250s | 1.00x |
| 🥈 pysentry-osv | 1.045s | 4.18x |
|  pysentry-all-sources | 1.152s | 4.60x |
|  pysentry-pypa | 1.155s | 4.61x |
|  pip-audit-default | 8.852s | 35.37x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 11.03 MB | 1.00x |
| 🥈 pysentry-pypi | 11.64 MB | 1.06x |
|  pip-audit-default | 45.64 MB | 4.14x |
|  pysentry-pypa | 75.38 MB | 6.84x |
|  pysentry-all-sources | 106.78 MB | 9.68x |

### Small_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.221s | 1.00x |
| 🥈 pysentry-pypa | 0.729s | 3.29x |
|  pysentry-osv | 0.982s | 4.43x |
|  pysentry-all-sources | 1.112s | 5.02x |
|  pip-audit-default | 7.854s | 35.46x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.81 MB | 1.00x |
| 🥈 pysentry-pypi | 11.93 MB | 1.10x |
|  pip-audit-default | 44.88 MB | 4.15x |
|  pysentry-pypa | 69.38 MB | 6.42x |
|  pysentry-all-sources | 104.60 MB | 9.68x |

### Large_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.722s | 1.00x |
| 🥈 pysentry-pypa | 1.258s | 1.74x |
|  pysentry-all-sources | 3.183s | 4.41x |
|  pysentry-osv | 3.714s | 5.14x |
|  pip-audit-default | 19.619s | 27.16x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 10.93 MB | 1.00x |
| 🥈 pysentry-pypi | 14.27 MB | 1.31x |
|  pip-audit-default | 47.34 MB | 4.33x |
|  pysentry-pypa | 74.92 MB | 6.85x |
|  pysentry-all-sources | 107.52 MB | 9.84x |

### Large_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.686s | 1.00x |
| 🥈 pysentry-pypa | 1.206s | 1.76x |
|  pysentry-all-sources | 3.464s | 5.05x |
|  pysentry-osv | 3.799s | 5.54x |
|  pip-audit-default | 16.105s | 23.48x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 11.07 MB | 1.00x |
| 🥈 pysentry-pypi | 11.27 MB | 1.02x |
|  pip-audit-default | 47.18 MB | 4.26x |
|  pysentry-pypa | 52.84 MB | 4.77x |
|  pysentry-all-sources | 108.84 MB | 9.83x |

## Detailed Analysis

### Pysentry Performance

- **Execution Time:** Avg: 1.542s, Min: 0.221s, Max: 3.799s

- **Memory Usage:** Avg: 49.58 MB, Min: 10.81 MB, Max: 108.84 MB

- **Success Rate:** 100.0% (16/16)

### Pip-Audit Performance

- **Execution Time:** Avg: 13.108s, Min: 7.854s, Max: 19.619s

- **Memory Usage:** Avg: 46.26 MB, Min: 44.88 MB, Max: 47.34 MB

- **Success Rate:** 100.0% (4/4)