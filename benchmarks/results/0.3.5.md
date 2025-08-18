# PySentry - pip-audit Benchmark Report

**Generated:** 2025-08-18 17:01:27
**Duration:** 1m 57.61s
**Total Tests:** 20

## Executive Summary

**Overall Success Rate:** 100.0% (20/20 successful runs)

### Small_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.326s) - 27.96x faster than slowest
- **Memory Efficient:** pysentry-osv (11.90 MB) - 7.77x less memory than highest

### Small_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.227s) - 34.73x faster than slowest
- **Memory Efficient:** pysentry-pypi (9.57 MB) - 10.54x less memory than highest

### Large_Requirements Dataset - Cold Cache
- **Fastest:** pysentry-pypi (0.810s) - 25.84x faster than slowest
- **Memory Efficient:** pysentry-osv (11.85 MB) - 7.91x less memory than highest

### Large_Requirements Dataset - Hot Cache
- **Fastest:** pysentry-pypi (0.667s) - 23.10x faster than slowest
- **Memory Efficient:** pysentry-pypi (9.42 MB) - 10.74x less memory than highest

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
| 🥇 pysentry-pypi | 0.326s | 1.00x |
| 🥈 pysentry-osv | 1.027s | 3.15x |
|  pysentry-all-sources | 1.188s | 3.65x |
|  pysentry-pypa | 1.232s | 3.78x |
|  pip-audit-default | 9.108s | 27.96x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 11.90 MB | 1.00x |
| 🥈 pysentry-pypi | 13.23 MB | 1.11x |
|  pip-audit-default | 45.44 MB | 3.82x |
|  pysentry-pypa | 75.45 MB | 6.34x |
|  pysentry-all-sources | 92.43 MB | 7.77x |

### Small_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.227s | 1.00x |
| 🥈 pysentry-osv | 0.917s | 4.04x |
|  pysentry-all-sources | 1.036s | 4.57x |
|  pysentry-pypa | 1.107s | 4.88x |
|  pip-audit-default | 7.881s | 34.73x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 9.57 MB | 1.00x |
| 🥈 pysentry-osv | 10.85 MB | 1.13x |
|  pip-audit-default | 44.36 MB | 4.63x |
|  pysentry-pypa | 53.60 MB | 5.60x |
|  pysentry-all-sources | 100.87 MB | 10.54x |

### Large_Requirements Dataset - Cold Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.810s | 1.00x |
| 🥈 pysentry-pypa | 1.324s | 1.63x |
|  pysentry-osv | 3.834s | 4.73x |
|  pysentry-all-sources | 3.965s | 4.89x |
|  pip-audit-default | 20.942s | 25.84x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-osv | 11.85 MB | 1.00x |
| 🥈 pysentry-pypi | 13.98 MB | 1.18x |
|  pip-audit-default | 47.18 MB | 3.98x |
|  pysentry-pypa | 71.19 MB | 6.01x |
|  pysentry-all-sources | 93.71 MB | 7.91x |

### Large_Requirements Dataset - Hot Cache

#### Execution Time Comparison

| Tool Configuration | Execution Time | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 0.667s | 1.00x |
| 🥈 pysentry-pypa | 1.321s | 1.98x |
|  pysentry-all-sources | 3.341s | 5.01x |
|  pysentry-osv | 3.600s | 5.40x |
|  pip-audit-default | 15.406s | 23.10x |

#### Memory Usage Comparison

| Tool Configuration | Peak Memory | Relative Performance |
|---------------------|---------------------|---------------------|
| 🥇 pysentry-pypi | 9.42 MB | 1.00x |
| 🥈 pysentry-osv | 10.72 MB | 1.14x |
|  pip-audit-default | 47.33 MB | 5.02x |
|  pysentry-pypa | 72.12 MB | 7.65x |
|  pysentry-all-sources | 101.22 MB | 10.74x |

## Detailed Analysis

### Pysentry Performance

- **Execution Time:** Avg: 1.620s, Min: 0.227s, Max: 3.965s

- **Memory Usage:** Avg: 47.01 MB, Min: 9.42 MB, Max: 101.22 MB

- **Success Rate:** 100.0% (16/16)

### Pip-Audit Performance

- **Execution Time:** Avg: 13.334s, Min: 7.881s, Max: 20.942s

- **Memory Usage:** Avg: 46.08 MB, Min: 44.36 MB, Max: 47.33 MB

- **Success Rate:** 100.0% (4/4)