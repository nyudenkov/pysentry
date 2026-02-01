---
sidebar_position: 2
---

# Why Scan for Vulnerabilities?

Dependency vulnerabilities are a common attack vector. This page covers the data and practical mitigations.

## Statistics

- **512,847** malicious packages detected on PyPI in 2024 ([Sonatype](https://www.sonatype.com/state-of-the-software-supply-chain/introduction))
- **75%** of organizations experienced a supply chain attack in 2024 ([DeepStrike](https://deepstrike.io/blog/supply-chain-attack-statistics-2025))
- **82%** of open source components flagged for poor maintenance or security flaws ([ISACA](https://www.isaca.org/resources/news-and-trends/isaca-now-blog/2025/the-2025-software-supply-chain-security-report))
- **$4.44M** average data breach cost globally, **$10.22M** in the US ([DeepStrike](https://deepstrike.io/blog/supply-chain-attack-statistics-2025))

## Recent PyPI Incidents

| Package | Date | Description |
|---------|------|-------------|
| **Ultralytics** | Dec 2024 | GitHub Actions cache poisoning led to malicious releases via legitimate CI/CD |
| **python-json-logger** | 2025 | Abandoned dependency (46M monthly downloads) hijacked for RCE |
| **Langflow** | May 2025 | CVSS 9.8 RCE, added to CISA Known Exploited Vulnerabilities |
| **sisaws** | Aug 2025 | Typosquat of `sisa` package, delivered RAT malware |

## Case Study: Log4Shell

Log4Shell (CVE-2021-44228) in December 2021 demonstrated the risk of transitive dependencies.

- CVSS 10.0, affected 93% of enterprise cloud environments
- Most organizations were unaware they used Log4j - it was a transitive dependency
- 45% patched within 10 days
- 30-40% of downloads remained vulnerable one year later

The core issue: transitive dependencies are not visible without tooling.

## Mitigations

### 1. Dependency Visibility

Track your full dependency tree, including transitive dependencies pulled in by direct dependencies.

### 2. Continuous Scanning

New CVEs are published daily. Periodic audits miss vulnerabilities discovered between scans.

### 3. CI/CD Integration

Automated scanning catches vulnerabilities before deployment.

### 4. Quarantine Detection

PyPI [quarantines malicious packages](https://blog.pypi.org/posts/2025-12-31-pypi-2025-in-review/) without full removal. Scanners should detect quarantine status.

## PySentry Capabilities

- **Multiple sources**: PyPA, PyPI, OSV.dev vulnerability databases
- **PEP 792**: Detects quarantined, deprecated, and archived packages
- **Performance**: Rust implementation, sub-second scans
- **Output formats**: JSON, Markdown, human-readable

## Next Steps

See the [Quick Start Guide](./getting-started/quickstart.md) for setup instructions.
