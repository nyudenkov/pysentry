use crate::output::report::ReportGenerator;
use crate::types::{AuditFormat, SeverityLevel, VulnerabilitySourceType};
use crate::{AuditCache, AuditEngine};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::path::Path;

#[pyfunction]
#[pyo3(signature = (path, format=None))]
fn audit_python(path: String, format: Option<String>) -> PyResult<String> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create async runtime: {}", e)))?;

    rt.block_on(async {
        let temp_dir = std::env::temp_dir().join("pysentry-cache");
        let cache = AuditCache::new(temp_dir);
        let engine = AuditEngine::new().with_cache(cache);

        let audit_format = match format.as_deref() {
            Some("json") => AuditFormat::Json,
            Some("sarif") => AuditFormat::Sarif,
            _ => AuditFormat::Human,
        };

        let vulnerability_source = VulnerabilitySourceType::Pypa;
        let min_severity = SeverityLevel::Low;
        let ignore_ids: Vec<String> = vec![];

        match engine
            .audit_project(&path, vulnerability_source, min_severity, &ignore_ids)
            .await
        {
            Ok(report) => {
                let project_path = Path::new(&path);
                match ReportGenerator::generate(&report, audit_format, Some(project_path)) {
                    Ok(output) => Ok(output),
                    Err(e) => Err(PyRuntimeError::new_err(format!(
                        "Failed to generate report: {}",
                        e
                    ))),
                }
            }
            Err(e) => Err(PyRuntimeError::new_err(format!("Audit failed: {}", e))),
        }
    })
}

#[pyfunction]
#[pyo3(signature = (path, format=None, source=None, min_severity=None, ignore_ids=None))]
fn audit_with_options(
    path: String,
    format: Option<String>,
    source: Option<String>,
    min_severity: Option<String>,
    ignore_ids: Option<Vec<String>>,
) -> PyResult<String> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create async runtime: {}", e)))?;

    rt.block_on(async {
        let temp_dir = std::env::temp_dir().join("pysentry-cache");
        let cache = AuditCache::new(temp_dir);
        let engine = AuditEngine::new().with_cache(cache);

        let audit_format = match format.as_deref() {
            Some("json") => AuditFormat::Json,
            Some("sarif") => AuditFormat::Sarif,
            _ => AuditFormat::Human,
        };

        let vulnerability_source = match source.as_deref() {
            Some("pypi") => VulnerabilitySourceType::Pypi,
            Some("osv") => VulnerabilitySourceType::Osv,
            _ => VulnerabilitySourceType::Pypa,
        };

        let min_sev = match min_severity.as_deref() {
            Some("critical") => SeverityLevel::Critical,
            Some("high") => SeverityLevel::High,
            Some("medium") => SeverityLevel::Medium,
            _ => SeverityLevel::Low,
        };

        let ignore_list = ignore_ids.unwrap_or_default();

        match engine
            .audit_project(&path, vulnerability_source, min_sev, &ignore_list)
            .await
        {
            Ok(report) => {
                let project_path = Path::new(&path);
                match ReportGenerator::generate(&report, audit_format, Some(project_path)) {
                    Ok(output) => Ok(output),
                    Err(e) => Err(PyRuntimeError::new_err(format!(
                        "Failed to generate report: {}",
                        e
                    ))),
                }
            }
            Err(e) => Err(PyRuntimeError::new_err(format!("Audit failed: {}", e))),
        }
    })
}

#[pymodule]
fn _internal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(audit_python, m)?)?;
    m.add_function(wrap_pyfunction!(audit_with_options, m)?)?;
    Ok(())
}
