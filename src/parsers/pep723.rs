// SPDX-License-Identifier: MIT

//! PEP 723 inline-script-metadata parser.
//!
//! A PEP 723 block is an inline-TOML `dependencies` list embedded in a `.py` file:
//!
//! ```text
//! # /// script
//! # dependencies = ["requests==2.31.0"]
//! # ///
//! ```
//!
//! The `dependencies` array holds PEP 508 strings, identical in shape to a requirements.txt
//! body, so once the block is extracted this parser hands the dependency lines straight to
//! `RequirementsParser::parse_content` - the same resolve / no-resolve path requirements.txt
//! uses (pinned deps audited directly, unpinned resolved or skipped).

use super::{ParsedDependency, ProjectParser, SkippedPackage};
use crate::{parsers::requirements::RequirementsParser, types::ResolverType, AuditError, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct ScriptMetadata {
    dependencies: Option<Vec<String>>,
}

pub struct Pep723Parser {
    requirements: RequirementsParser,
    /// Mirrors `resolver.is_none()` at construction: with no resolver we audit pinned deps
    /// directly and skip unpinned ones, exactly like requirements.txt under `--no-resolver`.
    no_resolver: bool,
}

impl Default for Pep723Parser {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Pep723Parser {
    pub fn new(resolver: Option<ResolverType>) -> Self {
        Self {
            no_resolver: resolver.is_none(),
            requirements: RequirementsParser::new(resolver),
        }
    }

    /// Extract the body of a `# /// script` ... `# ///` block, with the leading comment
    /// prefix stripped from each line. Returns `None` if no complete block is present.
    fn extract_script_block(content: &str) -> Option<String> {
        let mut in_block = false;
        let mut body = String::new();

        for line in content.lines() {
            if !in_block {
                if line.trim_end() == "# /// script" {
                    in_block = true;
                }
                continue;
            }

            if line.trim_end() == "# ///" {
                return Some(body);
            }

            // PEP 723: strip the comment prefix - "# " for content lines, "#" for blank ones.
            let stripped = line
                .strip_prefix("# ")
                .or_else(|| line.strip_prefix('#'))
                .unwrap_or(line);
            body.push_str(stripped);
            body.push('\n');
        }

        None
    }
}

#[async_trait]
impl ProjectParser for Pep723Parser {
    fn name(&self) -> &'static str {
        "PEP 723 script"
    }

    fn can_parse(&self, project_path: &Path) -> bool {
        if project_path.extension().and_then(|e| e.to_str()) != Some("py") {
            return false;
        }
        match std::fs::read_to_string(project_path) {
            Ok(content) => Self::extract_script_block(&content).is_some(),
            Err(_) => false,
        }
    }

    fn priority(&self) -> u8 {
        5
    }

    async fn parse_dependencies(
        &self,
        project_path: &Path,
        _include_dev: bool,
        _include_optional: bool,
        direct_only: bool,
    ) -> Result<(Vec<ParsedDependency>, Vec<SkippedPackage>)> {
        let content = tokio::fs::read_to_string(project_path)
            .await
            .map_err(|e| AuditError::DependencyRead(Box::new(e)))?;

        let block = Self::extract_script_block(&content).ok_or_else(|| {
            AuditError::other(format!(
                "No PEP 723 script block found in {}",
                project_path.display()
            ))
        })?;

        let metadata: ScriptMetadata =
            toml::from_str(&block).map_err(|e| AuditError::DependencyRead(Box::new(e)))?;
        let dependencies = metadata.dependencies.unwrap_or_default();

        if dependencies.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        let source_file = project_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string());

        // PEP 508 dependency lines are exactly requirements.txt content - reuse that path.
        self.requirements
            .parse_content(
                &dependencies.join("\n"),
                source_file,
                direct_only,
                self.no_resolver,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;
    use crate::types::{PackageName, Version};
    use std::io::Write;
    use std::str::FromStr;
    use tempfile::NamedTempFile;

    fn write_script(content: &str) -> NamedTempFile {
        let mut file = tempfile::Builder::new().suffix(".py").tempfile().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    #[tokio::test]
    async fn test_pinned_script_exact_deps() {
        let script = r#"# /// script
# dependencies = [
#   "requests==2.31.0",
#   "click==8.1.7",
# ]
# ///

print("hello")
"#;
        let file = write_script(script);
        let parser = Pep723Parser::new(None);
        assert!(parser.can_parse(file.path()));

        let (deps, skipped) = parser
            .parse_dependencies(file.path(), false, false, false)
            .await
            .unwrap();
        assert!(skipped.is_empty());
        assert_eq!(deps.len(), 2);

        let requests = deps
            .iter()
            .find(|d| d.name == PackageName::new("requests"))
            .unwrap();
        assert_eq!(requests.version, Version::from_str("2.31.0").unwrap());
        assert!(requests.is_direct);

        let click = deps
            .iter()
            .find(|d| d.name == PackageName::new("click"))
            .unwrap();
        assert_eq!(click.version, Version::from_str("8.1.7").unwrap());
    }

    #[tokio::test]
    async fn test_unpinned_script_skipped_without_resolver() {
        let script = r#"# /// script
# dependencies = ["requests", "flask>=2.0"]
# ///
"#;
        let file = write_script(script);
        // No resolver: unpinned deps are skipped, not surfaced with placeholder versions
        // (a 0.0.0 placeholder would false-match "fixed in X" advisories). With a resolver
        // configured, these same deps go through resolution instead.
        let parser = Pep723Parser::new(None);

        let (deps, skipped) = parser
            .parse_dependencies(file.path(), false, false, false)
            .await
            .unwrap();
        assert!(deps.is_empty());
        assert_eq!(skipped.len(), 2);
        assert!(skipped
            .iter()
            .any(|s| s.name == PackageName::new("requests")));
        assert!(skipped.iter().any(|s| s.name == PackageName::new("flask")));
    }

    #[tokio::test]
    async fn test_mixed_script_pins_audited_unpinned_skipped() {
        let script = r#"# /// script
# dependencies = ["requests==2.19.0", "flask>=2.0"]
# ///
"#;
        let file = write_script(script);
        let parser = Pep723Parser::new(None);

        let (deps, skipped) = parser
            .parse_dependencies(file.path(), false, false, false)
            .await
            .unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, PackageName::new("requests"));
        assert_eq!(deps[0].version, Version::from_str("2.19.0").unwrap());
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].name, PackageName::new("flask"));
    }

    #[test]
    fn test_py_file_without_block_cannot_parse() {
        let file = write_script("import requests\n\nprint(\"no metadata here\")\n");
        let parser = Pep723Parser::new(None);
        assert!(!parser.can_parse(file.path()));
    }

    #[test]
    fn test_non_py_extension_cannot_parse() {
        let parser = Pep723Parser::new(None);
        assert!(!parser.can_parse(Path::new(".")));
    }

    #[test]
    fn test_unclosed_block_is_not_detected() {
        let block = Pep723Parser::extract_script_block("# /// script\n# dependencies = []\n");
        assert!(block.is_none());
    }
}
