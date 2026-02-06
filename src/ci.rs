// SPDX-License-Identifier: MIT

//! CI environment detection and platform-specific annotation helpers.

use std::env;

#[derive(Debug, Clone, PartialEq)]
pub enum CiEnvironment {
    GitHubActions,
    GitLabCi,
    Jenkins,
    CircleCi,
    Generic,
    None,
}

impl CiEnvironment {
    pub fn is_ci(&self) -> bool {
        !matches!(self, CiEnvironment::None)
    }

    pub fn is_github_actions(&self) -> bool {
        matches!(self, CiEnvironment::GitHubActions)
    }
}

pub fn detect() -> CiEnvironment {
    if env::var("GITHUB_ACTIONS").is_ok() {
        CiEnvironment::GitHubActions
    } else if env::var("GITLAB_CI").is_ok() {
        CiEnvironment::GitLabCi
    } else if env::var("JENKINS_URL").is_ok() {
        CiEnvironment::Jenkins
    } else if env::var("CIRCLECI").is_ok() {
        CiEnvironment::CircleCi
    } else if env::var("CI").is_ok() {
        CiEnvironment::Generic
    } else {
        CiEnvironment::None
    }
}

pub fn github_notice(message: &str) {
    println!("::notice::{message}");
}

pub fn github_warning(message: &str) {
    println!("::warning::{message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ci_environment_is_ci() {
        assert!(CiEnvironment::GitHubActions.is_ci());
        assert!(CiEnvironment::GitLabCi.is_ci());
        assert!(CiEnvironment::Jenkins.is_ci());
        assert!(CiEnvironment::CircleCi.is_ci());
        assert!(CiEnvironment::Generic.is_ci());
        assert!(!CiEnvironment::None.is_ci());
    }

    #[test]
    fn test_ci_environment_is_github_actions() {
        assert!(CiEnvironment::GitHubActions.is_github_actions());
        assert!(!CiEnvironment::GitLabCi.is_github_actions());
        assert!(!CiEnvironment::None.is_github_actions());
    }
}
