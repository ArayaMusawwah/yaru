use crate::core::types::{Finding, FindingScope, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceIntegrity {
    Pinned,
    MutableGitRef,
    Unversioned,
    Unknown,
}

impl SourceIntegrity {
    pub fn label(&self) -> &'static str {
        match self {
            SourceIntegrity::Pinned => "PINNED",
            SourceIntegrity::MutableGitRef => "MUTABLE-GIT",
            SourceIntegrity::Unversioned => "UNVERSIONED",
            SourceIntegrity::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceAssessment {
    pub url: String,
    pub integrity: SourceIntegrity,
    pub finding: Option<Finding>,
}

pub fn assess_sources(sources: &[String], has_sha256sums: bool) -> Vec<SourceAssessment> {
    sources
        .iter()
        .filter_map(|url| {
            let integrity = classify_source(url, has_sha256sums);
            if integrity == SourceIntegrity::Pinned {
                return None;
            }
            let finding = build_finding(url, integrity);
            Some(SourceAssessment {
                url: url.clone(),
                integrity,
                finding: Some(finding),
            })
        })
        .collect()
}

fn classify_source(url: &str, has_sha256sums: bool) -> SourceIntegrity {
    if url.starts_with("git+") {
        if url.contains("#commit=") || url.contains("commit=") {
            SourceIntegrity::Pinned
        } else if url.contains("#branch=") || url.contains("#tag=") {
            SourceIntegrity::MutableGitRef
        } else {
            SourceIntegrity::Unknown
        }
    } else if url.contains("://") {
        if url.contains("latest.tar.gz")
            || url.contains("master.tar.gz")
            || url.contains("/HEAD")
            || url.contains("main.tar.gz")
        {
            SourceIntegrity::Unversioned
        } else if has_sha256sums {
            SourceIntegrity::Pinned
        } else {
            SourceIntegrity::Unknown
        }
    } else {
        SourceIntegrity::Unknown
    }
}

fn build_finding(url: &str, integrity: SourceIntegrity) -> Finding {
    let (rule_id, title, severity) = match integrity {
        SourceIntegrity::MutableGitRef => {
            ("mutable-git-ref", "Mutable Git Reference", Severity::Medium)
        }
        SourceIntegrity::Unversioned => (
            "unversioned-source",
            "Unversioned Source URL",
            Severity::Medium,
        ),
        _ => (
            "source-integrity-unknown",
            "Source Integrity Unknown",
            Severity::Low,
        ),
    };
    Finding {
        rule_id: rule_id.to_string(),
        title: title.to_string(),
        category: "source-integrity".to_string(),
        severity,
        file: "PKGBUILD".to_string(),
        line: 0,
        excerpt: url.to_string(),
        scope: FindingScope::Pkgbuild,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_git_commit_is_safe() {
        let result = classify_source("git+https://github.com/user/repo#commit=abc123", false);
        assert_eq!(result, SourceIntegrity::Pinned);
    }

    #[test]
    fn mutable_git_branch_is_flagged() {
        let result = classify_source("git+https://github.com/user/repo#branch=main", false);
        assert_eq!(result, SourceIntegrity::MutableGitRef);
    }

    #[test]
    fn unversioned_tarball_is_flagged() {
        let result = classify_source("https://example.com/latest.tar.gz", false);
        assert_eq!(result, SourceIntegrity::Unversioned);
    }

    #[test]
    fn sha256sums_pins_http_source() {
        let result = classify_source("https://example.com/foo-1.0.tar.gz", true);
        assert_eq!(result, SourceIntegrity::Pinned);
    }

    #[test]
    fn pinned_sources_produce_no_findings() {
        let sources = vec![
            "git+https://github.com/user/repo#commit=abc".to_string(),
            "https://example.com/foo.tar.gz".to_string(),
        ];
        let results = assess_sources(&sources, true);
        assert!(results.is_empty());
    }
}
