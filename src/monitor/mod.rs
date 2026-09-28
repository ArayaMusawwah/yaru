use crate::core::types::{Finding, Severity};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorEvent {
    pub event_type: String,
    pub process: Option<String>,
    pub detail: String,
    pub expected: bool,
    pub severity: Severity,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BehaviorReport {
    pub events: Vec<BehaviorEvent>,
    pub findings: Vec<Finding>,
    pub score: u32,
    pub suspicious: bool,
}

/// Rule definitions mirror the PKGBUILD rule engine (architecture §31):
/// signatures live in YAML and update without recompiling the binary.
#[derive(Debug, Clone, Deserialize)]
struct RuleDef {
    id: String,
    name: String,
    category: String,
    severity: String,
    /// Alternation string ("a|b|c"); split on '|' into substring needles.
    pattern: String,
    score: u32,
}

#[derive(Deserialize)]
struct RuleFile {
    rules: Vec<RuleDef>,
}

struct BehaviorRule {
    id: String,
    title: String,
    category: String,
    severity: Severity,
    score: u32,
    needles: Vec<String>,
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Medium,
    }
}

fn rules_from_yaml(yaml: &str) -> Vec<BehaviorRule> {
    let defs: Vec<RuleDef> = serde_yaml::from_str::<RuleFile>(yaml)
        .map(|file| file.rules)
        .unwrap_or_default();
    defs.into_iter()
        .map(|d| BehaviorRule {
            needles: d
                .pattern
                .split('|')
                .map(|n| n.trim().to_lowercase())
                .filter(|n| !n.is_empty())
                .collect(),
            id: d.id,
            title: d.name,
            category: d.category,
            severity: parse_severity(&d.severity),
            score: d.score,
        })
        .collect()
}

/// Built-in rules are compiled in so offline/first-run always works.
const BUILTIN_YAML: &str = include_str!("../rules/behavior/behavior.yaml");

fn load_rules() -> Vec<BehaviorRule> {
    if let Ok(path) = std::env::var("YARU_BEHAVIOR_RULES") {
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let parsed = rules_from_yaml(&text);
                if !parsed.is_empty() {
                    return parsed;
                }
                tracing::warn!("YARU_BEHAVIOR_RULES={path} yielded no rules; using builtin");
            }
            Err(_) => tracing::warn!("YARU_BEHAVIOR_RULES={path} unreadable; using builtin"),
        }
    }
    rules_from_yaml(BUILTIN_YAML)
}

fn rules() -> &'static [BehaviorRule] {
    static RULES: OnceLock<Vec<BehaviorRule>> = OnceLock::new();
    RULES.get_or_init(load_rules)
}

pub fn scan_output(stdout: &str, stderr: &str) -> BehaviorReport {
    let combined = format!("{stdout}\n{stderr}");
    let mut report = BehaviorReport::default();
    for (index, line) in combined.lines().enumerate() {
        let lower = line.to_lowercase();
        for rule in rules() {
            if rule.needles.iter().any(|needle| lower.contains(needle)) {
                report.findings.push(Finding {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    category: rule.category.clone(),
                    severity: rule.severity,
                    file: "sandbox-output".to_string(),
                    line: index + 1,
                    excerpt: line.trim().chars().take(160).collect(),
                    scope: crate::core::types::FindingScope::Pkgbuild,
                });
                report.events.push(BehaviorEvent {
                    event_type: rule.category.clone(),
                    process: None,
                    detail: line.trim().to_string(),
                    expected: false,
                    severity: rule.severity,
                    timestamp: Utc::now().timestamp(),
                });
                report.score = (report.score + rule.score).min(100);
            }
        }
    }
    report.suspicious = !report.findings.is_empty();
    report
}

pub fn append_events(path: &Path, report: &BehaviorReport) -> Result<(), std::io::Error> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    for event in &report.events {
        serde_json::to_writer(&mut file, event)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_yaml_rules_load() {
        let parsed = load_rules();
        assert!(parsed.len() >= 4, "expected >=4 builtin rules");
        assert!(parsed.iter().all(|r| !r.needles.is_empty()));
        assert!(
            parsed
                .iter()
                .any(|r| r.id == "dns-resolution-attempt" && r.severity == Severity::High)
        );
    }

    #[test]
    fn custom_yaml_is_parsed_without_env() {
        let yaml = "rules:\n  - id: custom-marker\n    name: Custom Marker\n    category: test\n    severity: critical\n    pattern: \"marker-xyz|other-token\"\n    score: 99\n";
        let parsed = rules_from_yaml(yaml);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "custom-marker");
        assert_eq!(parsed[0].score, 99);
        assert_eq!(parsed[0].severity, Severity::Critical);
        assert_eq!(parsed[0].needles.len(), 2);
    }

    #[test]
    fn malformed_yaml_yields_no_rules_instead_of_panicking() {
        assert!(rules_from_yaml("this: is: not: valid: yaml").is_empty());
    }

    #[test]
    fn clean_build_output_has_no_behavior_findings() {
        let report = scan_output("cargo build --release\nFinished release", "");
        assert!(!report.suspicious);
        assert_eq!(report.score, 0);
        assert!(report.events.is_empty());
    }

    #[test]
    fn dns_failure_becomes_high_behavior_signal() {
        let report = scan_output(
            "",
            "curl: (6) Could not resolve host: evil.example\nTemporary failure in name resolution",
        );
        assert!(report.suspicious);
        assert!(report.score >= 30);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "dns-resolution-attempt")
        );
    }

    #[test]
    fn privilege_failure_becomes_critical_signal() {
        let report = scan_output("", "sudo: command not found");
        assert_eq!(report.score, 50);
        assert_eq!(report.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn events_are_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let report = scan_output("", "Permission denied");
        append_events(&path, &report).unwrap();
        let content = std::fs::read_to_string(path).unwrap();
        assert_eq!(content.lines().count(), 1);
        assert!(content.contains("filesystem"));
    }
}
