use crate::core::types::{Finding, Severity};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::Path;

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

struct BehaviorRule {
    id: &'static str,
    title: &'static str,
    category: &'static str,
    severity: Severity,
    score: u32,
    needles: &'static [&'static str],
}

const RULES: &[BehaviorRule] = &[
    BehaviorRule {
        id: "dns-resolution-attempt",
        title: "DNS or Host Resolution Attempt",
        category: "network",
        severity: Severity::High,
        score: 30,
        needles: &[
            "temporary failure in name resolution",
            "getaddrinfo",
            "name or service not known",
            "connection timed out",
        ],
    },
    BehaviorRule {
        id: "unexpected-network-binary",
        title: "Network Tool Invoked",
        category: "network",
        severity: Severity::Critical,
        score: 50,
        needles: &["curl: ", "wget: ", "nc: ", "netcat"],
    },
    BehaviorRule {
        id: "privilege-escalation-attempt",
        title: "Privilege Escalation Attempt",
        category: "privilege",
        severity: Severity::Critical,
        score: 50,
        needles: &["sudo: ", "su: ", "operation not permitted", "setuid"],
    },
    BehaviorRule {
        id: "suspicious-file-write",
        title: "Write Outside Allowed Tree",
        category: "filesystem",
        severity: Severity::Medium,
        score: 15,
        needles: &["read-only file system", "permission denied"],
    },
];

pub fn scan_output(stdout: &str, stderr: &str) -> BehaviorReport {
    let combined = format!("{stdout}\n{stderr}");
    let mut report = BehaviorReport::default();
    for (index, line) in combined.lines().enumerate() {
        let lower = line.to_lowercase();
        for rule in RULES {
            if rule.needles.iter().any(|needle| lower.contains(needle)) {
                report.findings.push(Finding {
                    rule_id: rule.id.to_string(),
                    title: rule.title.to_string(),
                    category: rule.category.to_string(),
                    severity: rule.severity,
                    file: "sandbox-output".to_string(),
                    line: index + 1,
                    excerpt: line.trim().chars().take(160).collect(),
                });
                report.events.push(BehaviorEvent {
                    event_type: rule.category.to_string(),
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
