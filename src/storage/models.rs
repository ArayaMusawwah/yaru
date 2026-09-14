use crate::core::types::{Severity, Verdict};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatIndicator {
    pub indicator: String,
    pub kind: String,
    pub severity: Severity,
    pub confidence: f64,
    pub source: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionRecord {
    pub package: String,
    pub score: u32,
    pub verdict: Verdict,
    pub reasons: Vec<String>,
    pub timestamp: i64,
}
