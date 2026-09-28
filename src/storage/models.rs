use crate::core::types::{Finding, PackageSnapshot, ScoreBreakdown, Severity, Verdict};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedScan {
    pub package: String,
    pub fingerprint: String,
    pub breakdown: ScoreBreakdown,
    pub findings: Vec<Finding>,
    pub verdict: Verdict,
    pub reasons: Vec<String>,
    pub snapshot: PackageSnapshot,
    pub timestamp: i64,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeedState {
    pub url: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub last_success: i64,
}
