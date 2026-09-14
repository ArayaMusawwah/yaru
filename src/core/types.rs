use serde::{Deserialize, Serialize};

/// Trust zone assigned to a package source, from most to least trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustZone {
    Official,
    Trusted,
    ThirdParty,
    Aur,
    Unknown,
}

impl TrustZone {
    pub fn label(&self) -> &'static str {
        match self {
            TrustZone::Official => "OFFICIAL",
            TrustZone::Trusted => "TRUSTED",
            TrustZone::ThirdParty => "THIRD_PARTY",
            TrustZone::Aur => "AUR",
            TrustZone::Unknown => "UNKNOWN",
        }
    }

    /// Zone weight added to the risk score. Official repos carry no supply-chain
    /// penalty; unknown sources start already suspect.
    pub fn base_risk(&self) -> u32 {
        match self {
            TrustZone::Official => 0,
            TrustZone::Trusted => 5,
            TrustZone::ThirdParty => 20,
            TrustZone::Aur => 25,
            TrustZone::Unknown => 60,
        }
    }
}

/// Result of classifying a package name or PKGBUILD path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceClassification {
    pub package: String,
    pub repository: Option<String>,
    pub zone: TrustZone,
    pub version: Option<String>,
    pub maintainer: Option<String>,
    pub url: Option<String>,
    pub url_path: Option<String>,
}

/// Severity of a single static-analysis finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn weight(&self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 5,
            Severity::Medium => 15,
            Severity::High => 30,
            Severity::Critical => 50,
        }
    }
}

/// A single suspicious construct located in a PKGBUILD or .install file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub category: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub excerpt: String,
}

/// Verdict produced by the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    Warn,
    Quarantine,
    Block,
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Allow => "ALLOW",
            Verdict::Warn => "WARN",
            Verdict::Quarantine => "QUARANTINE",
            Verdict::Block => "BLOCK",
        }
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Verdict::Allow => "[OK]",
            Verdict::Warn => "[!]",
            Verdict::Quarantine => "[?]",
            Verdict::Block => "[X]",
        }
    }
}

/// Risk buckets derived from the 0-100 composite score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: u32) -> Self {
        match score {
            0..=29 => RiskLevel::Low,
            30..=59 => RiskLevel::Medium,
            60..=79 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }
}

/// Score breakdown across every signal the risk engine consumes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub static_score: u32,
    pub change_score: u32,
    pub dependency_score: u32,
    pub threat_score: u32,
    pub behavior_score: u32,
    pub source_score: u32,
}

impl ScoreBreakdown {
    pub fn total(&self) -> u32 {
        (self.static_score
            + self.change_score
            + self.dependency_score
            + self.threat_score
            + self.behavior_score
            + self.source_score)
            .min(100)
    }
}

/// One recorded maintainer transition between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintainerChange {
    pub package: String,
    pub previous: Option<String>,
    pub current: Option<String>,
    pub kind: MaintainerChangeKind,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaintainerChangeKind {
    Added,
    Removed,
    Changed,
    Orphaned,
    Adopted,
}

impl MaintainerChangeKind {
    pub fn label(&self) -> &'static str {
        match self {
            MaintainerChangeKind::Added => "Maintainer Added",
            MaintainerChangeKind::Removed => "Maintainer Removed",
            MaintainerChangeKind::Changed => "Maintainer Changed",
            MaintainerChangeKind::Orphaned => "Orphaned",
            MaintainerChangeKind::Adopted => "Adopted",
        }
    }
}

/// Stored representation of an analyzed package at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSnapshot {
    pub package_name: String,
    pub version: Option<String>,
    pub maintainer: Option<String>,
    pub pkgbuild_hash: String,
    pub source_urls: Vec<String>,
    pub depends: Vec<String>,
    pub makedepends: Vec<String>,
    pub checkdepends: Vec<String>,
    pub timestamp: i64,
}

/// Full result of running a package through the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReport {
    pub package: String,
    pub zone: TrustZone,
    pub breakdown: ScoreBreakdown,
    pub findings: Vec<Finding>,
    pub maintainer_changes: Vec<MaintainerChange>,
    pub verdict: Verdict,
    pub reasons: Vec<String>,
}

impl RiskReport {
    pub fn score(&self) -> u32 {
        self.breakdown.total()
    }

    pub fn level(&self) -> RiskLevel {
        RiskLevel::from_score(self.score())
    }
}

/// Yaru failure modes when a downstream engine is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FailureMode {
    #[default]
    Warn,
    Block,
}
