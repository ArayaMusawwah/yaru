use crate::core::risk::assess;
use crate::core::types::{
    Finding, MaintainerChange, RiskReport, ScoreBreakdown, TrustZone, Verdict,
};

/// Evaluates a package given its signals, applying policy overrides (e.g. whitelists).
pub struct PolicyEngine {
    whitelisted_rules: Vec<String>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            whitelisted_rules: Vec::new(),
        }
    }

    pub fn with_whitelist(rules: Vec<String>) -> Self {
        Self {
            whitelisted_rules: rules,
        }
    }

    /// Whitelist rules get filtered before scoring, so safe packages don't
    /// accumulate false-positive penalties.
    pub fn evaluate(
        &self,
        package: &str,
        zone: TrustZone,
        breakdown: &ScoreBreakdown,
        findings: &[Finding],
        maintainer_changes: &[MaintainerChange],
    ) -> RiskReport {
        let effective_findings: Vec<Finding> = findings
            .iter()
            .filter(|f| !self.whitelisted_rules.contains(&f.rule_id))
            .cloned()
            .collect();

        // Zone 0 fast-path: official repo packages bypass AUR static-analysis penalties
        if zone == TrustZone::Official {
            let mut b = breakdown.clone();
            b.source_score = 0;
            b.static_score = 0;
            return RiskReport {
                package: package.to_string(),
                zone,
                breakdown: b,
                findings: Vec::new(),
                maintainer_changes: Vec::new(),
                verdict: Verdict::Allow,
                reasons: vec!["Official repository package — fast path".to_string()],
            };
        }

        assess(
            package,
            zone,
            breakdown,
            &effective_findings,
            maintainer_changes,
        )
    }
}
